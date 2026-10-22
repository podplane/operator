// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsbackend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// fakeGCPSecrets models independent secret and version ETags and paginated history.
type fakeGCPSecrets struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
	mu           sync.Mutex
	name         string
	etag         string
	revision     int
	versions     []*secretmanagerpb.SecretVersion
	values       [][]byte
	failDestroy  string
	failAdd      bool
	failDelete   bool
	delayDestroy bool
	beforeRPC    func(string) error
}

// CreateSecret reserves an absent object without adding any version.
func (f *fakeGCPSecrets) CreateSecret(_ context.Context, r *secretmanagerpb.CreateSecretRequest) (*secretmanagerpb.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.name != "" {
		return nil, status.Error(codes.AlreadyExists, "exists")
	}
	f.name = r.Parent + "/secrets/" + r.SecretId
	f.revision++
	f.etag = fmt.Sprintf("etag-%d", f.revision)
	return &secretmanagerpb.Secret{Name: f.name, Etag: f.etag}, nil
}

// GetSecret returns the parent identity without reading its versions.
func (f *fakeGCPSecrets) GetSecret(_ context.Context, r *secretmanagerpb.GetSecretRequest) (*secretmanagerpb.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.name == "" || r.Name != f.name {
		return nil, status.Error(codes.NotFound, "missing")
	}
	return &secretmanagerpb.Secret{Name: f.name, Etag: f.etag}, nil
}

// DeleteSecret checks the parent ETag before deleting its metadata and history.
func (f *fakeGCPSecrets) DeleteSecret(_ context.Context, r *secretmanagerpb.DeleteSecretRequest) (*emptypb.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.name == "" || r.Name != f.name {
		return nil, status.Error(codes.NotFound, "missing")
	}
	if r.Etag != "" && r.Etag != f.etag {
		return nil, status.Error(codes.FailedPrecondition, "secret ETag changed")
	}
	if f.failDelete {
		f.failDelete = false
		return nil, status.Error(codes.PermissionDenied, "injected failure")
	}
	f.name, f.etag = "", ""
	f.versions, f.values = nil, nil
	return &emptypb.Empty{}, nil
}

// AddSecretVersion appends to an existing object without changing the parent ETag.
func (f *fakeGCPSecrets) AddSecretVersion(_ context.Context, r *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.name == "" || r.Parent != f.name {
		return nil, status.Error(codes.NotFound, "missing")
	}
	if f.failAdd {
		return nil, status.Error(codes.PermissionDenied, "injected failure")
	}
	f.revision++
	v := &secretmanagerpb.SecretVersion{Name: fmt.Sprintf("%s/versions/%d", r.Parent, len(f.versions)+1), State: secretmanagerpb.SecretVersion_ENABLED, Etag: fmt.Sprintf("etag-%d", f.revision)}
	f.versions = append(f.versions, v)
	f.values = append(f.values, append([]byte(nil), r.Payload.Data...))
	return proto.Clone(v).(*secretmanagerpb.SecretVersion), nil
}

// version finds a version while the caller holds the mutex.
func (f *fakeGCPSecrets) version(name string) (*secretmanagerpb.SecretVersion, error) {
	for i, v := range f.versions {
		if v.Name == name || strings.HasSuffix(name, "/latest") && i == len(f.versions)-1 {
			return v, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing")
}

// GetSecretVersion returns a snapshot so concurrent mutations cannot change a response.
func (f *fakeGCPSecrets) GetSecretVersion(_ context.Context, r *secretmanagerpb.GetSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, err := f.version(r.Name)
	if err != nil {
		return nil, err
	}
	return proto.Clone(v).(*secretmanagerpb.SecretVersion), nil
}

// ListSecretVersions returns one version per page, oldest first.
func (f *fakeGCPSecrets) ListSecretVersions(_ context.Context, r *secretmanagerpb.ListSecretVersionsRequest) (*secretmanagerpb.ListSecretVersionsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.name == "" || r.Parent != f.name {
		return nil, status.Error(codes.NotFound, "missing")
	}
	// Oldest first, one version per page, exercises late enabled discovery.
	i, _ := strconv.Atoi(r.PageToken)
	if i >= len(f.versions) {
		return &secretmanagerpb.ListSecretVersionsResponse{}, nil
	}
	next := ""
	if i+1 < len(f.versions) {
		next = strconv.Itoa(i + 1)
	}
	return &secretmanagerpb.ListSecretVersionsResponse{Versions: []*secretmanagerpb.SecretVersion{proto.Clone(f.versions[i]).(*secretmanagerpb.SecretVersion)}, NextPageToken: next}, nil
}

// change applies a version mutation without changing the parent ETag.
func (f *fakeGCPSecrets) change(name string, state secretmanagerpb.SecretVersion_State, etag string) (*secretmanagerpb.SecretVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, err := f.version(name)
	if err != nil {
		return nil, err
	}
	if etag != "" && etag != v.Etag {
		return nil, status.Error(codes.FailedPrecondition, "version ETag changed")
	}
	if v.State == secretmanagerpb.SecretVersion_DESTROYED {
		return nil, status.Error(codes.FailedPrecondition, "destroyed")
	}
	if state == secretmanagerpb.SecretVersion_DESTROYED && f.delayDestroy {
		return proto.Clone(v).(*secretmanagerpb.SecretVersion), nil
	}
	v.State = state
	f.revision++
	v.Etag = fmt.Sprintf("etag-%d", f.revision)
	if state == secretmanagerpb.SecretVersion_DESTROYED {
		for i := range f.versions {
			if f.versions[i] == v {
				f.values[i] = nil
			}
		}
	}
	return proto.Clone(v).(*secretmanagerpb.SecretVersion), nil
}

// DisableSecretVersion archives a version.
func (f *fakeGCPSecrets) DisableSecretVersion(_ context.Context, r *secretmanagerpb.DisableSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	return f.change(r.Name, secretmanagerpb.SecretVersion_DISABLED, r.Etag)
}

// EnableSecretVersion restores a retained version.
func (f *fakeGCPSecrets) EnableSecretVersion(_ context.Context, r *secretmanagerpb.EnableSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	return f.change(r.Name, secretmanagerpb.SecretVersion_ENABLED, r.Etag)
}

// DestroySecretVersion destroys a version, optionally injecting a one-time failure.
func (f *fakeGCPSecrets) DestroySecretVersion(_ context.Context, r *secretmanagerpb.DestroySecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	f.mu.Lock()
	fail := f.failDestroy == r.Name
	if fail {
		f.failDestroy = ""
	}
	f.mu.Unlock()
	if fail {
		return nil, status.Error(codes.PermissionDenied, "injected failure")
	}
	return f.change(r.Name, secretmanagerpb.SecretVersion_DESTROYED, r.Etag)
}

// newTestGCPBackend connects the real backend client to an isolated fake service.
func newTestGCPBackend(t *testing.T) (*GCPSecretManagerBackend, *fakeGCPSecrets) {
	t.Helper()
	l := bufconn.Listen(1024 * 1024)
	f := &fakeGCPSecrets{}
	s := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		f.mu.Lock()
		before := f.beforeRPC
		f.mu.Unlock()
		if before != nil {
			if err := before(info.FullMethod); err != nil {
				return nil, err
			}
		}
		return handler(ctx, req)
	}))
	secretmanagerpb.RegisterSecretManagerServiceServer(s, f)
	go func() { _ = s.Serve(l) }()
	t.Cleanup(s.Stop)
	c, err := secretmanager.NewClient(context.Background(), option.WithoutAuthentication(), option.WithEndpoint("passthrough:///fake"), option.WithGRPCDialOption(grpc.WithInsecure()), option.WithGRPCDialOption(grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return l.Dial() })))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &GCPSecretManagerBackend{name: "gcp", projectID: "test", client: c}, f
}

// pauseGCPRequest blocks the first matching RPC so tests can force an interleaving.
func pauseGCPRequest(t *testing.T, f *fakeGCPSecrets, method string) (<-chan struct{}, func()) {
	t.Helper()
	started, resume := make(chan struct{}), make(chan struct{})
	var paused atomic.Bool
	var released sync.Once
	release := func() { released.Do(func() { close(resume) }) }
	t.Cleanup(release)
	f.mu.Lock()
	f.beforeRPC = func(fullMethod string) error {
		if strings.HasSuffix(fullMethod, "/"+method) && !paused.Swap(true) {
			close(started)
			<-resume
		}
		return nil
	}
	f.mu.Unlock()
	return started, release
}

// TestGCPCreateOnce preserves one initializer both before and after explicit destruction.
func TestGCPCreateOnce(t *testing.T) {
	for _, recreate := range []bool{false, true} {
		t.Run(fmt.Sprintf("recreate=%t", recreate), func(t *testing.T) {
			g, f := newTestGCPBackend(t)
			other := *g
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ks := Keyspace{Prefix: "cluster", Namespace: "ns", BindingName: "binding"}
			if recreate {
				if _, err := g.Create(ctx, ks, "key", []byte("old"), false); err != nil {
					t.Fatal(err)
				}
				if err := g.Archive(ctx, ks, "key"); err != nil {
					t.Fatal(err)
				}
				// Model the retained container left by the previous destroy implementation.
				if _, err := f.change(f.versions[0].Name, secretmanagerpb.SecretVersion_DESTROYED, ""); err != nil {
					t.Fatal(err)
				}
				results := make(chan error, 2)
				for _, backend := range []*GCPSecretManagerBackend{g, &other} {
					go func() {
						_, err := backend.Create(ctx, ks, "key", []byte("replacement"), false)
						results <- err
					}()
				}
				for range 2 {
					if err := <-results; !errors.Is(err, ErrAlreadyExists) {
						t.Fatalf("create on destroyed container: %v", err)
					}
				}
				if len(f.versions) != 1 || f.values[0] != nil {
					t.Fatal("create changed destroyed history")
				}
				if err := g.Destroy(ctx, ks, "key"); err != nil {
					t.Fatal(err)
				}
			}
			started, release := pauseGCPRequest(t, f, "AddSecretVersion")
			winner := make(chan error, 1)
			go func() {
				_, err := g.Create(ctx, ks, "key", []byte("winner"), false)
				winner <- err
			}()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("creator never reached initialization")
			}
			if _, err := other.Create(ctx, ks, "key", []byte("loser"), false); !errors.Is(err, ErrAlreadyExists) {
				t.Errorf("competing create: %v", err)
			}
			if err := other.Destroy(ctx, ks, "key"); err == nil {
				t.Error("destroy removed an object still being initialized")
			}
			release()
			if err := <-winner; err != nil {
				t.Fatal(err)
			}
			if len(f.values) != 1 || string(f.values[0]) != "winner" {
				t.Fatal("concurrent creation did not preserve the sole initializer's value")
			}
		})
	}
}

// TestGCPFailedInitialization refuses automatic takeover of an abandoned empty object.
func TestGCPFailedInitialization(t *testing.T) {
	g, f := newTestGCPBackend(t)
	ctx := context.Background()
	ks := Keyspace{Prefix: "cluster", Namespace: "ns", BindingName: "binding"}
	f.failAdd = true
	if _, err := g.Create(ctx, ks, "key", []byte("first"), false); err == nil {
		t.Fatal("initialization unexpectedly succeeded")
	}
	f.failAdd = false
	if _, err := g.Create(ctx, ks, "key", []byte("second"), false); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("takeover: %v", err)
	}
	if err := g.Destroy(ctx, ks, "key"); err == nil {
		t.Fatal("empty object was deleted without explicit administrative recovery")
	}
	if f.name == "" || len(f.values) != 0 {
		t.Fatal("failed initialization was replaced or removed")
	}
}

// TestGCPWritesPreservePlaintext verifies text and binary writes retain the original payload bytes.
func TestGCPWritesPreservePlaintext(t *testing.T) {
	ks := Keyspace{Prefix: "cluster", Namespace: "ns", BindingName: "binding"}
	for _, tc := range writeTestValues() {
		g, f := newTestGCPBackend(t)
		for i, write := range []func(context.Context, Keyspace, string, []byte, bool) (Entry, error){g.Create, g.Update} {
			if _, err := write(context.Background(), ks, "key", tc.value, tc.binary); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			equal := string(f.values[i]) == string(tc.value)
			f.mu.Unlock()
			if !equal {
				t.Fatal("provider payload changed plaintext bytes")
			}
		}
	}
}

// TestGCPLifecycle verifies archive, restore, retryable destroy, and fresh recreation.
func TestGCPLifecycle(t *testing.T) {
	g, f := newTestGCPBackend(t)
	ctx := context.Background()
	ks := Keyspace{Prefix: "cluster", Namespace: "ns", BindingName: "binding"}
	if _, err := g.Create(ctx, ks, "key", []byte("first"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Update(ctx, ks, "key", []byte("second"), false); err != nil {
		t.Fatal(err)
	}
	if err := g.Archive(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	if err := g.Archive(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	for _, v := range f.versions {
		if v.State != secretmanagerpb.SecretVersion_DISABLED {
			t.Fatal("archive retained an enabled version")
		}
	}
	if _, err := g.Create(ctx, ks, "key", nil, false); !errors.Is(err, ErrArchived) {
		t.Fatalf("create archived: %v", err)
	}
	if _, err := g.Update(ctx, ks, "key", nil, false); !errors.Is(err, ErrArchived) {
		t.Fatalf("update archived: %v", err)
	}
	if _, err := g.Restore(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	if f.versions[0].State != secretmanagerpb.SecretVersion_DISABLED || f.versions[1].State != secretmanagerpb.SecretVersion_ENABLED {
		t.Fatal("restore must enable latest only")
	}
	if err := g.Destroy(ctx, ks, "key"); !errors.Is(err, ErrActive) {
		t.Fatalf("destroy active: %v", err)
	}
	if f.versions[0].State != secretmanagerpb.SecretVersion_DISABLED || string(f.values[0]) != "first" || string(f.values[1]) != "second" {
		t.Fatal("active rejection changed retained data")
	}
	if err := g.Archive(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.failDestroy = f.versions[1].Name
	f.mu.Unlock()
	if err := g.Destroy(ctx, ks, "key"); err == nil {
		t.Fatal("expected injected destroy failure")
	}
	f.failDelete = true
	if err := g.Destroy(ctx, ks, "key"); err == nil {
		t.Fatal("expected injected parent deletion failure")
	}
	if f.name == "" || len(f.versions) != 2 || f.values[0] != nil || f.values[1] != nil {
		t.Fatal("failed parent deletion did not retain only destroyed history")
	}
	if err := g.Destroy(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	if f.name != "" || len(f.versions) != 0 || len(f.values) != 0 {
		t.Fatal("destroy retained the secret object or its history")
	}
	if _, err := g.Restore(ctx, ks, "key"); err == nil {
		t.Fatal("restored destroyed key")
	}
	if _, err := g.Create(ctx, ks, "key", []byte("new"), false); err != nil {
		t.Fatal(err)
	}
	if len(f.versions) != 1 || string(f.values[0]) != "new" {
		t.Fatal("recreate did not initialize a fresh secret object")
	}
}

// TestGCPDestroyPreservesReplacement rejects stale work at each destructive boundary.
func TestGCPDestroyPreservesReplacement(t *testing.T) {
	for _, method := range []string{"ListSecretVersions", "DestroySecretVersion", "DeleteSecret"} {
		t.Run(method, func(t *testing.T) {
			g, f := newTestGCPBackend(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ks := Keyspace{Prefix: "cluster", Namespace: "ns", BindingName: "binding"}
			if _, err := g.Create(ctx, ks, "key", []byte("old"), false); err != nil {
				t.Fatal(err)
			}
			if err := g.Archive(ctx, ks, "key"); err != nil {
				t.Fatal(err)
			}
			started, release := pauseGCPRequest(t, f, method)
			result := make(chan error, 1)
			go func() { result <- g.Destroy(ctx, ks, "key") }()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("destroy never reached the race boundary")
			}
			// Another writer deletes and recreates the same path while destroy is paused.
			if _, err := f.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{Name: f.name, Etag: f.etag}); err != nil {
				t.Fatal(err)
			}
			if _, err := g.Create(ctx, ks, "key", []byte("replacement"), false); err != nil {
				t.Fatal(err)
			}
			if err := g.Archive(ctx, ks, "key"); err != nil {
				t.Fatal(err)
			}
			release()
			if err := <-result; err == nil {
				t.Fatal("stale destroy succeeded")
			}
			if f.name == "" || len(f.values) != 1 || string(f.values[0]) != "replacement" || f.versions[0].State != secretmanagerpb.SecretVersion_DISABLED {
				t.Fatal("stale destroy damaged the replacement")
			}
		})
	}
}

// TestGCPDestroyPreservesRestoredVersion rejects a restore that wins after preflight.
func TestGCPDestroyPreservesRestoredVersion(t *testing.T) {
	g, f := newTestGCPBackend(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ks := Keyspace{Prefix: "cluster", Namespace: "ns", BindingName: "binding"}
	if _, err := g.Create(ctx, ks, "key", []byte("retained"), false); err != nil {
		t.Fatal(err)
	}
	if err := g.Archive(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	started, release := pauseGCPRequest(t, f, "DestroySecretVersion")
	result := make(chan error, 1)
	go func() { result <- g.Destroy(ctx, ks, "key") }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("destroy never reached version destruction")
	}
	if _, err := g.Restore(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	release()
	if err := <-result; status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("destroy after restore: %v", err)
	}
	if f.name == "" || string(f.values[0]) != "retained" || f.versions[0].State != secretmanagerpb.SecretVersion_ENABLED {
		t.Fatal("destroy damaged the restored version")
	}
}

// TestGCPDestroyRespectsDelayedDestruction preserves versions still awaiting destruction.
func TestGCPDestroyRespectsDelayedDestruction(t *testing.T) {
	g, f := newTestGCPBackend(t)
	ctx := context.Background()
	ks := Keyspace{Prefix: "cluster", Namespace: "ns", BindingName: "binding"}
	if _, err := g.Create(ctx, ks, "key", []byte("retained"), false); err != nil {
		t.Fatal(err)
	}
	if err := g.Archive(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	f.delayDestroy = true
	if err := g.Destroy(ctx, ks, "key"); err == nil {
		t.Fatal("destroy bypassed delayed version destruction")
	}
	if f.name == "" || string(f.values[0]) != "retained" {
		t.Fatal("pending destruction removed retained data")
	}
}

// TestGCPDestroyPreflight rejects active history before mutating any page.
func TestGCPDestroyPreflight(t *testing.T) {
	g, f := newTestGCPBackend(t)
	ctx := context.Background()
	ks := Keyspace{Prefix: "cluster", Namespace: "ns", BindingName: "binding"}
	if _, err := g.Create(ctx, ks, "key", []byte("first"), false); err != nil {
		t.Fatal(err)
	}
	if err := g.Archive(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Restore(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Update(ctx, ks, "key", []byte("second"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.change(f.versions[0].Name, secretmanagerpb.SecretVersion_DISABLED, ""); err != nil {
		t.Fatal(err)
	}
	if err := g.Destroy(ctx, ks, "key"); !errors.Is(err, ErrActive) {
		t.Fatalf("destroy active: %v", err)
	}
	if f.versions[0].State != secretmanagerpb.SecretVersion_DISABLED || string(f.values[0]) != "first" {
		t.Fatal("destroy mutated history before rejecting active key")
	}
}

// TestGCPDestroyVersionRequiresArchivedVersion checks allowed version states.
func TestGCPDestroyVersionRequiresArchivedVersion(t *testing.T) {
	destroy, err := gcpDestroyVersion(secretmanagerpb.SecretVersion_ENABLED)
	if !errors.Is(err, ErrActive) {
		t.Fatalf("enabled version error = %v, want ErrActive", err)
	}
	if destroy {
		t.Fatal("enabled version must not be destroyed")
	}

	destroy, err = gcpDestroyVersion(secretmanagerpb.SecretVersion_DISABLED)
	if err != nil {
		t.Fatalf("disabled version error = %v", err)
	}
	if !destroy {
		t.Fatal("disabled version should be destroyed")
	}

	destroy, err = gcpDestroyVersion(secretmanagerpb.SecretVersion_DESTROYED)
	if err != nil {
		t.Fatalf("destroyed version error = %v", err)
	}
	if destroy {
		t.Fatal("already destroyed version should be skipped")
	}
}
