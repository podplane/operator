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
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type fakeGCPSecrets struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
	mu          sync.Mutex
	name        string
	versions    []*secretmanagerpb.SecretVersion
	values      [][]byte
	failDestroy string
}

func (f *fakeGCPSecrets) CreateSecret(_ context.Context, r *secretmanagerpb.CreateSecretRequest) (*secretmanagerpb.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.name != "" {
		return nil, status.Error(codes.AlreadyExists, "exists")
	}
	f.name = r.Parent + "/secrets/" + r.SecretId
	return &secretmanagerpb.Secret{Name: f.name}, nil
}

func (f *fakeGCPSecrets) AddSecretVersion(_ context.Context, r *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := &secretmanagerpb.SecretVersion{Name: fmt.Sprintf("%s/versions/%d", r.Parent, len(f.versions)+1), State: secretmanagerpb.SecretVersion_ENABLED}
	f.versions = append(f.versions, v)
	f.values = append(f.values, append([]byte(nil), r.Payload.Data...))
	return v, nil
}

func (f *fakeGCPSecrets) version(name string) (*secretmanagerpb.SecretVersion, error) {
	for i, v := range f.versions {
		if v.Name == name || strings.HasSuffix(name, "/latest") && i == len(f.versions)-1 {
			return v, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing")
}

func (f *fakeGCPSecrets) GetSecretVersion(_ context.Context, r *secretmanagerpb.GetSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.version(r.Name)
}

func (f *fakeGCPSecrets) ListSecretVersions(_ context.Context, r *secretmanagerpb.ListSecretVersionsRequest) (*secretmanagerpb.ListSecretVersionsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Oldest first, one version per page, exercises late enabled discovery.
	i, _ := strconv.Atoi(r.PageToken)
	if i >= len(f.versions) {
		return &secretmanagerpb.ListSecretVersionsResponse{}, nil
	}
	next := ""
	if i+1 < len(f.versions) {
		next = strconv.Itoa(i + 1)
	}
	return &secretmanagerpb.ListSecretVersionsResponse{Versions: f.versions[i : i+1], NextPageToken: next}, nil
}

func (f *fakeGCPSecrets) change(name string, state secretmanagerpb.SecretVersion_State) (*secretmanagerpb.SecretVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, err := f.version(name)
	if err != nil {
		return nil, err
	}
	if v.State == secretmanagerpb.SecretVersion_DESTROYED {
		return nil, status.Error(codes.FailedPrecondition, "destroyed")
	}
	v.State = state
	if state == secretmanagerpb.SecretVersion_DESTROYED {
		for i := range f.versions {
			if f.versions[i] == v {
				f.values[i] = nil
			}
		}
	}
	return v, nil
}

func (f *fakeGCPSecrets) DisableSecretVersion(_ context.Context, r *secretmanagerpb.DisableSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	return f.change(r.Name, secretmanagerpb.SecretVersion_DISABLED)
}
func (f *fakeGCPSecrets) EnableSecretVersion(_ context.Context, r *secretmanagerpb.EnableSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	return f.change(r.Name, secretmanagerpb.SecretVersion_ENABLED)
}
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
	return f.change(r.Name, secretmanagerpb.SecretVersion_DESTROYED)
}

func newTestGCPBackend(t *testing.T) (*GCPSecretManagerBackend, *fakeGCPSecrets) {
	t.Helper()
	l := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	f := &fakeGCPSecrets{}
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

func TestGCPLifecycle(t *testing.T) {
	g, f := newTestGCPBackend(t)
	ctx := context.Background()
	ks := Keyspace{Prefix: "cluster", Namespace: "ns", BindingName: "binding"}
	if _, err := g.Create(ctx, ks, "key", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Update(ctx, ks, "key", []byte("second")); err != nil {
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
	if _, err := g.Create(ctx, ks, "key", nil); !errors.Is(err, ErrArchived) {
		t.Fatalf("create archived: %v", err)
	}
	if _, err := g.Update(ctx, ks, "key", nil); !errors.Is(err, ErrArchived) {
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
	if err := g.Destroy(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	for i, v := range f.versions {
		if v.State != secretmanagerpb.SecretVersion_DESTROYED || f.values[i] != nil {
			t.Fatal("destroy retained data")
		}
	}
	if _, err := g.Restore(ctx, ks, "key"); err == nil {
		t.Fatal("restored destroyed key")
	}
	if _, err := g.Create(ctx, ks, "key", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if len(f.versions) != 3 || f.versions[2].State != secretmanagerpb.SecretVersion_ENABLED {
		t.Fatal("recreate did not add new latest")
	}
}

func TestGCPDestroyPreflight(t *testing.T) {
	g, f := newTestGCPBackend(t)
	ctx := context.Background()
	ks := Keyspace{Prefix: "cluster", Namespace: "ns", BindingName: "binding"}
	if _, err := g.Create(ctx, ks, "key", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := g.Archive(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Restore(ctx, ks, "key"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Update(ctx, ks, "key", []byte("second")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.change(f.versions[0].Name, secretmanagerpb.SecretVersion_DISABLED); err != nil {
		t.Fatal(err)
	}
	if err := g.Destroy(ctx, ks, "key"); !errors.Is(err, ErrActive) {
		t.Fatalf("destroy active: %v", err)
	}
	if f.versions[0].State != secretmanagerpb.SecretVersion_DISABLED || string(f.values[0]) != "first" {
		t.Fatal("destroy mutated history before rejecting active key")
	}
}

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
