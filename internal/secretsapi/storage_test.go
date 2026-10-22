// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsapi

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/hkdf"
	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	request "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/podplane/operator/internal/secretsbackend"
)

func TestUpdateValidatesAllEntriesBeforeMutation(t *testing.T) {
	keys, err := NewKeyRing(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	backend := &recordingBackend{name: "provider"}
	registry, err := secretsbackend.NewRegistry(backend)
	if err != nil {
		t.Fatal(err)
	}
	storage := &KeyspaceStorage{ClusterID: "cluster", Keys: keys, Backends: registry}
	ctx := request.WithNamespace(context.Background(), "namespace")
	value := encryptForTest(t, keys.PublicKey(), AssociatedData(Algorithm, "cluster", "namespace", "provider.binding", "first", false), []byte("value"))
	obj := &SecretProviderKeyspace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "namespace", Name: "provider.binding"},
		Spec: SecretProviderKeyspaceSpec{Entries: []SecretProviderKeyspaceEntry{
			{Key: "first", Operation: "create", EncryptedValue: &value},
			{Key: "second", Operation: "nonsense"},
		}},
	}

	_, _, err = storage.Update(ctx, "provider.binding", updatedObjectInfo{obj: obj}, nil, func(context.Context, runtime.Object, runtime.Object) error { return nil }, false, &metav1.UpdateOptions{})
	if err == nil {
		t.Fatal("expected invalid operation error")
	}
	if backend.creates != 0 {
		t.Fatalf("backend Create called before full request validation: %d", backend.creates)
	}
}

// TestUpdateRejectsInvalidUTF8BeforeAnyMutation verifies that invalid text rejects
// the entire request without writing values or disclosing their contents.
func TestUpdateRejectsInvalidUTF8BeforeAnyMutation(t *testing.T) {
	for _, operation := range []string{"create", "update"} {
		t.Run(operation, func(t *testing.T) {
			keys, err := NewKeyRing(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			backend := &recordingBackend{name: "provider"}
			registry, err := secretsbackend.NewRegistry(backend)
			if err != nil {
				t.Fatal(err)
			}
			storage := &KeyspaceStorage{ClusterID: "cluster", Keys: keys, Backends: registry}
			obj := &SecretProviderKeyspace{}
			for i, key := range []string{"first", "second"} {
				plaintext := []byte("private-plaintext")
				if i == 1 {
					plaintext = append(plaintext, 0xff)
				}
				value := encryptForTest(t, keys.PublicKey(), AssociatedData(Algorithm, "cluster", "namespace", "provider.binding", key, false), plaintext)
				obj.Spec.Entries = append(obj.Spec.Entries, SecretProviderKeyspaceEntry{Key: key, Operation: operation, EncryptedValue: &value})
			}
			ctx := request.WithNamespace(context.Background(), "namespace")
			_, _, err = storage.Update(ctx, "provider.binding", updatedObjectInfo{obj: obj}, nil, func(context.Context, runtime.Object, runtime.Object) error { return nil }, false, &metav1.UpdateOptions{})
			if !apierrors.IsBadRequest(err) || !strings.HasSuffix(err.Error(), "secret value must be valid UTF-8") || strings.Contains(err.Error(), "private-plaintext") {
				t.Fatalf("expected non-disclosing UTF-8 bad request, got %v", err)
			}
			if backend.creates != 0 || backend.updates != 0 {
				t.Fatal("request mutated backend before validating all plaintext")
			}
		})
	}
}

func TestUpdateUsesExistingVirtualKeyspaceObject(t *testing.T) {
	keys, err := NewKeyRing(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	backend := &recordingBackend{name: "provider"}
	registry, err := secretsbackend.NewRegistry(backend)
	if err != nil {
		t.Fatal(err)
	}
	storage := &KeyspaceStorage{ClusterID: "cluster", Keys: keys, Backends: registry}
	ctx := request.WithNamespace(context.Background(), "namespace")
	plaintext := " \t雪🙂e\u0301\r\nsecond line\nc2VjcmV0Cg==\n"
	value := encryptForTest(t, keys.PublicKey(), AssociatedData(Algorithm, "cluster", "namespace", "provider.binding", "first", false), []byte(plaintext))
	obj := &SecretProviderKeyspace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "namespace", Name: "provider.binding"},
		Spec:       SecretProviderKeyspaceSpec{Entries: []SecretProviderKeyspaceEntry{{Key: "first", Operation: "create", EncryptedValue: &value}}},
	}

	_, _, err = storage.Update(ctx, "provider.binding", requireExistingObjectInfo{obj: obj}, nil, func(context.Context, runtime.Object, runtime.Object) error { return nil }, false, &metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("update virtual keyspace: %v", err)
	}
	if backend.creates != 1 {
		t.Fatalf("backend Create calls = %d, want 1", backend.creates)
	}
	if string(backend.value) != plaintext {
		t.Fatal("API changed plaintext bytes")
	}
}

func TestGetReportsUnconfiguredProvider(t *testing.T) {
	registry, err := secretsbackend.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	storage := &KeyspaceStorage{ClusterID: "cluster", Backends: registry}
	ctx := request.WithNamespace(context.Background(), "namespace")

	_, err = storage.Get(ctx, "local-fakevault.hello", &metav1.GetOptions{})
	if err == nil {
		t.Fatal("expected unconfigured provider error")
	}
	if !apierrors.IsNotFound(err) {
		t.Fatalf("error = %v, want not found", err)
	}
	message := err.Error()
	if !strings.Contains(message, `secrets provider "local-fakevault" is not configured`) {
		t.Fatalf("error = %q, want unconfigured provider detail", message)
	}
}

type updatedObjectInfo struct{ obj runtime.Object }

func (u updatedObjectInfo) Preconditions() *metav1.Preconditions { return nil }
func (u updatedObjectInfo) UpdatedObject(context.Context, runtime.Object) (runtime.Object, error) {
	return u.obj, nil
}

var _ rest.UpdatedObjectInfo = updatedObjectInfo{}

type requireExistingObjectInfo struct{ obj runtime.Object }

func (r requireExistingObjectInfo) Preconditions() *metav1.Preconditions { return nil }
func (r requireExistingObjectInfo) UpdatedObject(_ context.Context, old runtime.Object) (runtime.Object, error) {
	accessor, err := meta.Accessor(old)
	if err != nil {
		return nil, err
	}
	if accessor.GetUID() == "" {
		return nil, apierrors.NewNotFound(keyspaceResource(), accessor.GetName())
	}
	return r.obj, nil
}

var _ rest.UpdatedObjectInfo = requireExistingObjectInfo{}

type recordingBackend struct {
	name    string
	creates int
	updates int
	value   []byte
	binary  bool
}

func (r *recordingBackend) ProviderName() string { return r.name }
func (r *recordingBackend) ProviderKind() string { return "memory" }

// Create records the plaintext and binary flag passed to the backend.
func (r *recordingBackend) Create(_ context.Context, _ secretsbackend.Keyspace, _ string, value []byte, binary bool) (secretsbackend.Entry, error) {
	r.creates++
	r.value = append([]byte(nil), value...)
	r.binary = binary
	return secretsbackend.Entry{}, nil
}

// Update records the plaintext and binary flag passed to the backend.
func (r *recordingBackend) Update(_ context.Context, _ secretsbackend.Keyspace, _ string, value []byte, binary bool) (secretsbackend.Entry, error) {
	r.updates++
	r.value = append([]byte(nil), value...)
	r.binary = binary
	return secretsbackend.Entry{}, nil
}
func (r *recordingBackend) List(context.Context, secretsbackend.Keyspace) ([]secretsbackend.Entry, error) {
	return nil, nil
}
func (r *recordingBackend) Archive(context.Context, secretsbackend.Keyspace, string) error {
	return nil
}
func (r *recordingBackend) ArchiveAll(context.Context, secretsbackend.Keyspace) error { return nil }
func (r *recordingBackend) Restore(context.Context, secretsbackend.Keyspace, string) (secretsbackend.Entry, error) {
	return secretsbackend.Entry{}, nil
}
func (r *recordingBackend) Destroy(context.Context, secretsbackend.Keyspace, string) error {
	return nil
}
func (r *recordingBackend) DestroyAll(context.Context, secretsbackend.Keyspace) error { return nil }

// TestBinaryWritesAndAuthenticatedIntent verifies plaintext and binary intent
// survive encrypted writes, while tampered flags and invalid batches are rejected.
func TestBinaryWritesAndAuthenticatedIntent(t *testing.T) {
	for _, operation := range []string{"create", "update"} {
		for _, plaintext := range [][]byte{[]byte("c2VjcmV0Cg=="), {0xff, 0, 0xc3}} {
			for _, mode := range []string{"text", "binary", "removed", "added", "restore", "mixed"} {
				t.Run(operation+"/"+mode, func(t *testing.T) {
					keys, err := NewKeyRing(time.Hour)
					if err != nil {
						t.Fatal(err)
					}
					backend := &recordingBackend{name: "provider"}
					registry, err := secretsbackend.NewRegistry(backend)
					if err != nil {
						t.Fatal(err)
					}
					kube := fake.NewClientset()
					kube.PrependReactor("create", "subjectaccessreviews", func(clienttesting.Action) (bool, runtime.Object, error) {
						return true, &authv1.SubjectAccessReview{Status: authv1.SubjectAccessReviewStatus{Allowed: true}}, nil
					})
					storage := &KeyspaceStorage{ClusterID: "cluster", Keys: keys, Backends: registry, Kube: kube}
					ctx := request.WithUser(request.WithNamespace(context.Background(), "namespace"), &user.DefaultInfo{Name: "test"})
					encrypted := encryptForTest(t, keys.PublicKey(), AssociatedData(Algorithm, "cluster", "namespace", "provider.binding", "first", mode != "added" && mode != "text"), plaintext)
					entry := SecretProviderKeyspaceEntry{Key: "first", Operation: operation, Binary: mode != "removed" && mode != "text", EncryptedValue: &encrypted}
					if mode == "restore" {
						entry.Operation = "restore"
						entry.EncryptedValue = nil
					}
					obj := &SecretProviderKeyspace{Spec: SecretProviderKeyspaceSpec{Entries: []SecretProviderKeyspaceEntry{entry}}}
					if mode == "mixed" {
						invalid := encryptForTest(t, keys.PublicKey(), AssociatedData(Algorithm, "cluster", "namespace", "provider.binding", "second", false), []byte{0xff})
						obj.Spec.Entries = append(obj.Spec.Entries, SecretProviderKeyspaceEntry{Key: "second", Operation: operation, EncryptedValue: &invalid})
					}
					_, _, err = storage.Update(ctx, "provider.binding", updatedObjectInfo{obj: obj}, nil, func(context.Context, runtime.Object, runtime.Object) error { return nil }, false, &metav1.UpdateOptions{})
					if mode == "binary" || mode == "text" && utf8.Valid(plaintext) {
						if err != nil {
							t.Fatal(err)
						}
						if backend.creates+backend.updates != 1 || backend.binary != entry.Binary || string(backend.value) != string(plaintext) {
							t.Fatal("binary intent or raw bytes lost")
						}
					} else if !apierrors.IsBadRequest(err) || backend.creates+backend.updates != 0 {
						t.Fatalf("expected atomic rejection, got %v", err)
					}
				})
			}
		}
	}
	context := Algorithm + "\x00cluster\x00namespace\x00provider.binding\x00first"
	if string(AssociatedData(Algorithm, "cluster", "namespace", "provider.binding", "first", false)) != context+"\x00false" || string(AssociatedData(Algorithm, "cluster", "namespace", "provider.binding", "first", true)) != context+"\x00true" {
		t.Fatal("encryption context must include explicit text or binary mode")
	}
}

func encryptForTest(t *testing.T, pub PublicKey, aad, plaintext []byte) EncryptedValue {
	t.Helper()
	serverPublic, err := base64.StdEncoding.DecodeString(pub.Spec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.X25519().NewPublicKey(serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := eph.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	hk := hkdf.New(sha256.New, shared, eph.PublicKey().Bytes(), []byte("podplane secrets v1"))
	cek := make([]byte, 32)
	if _, err := hk.Read(cek); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	env := envelope{Version: "podplane-secrets-v1", EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(eph.PublicKey().Bytes()), Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(gcm.Seal(nil, nonce, plaintext, aad))}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return EncryptedValue{KeyID: pub.Spec.KeyID, Algorithm: Algorithm, Ciphertext: "podplane-secrets-v1." + base64.RawURLEncoding.EncodeToString(raw)}
}
