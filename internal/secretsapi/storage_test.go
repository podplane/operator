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
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	request "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

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
	storage := &KeyspaceStorage{ClusterID: "cluster", Prefix: "cluster", Keys: keys, Backends: registry}
	ctx := request.WithNamespace(context.Background(), "namespace")
	value := encryptForTest(t, keys.PublicKey(), AssociatedData(Algorithm, "cluster", "namespace", "provider.binding", "first"), []byte("value"))
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

type updatedObjectInfo struct{ obj runtime.Object }

func (u updatedObjectInfo) Preconditions() *metav1.Preconditions { return nil }
func (u updatedObjectInfo) UpdatedObject(context.Context, runtime.Object) (runtime.Object, error) {
	return u.obj, nil
}

var _ rest.UpdatedObjectInfo = updatedObjectInfo{}

type recordingBackend struct {
	name    string
	creates int
}

func (r *recordingBackend) ProviderName() string { return r.name }
func (r *recordingBackend) ProviderKind() string { return "memory" }
func (r *recordingBackend) Create(context.Context, secretsbackend.Keyspace, string, []byte) (secretsbackend.Entry, error) {
	r.creates++
	return secretsbackend.Entry{}, nil
}
func (r *recordingBackend) Update(context.Context, secretsbackend.Keyspace, string, []byte) (secretsbackend.Entry, error) {
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
