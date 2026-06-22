// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsapi

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KeyRing keeps the current in-memory X25519 key pair.
type KeyRing struct {
	mu       sync.RWMutex
	key      currentKey
	rotation time.Duration
}
type currentKey struct {
	id      string
	created time.Time
	private *ecdh.PrivateKey
	public  []byte
}

type envelope struct {
	Version            string `json:"version"`
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
}

// NewKeyRing creates a key ring and immediately generates its first key.
func NewKeyRing(rotation time.Duration) (*KeyRing, error) {
	k := &KeyRing{rotation: rotation}
	return k, k.rotateLocked()
}

// Start rotates keys until stop is closed.
func (k *KeyRing) Start(stop <-chan struct{}) {
	ticker := time.NewTicker(k.rotation)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				k.mu.Lock()
				_ = k.rotateLocked()
				k.mu.Unlock()
			case <-stop:
				return
			}
		}
	}()
}

// rotateLocked generates and installs a new key while k.mu is held.
func (k *KeyRing) rotateLocked() error {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	k.key = currentKey{id: uuid.NewString(), created: time.Now().UTC(), private: priv, public: priv.PublicKey().Bytes()}
	return nil
}

// PublicKey returns the current public key API object.
func (k *KeyRing) PublicKey() PublicKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return PublicKey{TypeMeta: metav1.TypeMeta{APIVersion: GroupVersion, Kind: "PublicKey"}, ObjectMeta: metav1.ObjectMeta{Name: "latest"}, Spec: PublicKeySpec{KeyID: k.key.id, CreatedAt: metav1.NewTime(k.key.created), Algorithm: Algorithm, PublicKey: base64.StdEncoding.EncodeToString(k.key.public)}}
}

// Decrypt opens an encrypted value for the current key.
func (k *KeyRing) Decrypt(ev EncryptedValue, aad []byte) ([]byte, error) {
	k.mu.RLock()
	key := k.key
	k.mu.RUnlock()
	if ev.KeyID != key.id {
		return nil, StaleKeyError{}
	}
	if ev.Algorithm != Algorithm {
		return nil, fmt.Errorf("unsupported encrypted value algorithm %q", ev.Algorithm)
	}
	if !strings.HasPrefix(ev.Ciphertext, "podplane-secrets-v1.") {
		return nil, fmt.Errorf("unsupported ciphertext envelope")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(ev.Ciphertext, "podplane-secrets-v1."))
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.Version != "podplane-secrets-v1" {
		return nil, fmt.Errorf("unsupported envelope version %q", env.Version)
	}
	eph, err := base64.RawURLEncoding.DecodeString(env.EphemeralPublicKey)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.RawURLEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(eph)
	if err != nil {
		return nil, err
	}
	shared, err := key.private.ECDH(pub)
	if err != nil {
		return nil, err
	}
	hk := hkdf.New(sha256.New, shared, eph, []byte("podplane secrets v1"))
	cek := make([]byte, 32)
	if _, err := hk.Read(cek); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid ciphertext nonce length")
	}
	return gcm.Open(nil, nonce, ct, aad)
}

// StaleKeyError reports that a client used an old public key.
type StaleKeyError struct{}

// Error implements error.
func (StaleKeyError) Error() string { return "stale public key" }

// AssociatedData returns the authenticated encryption context for a key write.
func AssociatedData(algorithm, clusterID, namespace, resourceName, key string) []byte {
	return []byte(strings.Join([]string{algorithm, clusterID, namespace, resourceName, key}, "\x00"))
}
