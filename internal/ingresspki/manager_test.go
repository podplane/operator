// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package ingresspki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/podplane/operator/internal/secretsbackend"
)

// memoryStore is a concurrent test implementation of Store.
type memoryStore struct {
	mu     sync.Mutex
	values map[string][]byte
}

// newMemoryStore constructs isolated memory store state.
func newMemoryStore() *memoryStore { return &memoryStore{values: map[string][]byte{}} }

// Load returns a copy of a stored test value.
func (s *memoryStore) Load(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[key]
	if !ok {
		return nil, secretsbackend.ErrNotFound
	}
	return append([]byte(nil), value...), nil
}

// Save stores a copy of a test value.
func (s *memoryStore) Save(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = append([]byte(nil), value...)
	return nil
}

// fakeIssuer returns a configured bundle or error and counts requests.
type fakeIssuer struct {
	bundle []byte
	err    error
	calls  int
}

// Obtain records one request and returns the configured result.
func (i *fakeIssuer) Obtain(context.Context, Domain) ([]byte, error) {
	i.calls++
	return append([]byte(nil), i.bundle...), i.err
}

// TestManagerInitializesFallback requires a valid bundle before startup.
func TestManagerInitializesFallback(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	manager, err := NewManager(Config{Domains: []Domain{{Name: "example.com"}}}, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	if err := manager.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	bundle, err := store.Load(context.Background(), bundleKey("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := validateBundle(bundle, "example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if !info.selfSigned {
		t.Fatal("fallback certificate is not self-signed")
	}
	if err := manager.Ready(nil); err != nil {
		t.Fatalf("manager is not ready: %v", err)
	}
}

// TestManagerPromotesACMEBundle replaces a fallback with a validated public chain.
func TestManagerPromotesACMEBundle(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	issuer := &fakeIssuer{bundle: signedBundle(t, "example.com", now)}
	manager, err := NewManager(Config{Domains: []Domain{{Name: "example.com", DNSProvider: DNSProvider{Kind: "aws-route53"}}}}, store, issuer)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	if err := manager.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.reconcile(context.Background(), manager.config.Domains[0]); err != nil {
		t.Fatal(err)
	}
	bundle, err := store.Load(context.Background(), bundleKey("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := validateBundle(bundle, "example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if info.selfSigned {
		t.Fatal("ACME bundle was not promoted")
	}
	if issuer.calls != 1 {
		t.Fatalf("issuer calls = %d, want 1", issuer.calls)
	}
}

// TestManagerRetainsCurrentBundleWhenACMEFails preserves the last usable generation.
func TestManagerRetainsCurrentBundleWhenACMEFails(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	issuer := &fakeIssuer{err: errors.New("temporary failure")}
	manager, err := NewManager(Config{Domains: []Domain{{Name: "example.com", DNSProvider: DNSProvider{Kind: "aws-route53"}}}}, store, issuer)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	if err := manager.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Load(context.Background(), bundleKey("example.com"))
	if err := manager.reconcile(context.Background(), manager.config.Domains[0]); err == nil {
		t.Fatal("reconcile succeeded, want ACME failure")
	}
	after, _ := store.Load(context.Background(), bundleKey("example.com"))
	if string(after) != string(before) {
		t.Fatal("ACME failure replaced the current fallback")
	}
	if err := manager.Ready(nil); err != nil {
		t.Fatalf("fallback should keep manager ready: %v", err)
	}
}

// signedBundle creates a valid, publicly trusted-style test bundle.
func signedBundle(t *testing.T, domain string, now time.Time) []byte {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		DNSNames:     []string{domain, "*." + domain},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	return bundle
}
