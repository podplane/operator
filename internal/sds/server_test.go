// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package sds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

// TestCertificateFlags validates accepted, malformed, and duplicate mappings.
func TestCertificateFlags(t *testing.T) {
	flags := certificateFlags{}
	if err := flags.Set("bundle-example=example.com"); err != nil {
		t.Fatalf("Set valid mapping: %v", err)
	}
	if err := flags.Set("bundle-example=example.net"); err == nil {
		t.Fatal("Set duplicate mapping succeeded")
	}
	for _, value := range []string{"missing-separator", "=example.com", "bundle=", "../bundle=example.com", `dir\bundle=example.com`} {
		if err := flags.Set(value); err == nil {
			t.Errorf("Set(%q) succeeded", value)
		}
	}
}

// TestLoadBuildsValidatedTLSResources verifies bundle splitting and SDS resource construction.
func TestLoadBuildsValidatedTLSResources(t *testing.T) {
	directory := t.TempDir()
	writeBundle(t, directory, "bundle-example", certificateBundle(t, "example.com", 1))

	hashes, resources, err := load(directory, certificateFlags{"bundle-example": "example.com"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(hashes) != 1 || len(resources) != 1 {
		t.Fatalf("load returned %d hashes and %d resources, want 1 each", len(hashes), len(resources))
	}
	secret := resources["bundle-example"].(*tlsv3.Secret).GetTlsCertificate()
	if len(secret.GetCertificateChain().GetInlineBytes()) == 0 || len(secret.GetPrivateKey().GetInlineBytes()) == 0 {
		t.Fatal("SDS resource does not contain both certificate chain and private key")
	}
}

// TestLoadRejectsWrongDomain verifies exact apex-and-wildcard SAN enforcement.
func TestLoadRejectsWrongDomain(t *testing.T) {
	directory := t.TempDir()
	writeBundle(t, directory, "bundle-example", certificateBundle(t, "example.com", 1))
	if _, _, err := load(directory, certificateFlags{"bundle-example": "example.net"}); err == nil {
		t.Fatal("load accepted a certificate for another domain")
	}
}

// TestPollPublishesValidRotation verifies that a complete valid update replaces the cache.
func TestPollPublishesValidRotation(t *testing.T) {
	directory := t.TempDir()
	name := "bundle-example"
	first := certificateBundle(t, "example.com", 1)
	second := certificateBundle(t, "example.com", 2)
	writeBundle(t, directory, name, first)
	flags := certificateFlags{name: "example.com"}
	hashes, resources, err := load(directory, flags)
	if err != nil {
		t.Fatalf("load initial bundle: %v", err)
	}
	cache := cachev3.NewLinearCache(resourcev3.SecretType)
	cache.SetResources(resources)
	initialKey := resourceKey(t, cache, name)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go poll(ctx, 5*time.Millisecond, directory, flags, cache, hashes)
	writeBundle(t, directory, name, second)

	waitFor(t, func() bool { return !bytes.Equal(resourceKey(t, cache, name), initialKey) })
}

// TestPollRetainsLastGoodRotation verifies malformed and missing updates do not replace valid resources.
func TestPollRetainsLastGoodRotation(t *testing.T) {
	directory := t.TempDir()
	name := "bundle-example"
	writeBundle(t, directory, name, certificateBundle(t, "example.com", 1))
	flags := certificateFlags{name: "example.com"}
	hashes, resources, err := load(directory, flags)
	if err != nil {
		t.Fatalf("load initial bundle: %v", err)
	}
	cache := cachev3.NewLinearCache(resourcev3.SecretType)
	cache.SetResources(resources)
	initialKey := resourceKey(t, cache, name)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go poll(ctx, 5*time.Millisecond, directory, flags, cache, hashes)

	writeBundle(t, directory, name, []byte("not PEM"))
	time.Sleep(25 * time.Millisecond)
	if got := resourceKey(t, cache, name); !bytes.Equal(got, initialKey) {
		t.Fatal("malformed rotation replaced the last-known-good resource")
	}
	writeBundle(t, directory, name, certificateBundle(t, "example.net", 2))
	time.Sleep(25 * time.Millisecond)
	if got := resourceKey(t, cache, name); !bytes.Equal(got, initialKey) {
		t.Fatal("wrong-domain rotation replaced the last-known-good resource")
	}
	if err := os.Remove(filepath.Join(directory, name)); err != nil {
		t.Fatalf("remove bundle: %v", err)
	}
	time.Sleep(25 * time.Millisecond)
	if got := resourceKey(t, cache, name); !bytes.Equal(got, initialKey) {
		t.Fatal("missing rotation replaced the last-known-good resource")
	}
}

// TestListenProtectsSocketPath verifies non-socket refusal and exact socket permissions.
func TestListenProtectsSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sds.sock")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	if _, err := listen(path); err == nil {
		t.Fatal("listen replaced a non-socket path")
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove sentinel: %v", err)
	}
	listener, err := listen(path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o660); got != want {
		t.Fatalf("socket permissions = %o, want %o", got, want)
	}
}

// certificateBundle returns a valid apex-and-wildcard combined PEM bundle.
func certificateBundle(t *testing.T, domain string, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain, "*." + domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(bundle, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
}

// writeBundle atomically replaces one mounted bundle fixture.
func writeBundle(t *testing.T, directory, name string, value []byte) {
	t.Helper()
	temporary := filepath.Join(directory, name+".new")
	if err := os.WriteFile(temporary, value, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.Rename(temporary, filepath.Join(directory, name)); err != nil {
		t.Fatalf("replace bundle: %v", err)
	}
}

// resourceKey returns a copy of one cached resource's inline private key.
func resourceKey(t *testing.T, cache *cachev3.LinearCache, name string) []byte {
	t.Helper()
	resource, ok := cache.GetResources()[name]
	if !ok {
		t.Fatalf("cache does not contain resource %q", name)
	}
	key := resource.(*tlsv3.Secret).GetTlsCertificate().GetPrivateKey().GetInlineBytes()
	return append([]byte(nil), key...)
}

// waitFor waits for condition to become true within one second.
func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not met before timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
