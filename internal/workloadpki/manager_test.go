// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package workloadpki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestServiceDNSNames verifies canonical Kubernetes Service identity derivation.
func TestServiceDNSNames(t *testing.T) {
	want := []string{"api", "api.payments", "api.payments.svc", "api.payments.svc.cluster.local"}
	if got := ServiceDNSNames("api", "payments"); !slices.Equal(got, want) {
		t.Fatalf("ServiceDNSNames() = %v, want %v", got, want)
	}
}

// TestValidateCSRProofContentsAndAllSupportedKeys covers the complete CSR policy.
func TestValidateCSRProofContentsAndAllSupportedKeys(t *testing.T) {
	keys := map[string]crypto.Signer{}
	for _, bits := range []int{3072, 4096} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		keys[keyType(&key.PublicKey)] = key
	}
	for _, curve := range []struct {
		name  string
		curve elliptic.Curve
	}{
		{"ECDSAP256", elliptic.P256()}, {"ECDSAP384", elliptic.P384()}, {"ECDSAP521", elliptic.P521()},
	} {
		key, err := ecdsa.GenerateKey(curve.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[curve.name] = key
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys["ED25519"] = edKey
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			if err != nil {
				t.Fatal(err)
			}
			csr, _, err := validateCSR(der)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateKey(csr.PublicKey); err != nil {
				t.Fatal(err)
			}
			der[len(der)-1] ^= 1
			if _, _, err := validateCSR(der); err == nil {
				t.Fatal("accepted invalid proof of possession")
			}
		})
	}

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for name, template := range map[string]*x509.CertificateRequest{
		"subject":   {Subject: pkix.Name{CommonName: "injected"}},
		"extension": {DNSNames: []string{"injected.example"}},
		"attribute": {Attributes: []pkix.AttributeTypeAndValueSET{{Type: []int{1, 2, 3}, Value: [][]pkix.AttributeTypeAndValue{{{Type: []int{1, 2, 3, 4}, Value: "x"}}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := validateCSR(der); err == nil {
				t.Fatal("accepted nonempty CSR")
			}
		})
	}
}

// TestRandomSerialIsPositiveBounded128Bit bounds generated certificate serials.
func TestRandomSerialIsPositiveBounded128Bit(t *testing.T) {
	for range 100 {
		n, err := randomSerial()
		if err != nil {
			t.Fatal(err)
		}
		if n.Sign() <= 0 || n.BitLen() > 128 || n.Cmp(big.NewInt(0)) == 0 {
			t.Fatalf("invalid serial %v", n)
		}
	}
}

// TestAnnotationsFailClosed rejects unknown or incomplete identity annotations.
func TestAnnotationsFailClosed(t *testing.T) {
	tests := []struct {
		name string
		a    map[string]string
		mode string
		svc  string
		bad  bool
	}{
		{"default", nil, "spiffe", "", false},
		{"spiffe service", map[string]string{ServiceAnnotation: "api"}, "spiffe", "api", false},
		{"service", map[string]string{ModeAnnotation: "service", ServiceAnnotation: "api"}, "service", "api", false},
		{"service missing", map[string]string{ModeAnnotation: "service"}, "", "", true},
		{"unknown", map[string]string{"example.com/san": "evil"}, "", "", true},
		{"invalid name", map[string]string{ServiceAnnotation: "other/api"}, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, svc, err := parseAnnotations(tt.a)
			if (err != nil) != tt.bad || (!tt.bad && (mode != tt.mode || svc != tt.svc)) {
				t.Fatalf("parseAnnotations() = %q, %q, %v", mode, svc, err)
			}
		})
	}
}

// TestStrictPKCS8Ed25519Loading rejects unsupported workload CA encodings.
func TestStrictPKCS8Ed25519Loading(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	path := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseKeyFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), []byte("junk")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseKeyFile(path); err == nil {
		t.Fatal("accepted trailing data")
	}
}

// TestChangedCAKeyCannotPublishWhenBundleIsMissing prevents accidental trust replacement.
func TestChangedCAKeyCannotPublishWhenBundleIsMissing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := certv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	path := t.TempDir() + "/ca.pem"
	first := writePKCS8Key(t, path)
	m := &Manager{client: c, reader: c, cfg: Config{TrustDomain: "k8s.example", CAPath: path}}
	m.reconcileCA(ctx)
	if !m.ready || m.active == nil || !m.active.key.Equal(first) {
		t.Fatal("initial CA did not become active")
	}
	var bundle certv1.ClusterTrustBundle
	if err := c.Get(ctx, types.NamespacedName{Name: BundleName}, &bundle); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, &bundle); err != nil {
		t.Fatal(err)
	}
	writePKCS8Key(t, path)
	m.reconcileCA(ctx)
	if !m.ready || !m.active.key.Equal(first) {
		t.Fatal("changed key displaced the last known-good signer")
	}
	if err := c.Get(ctx, types.NamespacedName{Name: BundleName}, &bundle); !apierrors.IsNotFound(err) {
		t.Fatalf("changed key published a replacement trust bundle: %v", err)
	}
}

// writePKCS8Key persists pkcs8 key with the required encoding and permissions.
func writePKCS8Key(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return key
}

// TestSPIFFEAndServiceCertificateContracts verifies both supported leaf identities.
func TestSPIFFEAndServiceCertificateContracts(t *testing.T) {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	root, err := newRoot(caKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{cfg: Config{TrustDomain: "k8s.example"}, active: &signingPair{key: caKey, cert: root}, canSign: true, ready: true}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	p := &certv1.PodCertificateRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Generation: 7}, Spec: certv1.PodCertificateRequestSpec{ServiceAccountName: "api"}}

	spiffe, err := m.sign(p, pub, "spiffe", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := parseLeaf(t, spiffe.CertificateChain)
	if len(c.URIs) != 1 || c.URIs[0].String() != "spiffe://k8s.example/ns/payments/sa/api" || len(c.DNSNames) != 0 || len(c.ExtKeyUsage) != 2 {
		t.Fatalf("unexpected SPIFFE certificate: %+v", c)
	}
	if c.Subject.String() != "" || c.SerialNumber.Sign() <= 0 || c.NotAfter.Sub(c.NotBefore) > maxLifetime {
		t.Fatal("leaf invariant violated")
	}

	a := &authorization{dns: []string{"web", "web.payments", "web.payments.svc", "web.payments.svc.cluster.local"}}
	service, err := m.sign(p, pub, "service", a)
	if err != nil {
		t.Fatal(err)
	}
	c = parseLeaf(t, service.CertificateChain)
	if len(c.URIs) != 0 || len(c.DNSNames) != 4 || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("unexpected service certificate: %+v", c)
	}
}

// TestOperatorServingCertificateGenerationAndRotation covers fixed endpoint key-pair lifecycle.
func TestOperatorServingCertificateGenerationAndRotation(t *testing.T) {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	root, err := newRoot(caKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := ServingCertificate{
		Name:     "aggregated-api",
		CertFile: dir + "/tls.crt",
		KeyFile:  dir + "/tls.key",
		DNSNames: []string{"platform-podplane-operator-aggregated-api", "platform-podplane-operator-aggregated-api.platform-podplane-operator.svc.cluster.local"},
	}
	now := time.Now()
	if err := ensureServingCertificate(cfg, &signingPair{key: caKey, cert: root}, now); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseServingKeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cert.DNSNames, cfg.DNSNames) || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || cert.CheckSignatureFrom(root) != nil {
		t.Fatalf("unexpected serving certificate: %+v", cert)
	}
	if cert.NotAfter.Sub(cert.NotBefore) > maxLifetime {
		t.Fatalf("serving lifetime = %s", cert.NotAfter.Sub(cert.NotBefore))
	}
	if err := ensureServingCertificate(cfg, &signingPair{key: caKey, cert: root}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := os.ReadFile(cfg.CertFile)
	if !slices.Equal(certPEM, unchanged) {
		t.Fatal("current serving certificate was replaced")
	}
	if err := ensureServingCertificate(cfg, &signingPair{key: caKey, cert: root}, cert.NotAfter.Add(-servingRefreshBefore+time.Second)); err != nil {
		t.Fatal(err)
	}
	rotated, _ := os.ReadFile(cfg.CertFile)
	if slices.Equal(certPEM, rotated) {
		t.Fatal("serving certificate did not rotate before expiry")
	}
	rotatedKey, _ := os.ReadFile(cfg.KeyFile)
	if !slices.Equal(keyPEM, rotatedKey) {
		t.Fatal("serving private key changed during certificate renewal")
	}
	info, err := os.Stat(cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("serving key mode = %o", info.Mode().Perm())
	}
}

// TestWriteServingPairPublishesCompleteGenerations verifies stable public paths and bounded retention.
func TestWriteServingPairPublishesCompleteGenerations(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	current := filepath.Join(dir, ".serving-"+servingPairID(certFile, keyFile)+"-current")
	if err := writeServingPair(certFile, []byte("certificate one"), keyFile, []byte("private key")); err != nil {
		t.Fatal(err)
	}
	first, err := os.Readlink(current)
	if err != nil {
		t.Fatal(err)
	}
	for path, name := range map[string]string{certFile: "tls.crt", keyFile: "tls.key"} {
		link, err := os.Readlink(path)
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(filepath.Base(current), name); link != want {
			t.Fatalf("%s link = %q, want %q", name, link, want)
		}
	}
	if err := writeServingPair(certFile, []byte("certificate two"), keyFile, []byte("private key")); err != nil {
		t.Fatal(err)
	}
	second, err := os.Readlink(current)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("serving generation did not change")
	}
	if got, _ := os.ReadFile(certFile); string(got) != "certificate two" {
		t.Fatalf("certificate = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, first)); err != nil {
		t.Fatalf("previous generation was not retained: %v", err)
	}
	if err := writeServingPair(certFile, []byte("certificate three"), keyFile, []byte("private key")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, first)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale generation still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, second)); err != nil {
		t.Fatalf("previous generation was not retained: %v", err)
	}
}

// parseLeaf decodes the first certificate in an issued test chain.
func parseLeaf(t *testing.T, s string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		t.Fatal("missing PEM")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
