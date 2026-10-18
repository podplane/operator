// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package sds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
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

	hashes, resources, err := load(directory, certificateFlags{"bundle-example": "example.com"}, nil)
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
	if _, _, err := load(directory, certificateFlags{"bundle-example": "example.net"}, nil); err == nil {
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
	hashes, resources, err := load(directory, flags, nil)
	if err != nil {
		t.Fatalf("load initial bundle: %v", err)
	}
	cache := cachev3.NewLinearCache(resourcev3.SecretType)
	cache.SetResources(resources)
	initialKey := resourceKey(t, cache, name)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go poll(ctx, 5*time.Millisecond, directory, flags, nil, cache, hashes)
	writeBundle(t, directory, name, second)

	waitFor(t, func() bool { return !bytes.Equal(resourceKey(t, cache, name), initialKey) })
}

// TestPollRetainsLastGoodRotation verifies malformed and missing updates do not replace valid resources.
func TestPollRetainsLastGoodRotation(t *testing.T) {
	directory := t.TempDir()
	name := "bundle-example"
	writeBundle(t, directory, name, certificateBundle(t, "example.com", 1))
	flags := certificateFlags{name: "example.com"}
	hashes, resources, err := load(directory, flags, nil)
	if err != nil {
		t.Fatalf("load initial bundle: %v", err)
	}
	cache := cachev3.NewLinearCache(resourcev3.SecretType)
	cache.SetResources(resources)
	initialKey := resourceKey(t, cache, name)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go poll(ctx, 5*time.Millisecond, directory, flags, nil, cache, hashes)

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

// TestPollIsolatesDomainFailures permits healthy rotations while retaining a failing resource.
func TestPollIsolatesDomainFailures(t *testing.T) {
	for _, failure := range []string{"missing", "malformed", "wrong domain"} {
		t.Run(failure, func(t *testing.T) {
			directory := t.TempDir()
			flags := certificateFlags{"one": "example.com", "two": "example.net"}
			writeBundle(t, directory, "one", certificateBundle(t, "example.com", 1))
			writeBundle(t, directory, "two", certificateBundle(t, "example.net", 1))
			hashes, resources, err := load(directory, flags, nil)
			if err != nil {
				t.Fatal(err)
			}
			cache := cachev3.NewLinearCache(resourcev3.SecretType)
			cache.SetResources(resources)
			first, retained := resourceKey(t, cache, "one"), resourceKey(t, cache, "two")
			switch failure {
			case "missing":
				if err := os.Remove(filepath.Join(directory, "two")); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				writeBundle(t, directory, "two", []byte("bad"))
			case "wrong domain":
				writeBundle(t, directory, "two", certificateBundle(t, "example.org", 2))
			}
			// The same mixed generation must still fail closed at startup.
			if _, _, err := load(directory, flags, nil); err == nil {
				t.Fatal("initial load accepted invalid configured resource")
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); poll(ctx, 5*time.Millisecond, directory, flags, nil, cache, hashes) }()
			t.Cleanup(func() { cancel(); <-done })
			writeBundle(t, directory, "one", certificateBundle(t, "example.com", 2))
			waitFor(t, func() bool { return !bytes.Equal(resourceKey(t, cache, "one"), first) })
			if !bytes.Equal(resourceKey(t, cache, "two"), retained) {
				t.Fatal("failed resource was replaced")
			}
			writeBundle(t, directory, "two", certificateBundle(t, "example.net", 3))
			waitFor(t, func() bool { return !bytes.Equal(resourceKey(t, cache, "two"), retained) })
		})
	}
}

// TestRunNodeCertificate serves a multi-domain Ed25519 bundle over the SDS socket.
func TestRunNodeCertificate(t *testing.T) {
	directory := t.TempDir()
	bundle := nodeBundle(t, nil)
	writeBundle(t, directory, "node.pem", bundle)
	// Keep the Unix socket path below platform limits even with long test names.
	socketDir, err := os.MkdirTemp("/tmp", "sds-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "sds.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, []string{"--socket=" + socket, "--certificates-dir=" + directory, "--poll-interval=5ms", "--node-certificate=example.com,example.net"})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := secretv3.NewSecretDiscoveryServiceClient(conn)
	stream, err := client.StreamSecrets(ctx, grpc.WaitForReady(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: resourcev3.SecretType, ResourceNames: []string{"node"}}); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Resources) != 1 {
		t.Fatalf("received %d resources, want one", len(response.Resources))
	}
	var secret tlsv3.Secret
	if err := response.Resources[0].UnmarshalTo(&secret); err != nil {
		t.Fatal(err)
	}
	if secret.Name != "node" {
		t.Fatalf("resource name = %q, want node", secret.Name)
	}
	pair, err := tls.X509KeyPair(secret.GetTlsCertificate().GetCertificateChain().GetInlineBytes(), secret.GetTlsCertificate().GetPrivateKey().GetInlineBytes())
	if err != nil {
		t.Fatalf("SDS keypair: %v", err)
	}
	if _, ok := pair.PrivateKey.(ed25519.PrivateKey); !ok {
		t.Fatal("SDS did not serve an Ed25519 key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"example.com", "*.example.com", "example.net", "*.example.net", "localhost", "node-1"} {
		if !slices.Contains(leaf.DNSNames, name) {
			t.Errorf("SDS certificate missing %q", name)
		}
	}
	if len(leaf.IPAddresses) != 2 {
		t.Fatalf("SDS certificate has %d IP SANs, want two", len(leaf.IPAddresses))
	}
	if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: resourcev3.SecretType, ResourceNames: []string{"node"}, VersionInfo: response.VersionInfo, ResponseNonce: response.Nonce}); err != nil {
		t.Fatal(err)
	}
	replacement := nodeBundle(t, nil)
	writeBundle(t, directory, "replacement.pem", replacement)
	if err := os.Rename(filepath.Join(directory, "replacement.pem"), filepath.Join(directory, "node.pem")); err != nil {
		t.Fatal(err)
	}
	response, err = stream.Recv()
	if err != nil {
		t.Fatalf("receive atomic replacement: %v", err)
	}
	if len(response.Resources) != 1 {
		t.Fatalf("replacement has %d resources, want one", len(response.Resources))
	}
	if err := response.Resources[0].UnmarshalTo(&secret); err != nil {
		t.Fatal(err)
	}
	_, expectedKey := pem.Decode(replacement)
	if secret.Name != "node" || !bytes.Equal(secret.GetTlsCertificate().GetPrivateKey().GetInlineBytes(), expectedKey) {
		t.Fatal("SDS did not publish the replacement node certificate")
	}
	if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: resourcev3.SecretType, ResourceNames: []string{"node.pem"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unconfigured resource error = %v, want PermissionDenied", err)
	}
}

// TestRunRejectsInvalidNodeBundles exercises shared validation through the CLI.
func TestRunRejectsInvalidNodeBundles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
		want   string
	}{
		{"missing apex", func(c *x509.Certificate) { c.DNSNames = slices.Delete(c.DNSNames, 2, 3) }, `missing DNS name "example.net"`},
		{"missing wildcard", func(c *x509.Certificate) { c.DNSNames = slices.Delete(c.DNSNames, 3, 4) }, `missing DNS name "*.example.net"`},
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Second) }, "not currently valid"},
		{"not yet valid", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }, "not currently valid"},
		{"client only", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, "does not permit server authentication"},
		{"malformed", nil, "invalid PEM data"},
		{"mismatched key", nil, "validate keypair"},
		{"invalid chain", nil, "validate certificate chain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			bundle := nodeBundle(t, tc.mutate)
			switch tc.name {
			case "malformed":
				bundle = []byte("not PEM")
			case "mismatched key":
				cert, _ := pem.Decode(bundle)
				_, otherKey := pem.Decode(nodeBundle(t, nil))
				bundle = append(pem.EncodeToMemory(cert), otherKey...)
			case "invalid chain":
				otherCert, _ := pem.Decode(nodeBundle(t, nil))
				bundle = append(bundle, pem.EncodeToMemory(otherCert)...)
			}
			writeBundle(t, directory, "node.pem", bundle)
			err := Run(context.Background(), []string{"--certificates-dir=" + directory, "--node-certificate=example.com,example.net"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Run error = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestRunCertificateModes verifies exclusive flags, required inputs, and unchanged NLB SAN policy.
func TestRunCertificateModes(t *testing.T) {
	directory := t.TempDir()
	writeBundle(t, directory, "nlb", nodeBundle(t, func(c *x509.Certificate) {
		c.DNSNames = []string{"example.com", "*.example.com", "localhost"}
	}))
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--domain-certificate=nlb=example.com", "--node-certificate=example.com"}, "mutually exclusive"},
		{[]string{"--domain-certificate=node=example.com"}, "reserved for the node certificate"},
		{[]string{"--domain-certificate=nlb=example.com"}, "do not match"},
		{[]string{"--node-certificate=example.com"}, "read resource"},
		{[]string{"--node-certificate="}, "comma-separated list of apex domains"},
		{[]string{"--node-certificate=*.example.com"}, "comma-separated list of apex domains"},
		{[]string{"--node-certificate=ingress=example.com"}, "comma-separated list of apex domains"},
		{[]string{"--node-certificate=example.com,"}, "comma-separated list of apex domains"},
		{[]string{"--node-certificate=example.com,*.example.net"}, "comma-separated list of apex domains"},
		{[]string{"--node-certificate=example.com", "--poll-interval=0s"}, "positive poll interval"},
		{nil, "at least one certificate"},
	} {
		err := Run(context.Background(), append([]string{"--certificates-dir=" + directory}, tc.args...))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Run(%v) error = %v, want %q", tc.args, err, tc.want)
		}
	}
}

// nodeBundle creates an Ed25519 fixture with multiple domains and node identity SANs.
func nodeBundle(t *testing.T, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"example.com", "*.example.com", "example.net", "*.example.net", "localhost", "node-1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.0.2.1")},
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
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
