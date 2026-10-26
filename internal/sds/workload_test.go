// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package sds

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const serviceHostname = "agent-router.podplane.svc"

// TestRunWorkloadProjectedRotation exercises the public Run and SDS interfaces
// with the same stable-file -> ..data -> generation layout as projected volumes.
func TestRunWorkloadProjectedRotation(t *testing.T) {
	directory := t.TempDir()
	const name = "agent-router.pem"
	if err := os.Symlink(filepath.Join("..data", name), filepath.Join(directory, name)); err != nil {
		t.Fatal(err)
	}
	generation := 0
	project := func(bundle []byte) {
		t.Helper()
		generation++
		nameDir := fmt.Sprintf("..generation-%d", generation)
		path := filepath.Join(directory, nameDir)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if bundle != nil {
			if err := os.WriteFile(filepath.Join(path, name), bundle, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(nameDir, filepath.Join(directory, "..data_tmp")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(directory, "..data_tmp"), filepath.Join(directory, "..data")); err != nil {
			t.Fatal(err)
		}
	}
	first := workloadBundle(t, nil)
	project(first)
	// A second resource proves repeatable mappings work without requiring ingress SANs.
	if err := os.WriteFile(filepath.Join(directory, "second"), first, 0o600); err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp("/tmp", "sds-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "sds.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, []string{"--socket=" + socket, "--certificates-dir=" + directory,
			"--poll-interval=5ms", "--workload-certificate=" + name + "=" + serviceHostname,
			"--workload-certificate=second=" + serviceHostname})
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
	subscribe := func(ctx context.Context, resource string) secretv3.SecretDiscoveryService_StreamSecretsClient {
		t.Helper()
		stream, err := client.StreamSecrets(ctx, grpc.WaitForReady(true))
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: resourcev3.SecretType, ResourceNames: []string{resource}}); err != nil {
			t.Fatal(err)
		}
		return stream
	}
	receive := func(stream secretv3.SecretDiscoveryService_StreamSecretsClient, resource string, bundle []byte) {
		t.Helper()
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
		key, chain := pem.Decode(bundle) // projected bundle is private key first
		cert := secret.GetTlsCertificate()
		if secret.Name != resource || !bytes.Equal(cert.GetCertificateChain().GetInlineBytes(), chain) ||
			!bytes.Equal(cert.GetPrivateKey().GetInlineBytes(), pem.EncodeToMemory(key)) {
			t.Fatal("SDS did not return the expected resource, complete chain, and private key")
		}
		pair, err := tls.X509KeyPair(cert.GetCertificateChain().GetInlineBytes(), cert.GetPrivateKey().GetInlineBytes())
		if err != nil {
			t.Fatalf("returned keypair: %v", err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := leaf.VerifyHostname(serviceHostname); err != nil {
			t.Fatal(err)
		}
		if leaf.IsCA || len(pair.Certificate) != 2 {
			t.Fatal("expected non-CA leaf and issuer chain")
		}
		if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: resourcev3.SecretType, ResourceNames: []string{resource}, VersionInfo: response.VersionInfo, ResponseNonce: response.Nonce}); err != nil {
			t.Fatal(err)
		}
	}
	stream := subscribe(ctx, name)
	receive(stream, name, first)
	secondCtx, secondCancel := context.WithCancel(ctx)
	receive(subscribe(secondCtx, "second"), "second", first)
	secondCancel()
	rotated := workloadBundle(t, nil)
	project(rotated)
	receive(stream, name, rotated)

	for _, invalid := range [][]byte{
		[]byte("not PEM"),
		workloadBundle(t, func(c *x509.Certificate) { c.DNSNames = []string{"other.podplane.svc"} }),
		nil, // dangling projection during replacement
	} {
		project(invalid)
		// Observe the retained generation across multiple polling intervals using
		// fresh SDS streams (rather than inspecting the implementation's cache).
		for range 3 {
			time.Sleep(15 * time.Millisecond)
			probeCtx, probeCancel := context.WithCancel(ctx)
			receive(subscribe(probeCtx, name), name, rotated)
			probeCancel()
		}
	}
	recovered := workloadBundle(t, nil)
	project(recovered)
	// This also catches any invalid generation queued on the original stream.
	receive(stream, name, recovered)
	unknown := subscribe(ctx, "unconfigured")
	if _, err := unknown.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown resource error = %v, want PermissionDenied", err)
	}
}

// TestRunRejectsInvalidWorkloadBundles checks startup validation without binding a socket.
func TestRunRejectsInvalidWorkloadBundles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
		want   string
	}{
		{"wrong hostname", func(c *x509.Certificate) { c.DNSNames = []string{"other.podplane.svc"} }, "validate service hostname"},
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Second) }, "not currently valid"},
		{"future", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) }, "not currently valid"},
		{"client only", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, "does not permit server authentication"},
		{"no EKU", func(c *x509.Certificate) { c.ExtKeyUsage = nil }, "does not permit server authentication"},
		{"CA leaf", func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true }, "must not be a CA"},
		{"malformed", nil, "invalid PEM data"},
		{"mismatched key", nil, "validate keypair"},
		{"invalid chain", nil, "validate certificate chain"},
		{"duplicate key", nil, "exactly one private key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			bundle := workloadBundle(t, tc.mutate)
			switch tc.name {
			case "malformed":
				bundle = []byte("not PEM")
			case "mismatched key":
				_, chain := pem.Decode(bundle)
				otherKey, _ := pem.Decode(workloadBundle(t, nil))
				bundle = append(pem.EncodeToMemory(otherKey), chain...)
			case "invalid chain":
				otherCert, _ := pem.Decode(nodeBundle(t, nil))
				bundle = append(bundle, pem.EncodeToMemory(otherCert)...)
			case "duplicate key":
				key, _ := pem.Decode(bundle)
				bundle = append(bundle, pem.EncodeToMemory(key)...)
			}
			writeBundle(t, directory, "workload", bundle)
			err := Run(context.Background(), []string{"--certificates-dir=" + directory, "--workload-certificate=workload=" + serviceHostname})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Run error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunWorkloadFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--workload-certificate=workload="},
		{"--workload-certificate=workload=*.podplane.svc"},
		{"--workload-certificate=workload=127.0.0.1"},
		{"--workload-certificate=workload=bad name"},
		{"--workload-certificate=../workload=" + serviceHostname},
		{"--workload-certificate=..=" + serviceHostname},
		{"--workload-certificate=node=" + serviceHostname},
		{"--workload-certificate=workload=" + serviceHostname, "--workload-certificate=workload=" + serviceHostname},
		{"--workload-certificate=workload=" + serviceHostname, "--domain-certificate=ingress=example.com"},
		{"--workload-certificate=workload=" + serviceHostname, "--node-certificate=example.com"},
	} {
		err := Run(context.Background(), args)
		if err == nil || strings.Contains(err.Error(), "load initial SDS resources") {
			t.Errorf("Run(%v) error = %v, want flag validation failure", args, err)
		}
	}
}

// workloadBundle returns a key-first projected credential with a service-only
// leaf and its signing CA, deliberately containing no ingress wildcard SAN.
func workloadBundle(t *testing.T, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	caBundle := nodeBundle(t, func(c *x509.Certificate) {
		c.IsCA = true
		c.BasicConstraintsValid = true
		c.KeyUsage = x509.KeyUsageCertSign
	})
	ca, caKey := pem.Decode(caBundle)
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(ca), caKey)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := x509.ParseCertificate(ca.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leafBundle := nodeBundle(t, func(c *x509.Certificate) {
		c.DNSNames = []string{serviceHostname}
		c.IPAddresses = nil
		if mutate != nil {
			mutate(c)
		}
	})
	leaf, key := pem.Decode(leafBundle)
	leafPair, err := tls.X509KeyPair(pem.EncodeToMemory(leaf), key)
	if err != nil {
		t.Fatal(err)
	}
	template, err := x509.ParseCertificate(leaf.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, leafPair.PrivateKey.(ed25519.PrivateKey).Public(), pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	return append(bundle, pem.EncodeToMemory(ca)...)
}
