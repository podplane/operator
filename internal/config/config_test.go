// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/podplane/operator/internal/workloadpki"
)

// TestLoadParsesKeyRotation verifies secrets.key_rotation is read from the config file.
func TestLoadParsesKeyRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"cluster":{"id":"test-cluster"},"secrets":{"key_rotation":"12h","providers":{}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.Secrets.KeyRotation, "12h"; got != want {
		t.Fatalf("Secrets.KeyRotation = %q, want %q", got, want)
	}
	rotation, err := cfg.KeyRotationDuration()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rotation, 12*time.Hour; got != want {
		t.Fatalf("KeyRotationDuration() = %v, want %v", got, want)
	}
}

// TestLoadDefaultsKeyRotation verifies key_rotation remains optional.
func TestLoadDefaultsKeyRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"cluster":{"id":"test-cluster"},"secrets":{"providers":{}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.Secrets.KeyRotation, ""; got != want {
		t.Fatalf("Secrets.KeyRotation = %q, want %q", got, want)
	}
	rotation, err := cfg.KeyRotationDuration()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rotation, DefaultRotation(); got != want {
		t.Fatalf("KeyRotationDuration() = %v, want %v", got, want)
	}
}

// TestLoadDefaultsOIDCClientID verifies the OIDC client ID defaults to the cluster ID.
func TestLoadDefaultsOIDCClientID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"cluster":{"id":"test-cluster","oidc":{"issuer_url":"https://issuer.example"}},"secrets":{"providers":{}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.Cluster.OIDC.ClientID, "test-cluster"; got != want {
		t.Fatalf("Cluster.OIDC.ClientID = %q, want %q", got, want)
	}
}

// TestLoadRequiresClusterIDForSecretsProviders verifies the secrets module has
// a cluster identity for backend path prefixes.
func TestLoadRequiresClusterIDForSecretsProviders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"cluster":{},"secrets":{"providers":{"openbao":{"kind":"openbao"}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load succeeded, want missing cluster.id error")
	}
}

// TestLoadIngressCertificates decodes operator-managed ingress state.
func TestLoadIngressCertificates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	contents := `{
		"cluster":{"id":"test-cluster"},
		"secrets":{"default_provider":"aws","providers":{"aws":{"kind":"aws","object_type":"secretsmanager"}}},
		"ingress_certificates":{
			"acme":{"server":"https://acme.example/directory","email":"ops@example.com"},
			"domains":{"example.com":{"dns_provider":{"kind":"aws-route53","region":"us-east-1","hosted_zone_id":"Z123","role_arn":"arn:aws:iam::123:role/acme"}}}
		}
	}`
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.IngressCertificates.Provider, "aws"; got != want {
		t.Fatalf("IngressCertificates.Provider = %q, want %q", got, want)
	}
	if got, want := cfg.IngressCertificates.KeyPrefix, "test-cluster"; got != want {
		t.Fatalf("IngressCertificates.KeyPrefix = %q, want %q", got, want)
	}
	provider := cfg.IngressCertificates.Domains["example.com"].Provider
	if provider == nil || provider.RoleARN != "arn:aws:iam::123:role/acme" {
		t.Fatalf("DNS provider = %#v", provider)
	}
}

// TestLoadIngressCertificatesRequiresStorageProvider rejects state without a backend.
func TestLoadIngressCertificatesRequiresStorageProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	contents := `{"cluster":{"id":"test-cluster"},"secrets":{"providers":{}},"ingress_certificates":{"domains":{"example.com":{}}}}`
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load succeeded, want missing storage provider error")
	}
}

// TestLoadTrustBundleSync verifies destination decoding and rejects invalid configuration.
func TestLoadTrustBundleSync(t *testing.T) {
	secret := workloadpki.TrustBundleSyncTarget{Kind: "Secret", Namespace: "platform-router", Name: "workload-ca", Key: "tls.crt"}
	configMap := workloadpki.TrustBundleSyncTarget{Kind: "ConfigMap", Namespace: "tenant-a", Name: "trust.roots", Key: "ca.crt"}
	on, off := true, false
	createSecret, precreatedMap := secret, configMap
	createSecret.CreateIfMissing = &on
	precreatedMap.CreateIfMissing = &off
	for _, tc := range []struct {
		name            string
		domain          string
		targets         []workloadpki.TrustBundleSyncTarget
		createIfMissing bool
		wantErr         string
	}{
		{name: "disabled by default"},
		{name: "both kinds", domain: "cluster.example", targets: []workloadpki.TrustBundleSyncTarget{secret, configMap}},
		{name: "creation overrides", domain: "cluster.example", targets: []workloadpki.TrustBundleSyncTarget{createSecret, precreatedMap}, createIfMissing: true},
		{name: "requires signer", targets: []workloadpki.TrustBundleSyncTarget{secret}, wantErr: "trust_domain"},
		{name: "duplicates", domain: "cluster.example", targets: []workloadpki.TrustBundleSyncTarget{secret, secret}, wantErr: "duplicate"},
		{name: "duplicates with different creation policy", domain: "cluster.example", targets: []workloadpki.TrustBundleSyncTarget{secret, createSecret}, wantErr: "duplicate"},
		{name: "unknown kind", domain: "cluster.example", targets: []workloadpki.TrustBundleSyncTarget{{Kind: "secret", Namespace: "ns", Name: "ca", Key: "ca.crt"}}, wantErr: "kind"},
		{name: "missing namespace", domain: "cluster.example", targets: []workloadpki.TrustBundleSyncTarget{{Kind: "Secret", Name: "ca", Key: "ca.crt"}}, wantErr: "namespace"},
		{name: "invalid name", domain: "cluster.example", targets: []workloadpki.TrustBundleSyncTarget{{Kind: "ConfigMap", Namespace: "ns", Name: "bad/name", Key: "ca.crt"}}, wantErr: "name"},
		{name: "missing key", domain: "cluster.example", targets: []workloadpki.TrustBundleSyncTarget{{Kind: "Secret", Namespace: "ns", Name: "ca"}}, wantErr: "key"},
		{name: "invalid key", domain: "cluster.example", targets: []workloadpki.TrustBundleSyncTarget{{Kind: "Secret", Namespace: "ns", Name: "ca", Key: "../ca"}}, wantErr: "key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contents, err := json.Marshal(map[string]any{
				"cluster":      map[string]any{"spiffe": map[string]string{"trust_domain": tc.domain}},
				"certificates": map[string]any{"trust_bundle_sync": map[string]any{"create_if_missing": tc.createIfMissing, "resources": tc.targets}},
			})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Certificates.TrustBundleSync.CreateIfMissing != tc.createIfMissing || !reflect.DeepEqual(cfg.Certificates.TrustBundleSync.Resources, tc.targets) {
				t.Fatalf("destinations = %+v, want %+v", cfg.Certificates.TrustBundleSync, tc.targets)
			}
		})
	}
}
