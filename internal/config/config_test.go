// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

// TestLoadDefaultsRegistryAuthAudience verifies registry auth uses cluster OIDC client_id as audience.
func TestLoadDefaultsRegistryAuthAudience(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"cluster":{"id":"test-cluster","oidc":{"issuer_url":"https://issuer.example"}},"secrets":{"providers":{}},"registry":{"auth":{"enabled":true}}}`), 0o644); err != nil {
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

// TestLoadRequiresRegistryAuthIssuer verifies enabled registry auth validates its issuer config.
func TestLoadRequiresRegistryAuthIssuer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"cluster":{"id":"test-cluster"},"secrets":{"providers":{}},"registry":{"auth":{"enabled":true}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load succeeded, want missing issuer error")
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
