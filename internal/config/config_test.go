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
