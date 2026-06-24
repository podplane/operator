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

// TestLoadParsesKeyRotation verifies key_rotation is read from the config file.
func TestLoadParsesKeyRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"cluster_id":"test-cluster","key_rotation":"12h","providers":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.KeyRotation, "12h"; got != want {
		t.Fatalf("KeyRotation = %q, want %q", got, want)
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
	if err := os.WriteFile(path, []byte(`{"cluster_id":"test-cluster","providers":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.KeyRotation, ""; got != want {
		t.Fatalf("KeyRotation = %q, want %q", got, want)
	}
	rotation, err := cfg.KeyRotationDuration()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rotation, DefaultRotation(); got != want {
		t.Fatalf("KeyRotationDuration() = %v, want %v", got, want)
	}
}
