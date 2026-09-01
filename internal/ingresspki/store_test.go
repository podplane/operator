// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package ingresspki

import (
	"context"
	"testing"

	"github.com/podplane/operator/internal/secretsbackend"
)

// TestBackendStoreCreatesAndReplacesValues verifies backend store creates and replaces values.
func TestBackendStoreCreatesAndReplacesValues(t *testing.T) {
	ctx := context.Background()
	backend := secretsbackend.NewMemoryBackend("memory", "memory")
	store, err := NewBackendStore(backend, "cluster")
	if err != nil {
		t.Fatal(err)
	}

	for _, value := range []string{"first", "second"} {
		if err := store.Save(ctx, "bundle-example", []byte(value)); err != nil {
			t.Fatal(err)
		}
		got, err := store.Load(ctx, "bundle-example")
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != value {
			t.Fatalf("Load() = %q, want %q", got, value)
		}
	}
}
