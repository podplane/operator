// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsbackend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultDestroyRejectsInvalidKeyBeforeRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer server.Close()

	backend := NewVaultBackend(VaultOptions{Name: "provider", Address: server.URL, Mount: "secret"})
	ks, err := NewKeyspace("cluster", "namespace", "provider.binding")
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Destroy(context.Background(), ks, "../other/key"); err == nil {
		t.Fatal("expected invalid key error")
	}
	if called {
		t.Fatal("vault request was sent for invalid key")
	}
}
