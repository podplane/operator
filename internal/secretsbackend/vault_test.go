// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsbackend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestVaultDestroyRejectsInvalidKeyBeforeRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer server.Close()

	backend, err := NewVaultBackend(VaultOptions{Name: "provider", Address: server.URL, Mount: "secret"})
	if err != nil {
		t.Fatal(err)
	}
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

func TestVaultBackendLogsInWithServiceAccount(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("service-account-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTokenPath := serviceAccountTokenPath
	serviceAccountTokenPath = tokenPath
	t.Cleanup(func() { serviceAccountTokenPath = oldTokenPath })

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/v1/auth/podplane/login" {
			t.Fatalf("login path = %s, want /v1/auth/podplane/login", r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if got, want := body["role"], "operator-role"; got != want {
			t.Fatalf("role = %q, want %q", got, want)
		}
		if got, want := body["jwt"], "service-account-jwt"; got != want {
			t.Fatalf("jwt = %q, want %q", got, want)
		}
		_, _ = w.Write([]byte("{\"auth\":{\"client_token\":\"vault-token\",\"lease_duration\":3600}}"))
	}))
	defer server.Close()

	backend, err := NewVaultBackend(VaultOptions{Name: "provider", Address: server.URL, AuthPath: "auth/podplane", OperatorRole: "operator-role"})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		token, err := backend.requestToken(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got, want := token, "vault-token"; got != want {
			t.Fatalf("token = %q, want %q", got, want)
		}
	}
	if got, want := requests, 1; got != want {
		t.Fatalf("requests = %d, want %d", got, want)
	}
}
