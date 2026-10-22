// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsbackend

import (
	"context"
	"testing"
)

// writeTestValues supplies text and binary inputs with their expected text-storage representations.
func writeTestValues() []struct {
	value  []byte
	binary bool
	stored string
} {
	return []struct {
		value  []byte
		binary bool
		stored string
	}{
		{[]byte(" \t雪🙂e\u0301\r\nsecond line\n"), false, " \t雪🙂e\u0301\r\nsecond line\n"},
		{[]byte("c2VjcmV0Cg=="), false, "c2VjcmV0Cg=="},
		{[]byte("c2VjcmV0Cg=="), true, "YzJWamNtVjBDZz09"},
		{[]byte{0xff, 0, 0xc3}, true, "/wDD"},
		{[]byte{0xff}, true, "/w=="},
	}
}

// TestBackendWritesRejectInvalidUTF8BeforeRequests verifies all adapters enforce
// the text contract without disclosing rejected values or contacting providers.
func TestBackendWritesRejectInvalidUTF8BeforeRequests(t *testing.T) {
	// Nil clients ensure rejection happens before even a provider read request.
	for name, backend := range map[string]Backend{
		"secrets-manager": &AWSSecretsManagerBackend{},
		"parameter-store": &AWSParameterStoreBackend{},
		"gcp":             &GCPSecretManagerBackend{},
		"vault":           &VaultBackend{},
	} {
		t.Run(name, func(t *testing.T) {
			ks := Keyspace{Prefix: "cluster", Namespace: "ns", BindingName: "binding"}
			for _, write := range []func(context.Context, Keyspace, string, []byte, bool) (Entry, error){backend.Create, backend.Update} {
				for _, invalid := range [][]byte{[]byte("private-plaintext\xff"), {0xc3}, {0xed, 0xa0, 0x80}} {
					if _, err := write(context.Background(), ks, "key", invalid, false); err == nil || err.Error() != "secret value must be valid UTF-8" {
						t.Fatalf("expected non-disclosing UTF-8 error, got %v", err)
					}
				}
			}
		})
	}
}
