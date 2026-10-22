// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"strings"
	"testing"

	secretsv1beta1 "github.com/podplane/operator/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

// TestRendererBinaryMounts verifies per-item decoding and binary support against
// the resolved provider, including explicit overrides of the cluster default.
func TestRendererBinaryMounts(t *testing.T) {
	for _, provider := range []ProviderConfig{
		{Name: "aws-default", Kind: "aws"},
		{Name: "aws-secrets", Kind: "aws", ObjectType: "secretsmanager"},
		{Name: "aws-ssm", Kind: "aws", ObjectType: "ssmparameter"},
		{Name: "google", Kind: "gcp", ProjectID: "project"},
		{Name: "vault", Kind: "vault"},
		{Name: "openbao", Kind: "openbao"},
	} {
		for _, selection := range []string{"default", "explicit"} {
			t.Run(provider.Name+"/"+selection, func(t *testing.T) {
				r := Renderer{ClusterID: "cluster", DefaultProvider: provider.Name, Providers: map[string]ProviderConfig{
					provider.Name: provider,
					"other":       {Name: "other", Kind: "aws", ObjectType: "ssmparameter"},
				}}
				binding := &secretsv1beta1.SecretProviderBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team"},
					Spec: secretsv1beta1.SecretProviderBindingSpec{Items: []secretsv1beta1.SecretProviderBindingItem{
						{Key: "text"},
						{Key: "key", Path: "keys/signing"},
					}},
				}
				supportsDecoding := provider.Kind == "vault" || provider.Kind == "openbao"
				if selection == "explicit" {
					binding.Spec.ProviderName = provider.Name
					r.DefaultProvider = "other"
					if !supportsDecoding {
						r.Providers["other"] = ProviderConfig{Name: "other", Kind: "vault"}
					}
				}
				for _, binary := range []*bool{nil, ptr(true), ptr(false)} {
					binding.Spec.Items[1].Binary = binary
					spc, status, err := r.Render(binding)
					if binary != nil && !supportsDecoding {
						if err == nil || !strings.Contains(err.Error(), "binary may only be set for Vault/OpenBao") || !strings.Contains(err.Error(), provider.Name) {
							t.Fatalf("expected provider-specific binary mount error, got %v", err)
						}
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					if status.Provider.Name != provider.Name {
						t.Fatalf("resolved provider = %q, want %q", status.Provider.Name, provider.Name)
					}
					field := "objects"
					if provider.Kind == "gcp" {
						field = "secrets"
					}
					encoded, found, err := unstructured.NestedString(spc.Object, "spec", "parameters", field)
					if err != nil || !found {
						t.Fatalf("missing %s: %v", field, err)
					}
					var objects []map[string]string
					if err := yaml.Unmarshal([]byte(encoded), &objects); err != nil {
						t.Fatal(err)
					}
					if len(objects) != 2 {
						t.Fatalf("got %d objects, want 2", len(objects))
					}
					for i, object := range objects {
						wantEncoding := ""
						if i == 1 && binary != nil && *binary {
							wantEncoding = "base64"
							if object["secretKey"] != "value" || object["objectName"] != "keys/signing" {
								t.Fatalf("incorrect binary object mapping: %v", object)
							}
						}
						encoding, present := object["encoding"]
						if encoding != wantEncoding || present != (wantEncoding != "") {
							t.Fatalf("object %d: encoding = %q (present=%t), want %q", i, encoding, present, wantEncoding)
						}
					}
				}
			})
		}
	}
}
