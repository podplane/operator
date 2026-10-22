// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsbackend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// TestAWSWritesPreservePlaintext verifies text is unchanged and binary uses
// SecretBinary in Secrets Manager or base64 text in Parameter Store.
func TestAWSWritesPreservePlaintext(t *testing.T) {
	for _, provider := range []string{"secrets-manager", "parameter-store"} {
		for _, operation := range []string{"create", "update"} {
			t.Run(provider+"/"+operation, func(t *testing.T) {
				for _, tc := range writeTestValues() {
					writes := 0
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/x-amz-json-1.1")
						if r.Header.Get("X-Amz-Target") == "AmazonSSM.GetParameter" {
							_, _ = w.Write([]byte(`{"Parameter":{"Name":"key","Value":"old"}}`))
							return
						}
						var body map[string]any
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Error(err)
						}
						field := "SecretString"
						if tc.binary {
							field = "SecretBinary"
						}
						if provider == "parameter-store" {
							field = "Value"
							if body["Type"] != "SecureString" {
								t.Error("parameter must use SecureString")
							}
						}
						expected := string(tc.value)
						if tc.binary {
							expected = tc.stored
						}
						if body[field] != expected || (tc.binary && body["SecretString"] != nil) || (!tc.binary && body["SecretBinary"] != nil) {
							t.Error("provider payload changed plaintext bytes or used binary encoding")
						}
						writes++
						_, _ = w.Write([]byte(`{}`))
					}))
					cfg := aws.Config{Region: "test", Credentials: aws.AnonymousCredentials{}}
					var backend Backend = &AWSSecretsManagerBackend{client: sm.NewFromConfig(cfg, func(o *sm.Options) { o.BaseEndpoint = aws.String(server.URL) })}
					if provider == "parameter-store" {
						backend = &AWSParameterStoreBackend{client: ssm.NewFromConfig(cfg, func(o *ssm.Options) { o.BaseEndpoint = aws.String(server.URL) })}
					}
					write := backend.Create
					if operation == "update" {
						write = backend.Update
					}
					_, err := write(context.Background(), Keyspace{Prefix: "cluster", Namespace: "ns", BindingName: "binding"}, "key", tc.value, tc.binary)
					server.Close()
					if err != nil {
						t.Fatal(err)
					}
					if writes != 1 {
						t.Fatalf("writes = %d, want 1", writes)
					}
				}
			})
		}
	}
}
