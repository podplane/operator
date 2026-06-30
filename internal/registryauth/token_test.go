// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package registryauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TestTokenEndpointReturnsSameBearerToken verifies successful Docker token exchange.
func TestTokenEndpointReturnsSameBearerToken(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
	token := "podplane-id-token"
	server := &Server{Validator: validatorFunc(func(context.Context, string) (time.Time, error) { return expiresAt, nil })}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "scope": {"repository:apps/example:push,pull"}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	if got, want := w.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, w.Body.String())
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Token != token || body.AccessToken != token {
		t.Fatalf("returned token/access_token = %q/%q, want original token", body.Token, body.AccessToken)
	}
	if body.ExpiresIn <= 0 {
		t.Fatalf("expires_in = %d, want positive", body.ExpiresIn)
	}
}

// TestTokenEndpointRejectsInvalidToken verifies invalid refresh tokens are rejected safely.
func TestTokenEndpointRejectsInvalidToken(t *testing.T) {
	server := &Server{Validator: validatorFunc(func(context.Context, string) (time.Time, error) { return time.Time{}, fmt.Errorf("invalid") })}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"bad-token"}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	if got, want := w.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if strings.Contains(w.Body.String(), "bad-token") {
		t.Fatalf("error response leaked token: %s", w.Body.String())
	}
}

// TestValidatorValidatesOIDCIDToken verifies OIDC ID token signature and claims validation.
func TestValidatorValidatesOIDCIDToken(t *testing.T) {
	now := time.Unix(1000, 0)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": "http://" + r.Host + "/keys"})
		case "/keys":
			_ = json.NewEncoder(w).Encode(rsaJWKS(t, "test-key", &key.PublicKey))
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()
	token := signedRS256(t, key, "test-key", issuer.URL, []string{"podplane-cluster"}, now.Add(time.Hour))
	validator := &Validator{IssuerURL: issuer.URL, Audience: "podplane-cluster", Now: func() time.Time { return now }}

	expiresAt, err := validator.Validate(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := expiresAt, now.Add(time.Hour); !got.Equal(want) {
		t.Fatalf("expiresAt = %v, want %v", got, want)
	}
}

// TestValidatorRejectsWrongAudience verifies audience mismatches fail validation.
func TestValidatorRejectsWrongAudience(t *testing.T) {
	now := time.Unix(1000, 0)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": "http://" + r.Host + "/keys"})
		case "/keys":
			_ = json.NewEncoder(w).Encode(rsaJWKS(t, "test-key", &key.PublicKey))
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()
	token := signedRS256(t, key, "test-key", issuer.URL, []string{"other"}, now.Add(time.Hour))
	validator := &Validator{IssuerURL: issuer.URL, Audience: "podplane-cluster", Now: func() time.Time { return now }}

	if _, err := validator.Validate(context.Background(), token); err == nil {
		t.Fatal("Validate succeeded, want audience error")
	}
}

type validatorFunc func(context.Context, string) (time.Time, error)

// Validate adapts a function into a TokenValidator for tests.
func (f validatorFunc) Validate(ctx context.Context, token string) (time.Time, error) {
	return f(ctx, token)
}

// signedRS256 returns a compact RS256 JWT signed with key.
func signedRS256(t *testing.T, key *rsa.PrivateKey, kid, issuer string, audience []string, expiresAt time.Time) string {
	t.Helper()
	token, err := jwt.NewBuilder().Issuer(issuer).Audience(audience).Expiration(expiresAt).Build()
	if err != nil {
		t.Fatal(err)
	}
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// rsaJWKS returns a JWKS containing the public RSA key.
func rsaJWKS(t *testing.T, kid string, key *rsa.PublicKey) jwk.Set {
	t.Helper()
	publicKey, err := jwk.PublicKeyOf(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := publicKey.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	keys := jwk.NewSet()
	if err := keys.AddKey(publicKey); err != nil {
		t.Fatal(err)
	}
	return keys
}
