// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package registryauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Validator validates Podplane OIDC ID tokens for Zot registry access.
type Validator struct {
	IssuerURL string
	Audience  string
	Client    *http.Client
	Now       func() time.Time

	mu      sync.Mutex
	jwksURL string
	keys    jwk.Set
}

// Validate checks signature and standard OIDC issuer/audience/time claims.
func (v *Validator) Validate(ctx context.Context, tokenString string) (time.Time, error) {
	keys, err := v.keySet(ctx)
	if err != nil {
		return time.Time{}, err
	}
	clock := jwt.ClockFunc(time.Now)
	if v.Now != nil {
		clock = jwt.ClockFunc(v.Now)
	}
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(keys, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.IssuerURL),
		jwt.WithAudience(v.Audience),
		jwt.WithAcceptableSkew(30*time.Second),
		jwt.WithClock(clock),
		jwt.WithContext(ctx),
	)
	if err != nil {
		return time.Time{}, err
	}
	return token.Expiration(), nil
}

// keySet returns the cached JWKS, loading it from the issuer if needed.
func (v *Validator) keySet(ctx context.Context) (jwk.Set, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.keys != nil {
		return v.keys, nil
	}
	if err := v.refreshLocked(ctx); err != nil {
		return nil, err
	}
	return v.keys, nil
}

// refreshLocked loads OIDC discovery metadata and the current JWKS.
func (v *Validator) refreshLocked(ctx context.Context) error {
	client := v.Client
	if client == nil {
		client = http.DefaultClient
	}
	if v.jwksURL == "" {
		var discovery struct {
			JWKSURI string `json:"jwks_uri"`
		}
		discoveryURL := strings.TrimRight(v.IssuerURL, "/") + "/.well-known/openid-configuration"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s: %s", discoveryURL, resp.Status)
		}
		if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
			return err
		}
		if discovery.JWKSURI == "" {
			return fmt.Errorf("OIDC discovery missing jwks_uri")
		}
		v.jwksURL = discovery.JWKSURI
	}
	keys, err := jwk.Fetch(ctx, v.jwksURL, jwk.WithHTTPClient(client))
	if err != nil {
		return err
	}
	if keys.Len() == 0 {
		return fmt.Errorf("OIDC JWKS contains no keys")
	}
	v.keys = keys
	return nil
}
