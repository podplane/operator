// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsbackend

import "fmt"

// Registry resolves configured backends by provider name.
type Registry struct{ backends map[string]Backend }

// NewRegistry validates and indexes backends by provider name.
func NewRegistry(backends ...Backend) (*Registry, error) {
	r := &Registry{backends: map[string]Backend{}}
	for _, b := range backends {
		if b == nil {
			continue
		}
		if err := ValidateProviderName(b.ProviderName()); err != nil {
			return nil, err
		}
		if _, ok := r.backends[b.ProviderName()]; ok {
			return nil, fmt.Errorf("duplicate backend provider %q", b.ProviderName())
		}
		r.backends[b.ProviderName()] = b
	}
	return r, nil
}

// Backend returns the backend for a provider name.
func (r *Registry) Backend(name string) (Backend, error) {
	b, ok := r.backends[name]
	if !ok {
		return nil, fmt.Errorf("unknown secrets provider %q", name)
	}
	return b, nil
}

// Backends returns a copy of the registry map.
func (r *Registry) Backends() map[string]Backend {
	out := make(map[string]Backend, len(r.backends))
	for k, v := range r.backends {
		out[k] = v
	}
	return out
}
