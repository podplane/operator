// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package ingresspki

import (
	"context"
	"errors"
	"fmt"

	"github.com/podplane/operator/internal/secretsbackend"
)

const (
	stateNamespace = "platform-cluster"
	stateBinding   = "ingress-certificates"
)

// Store atomically loads and replaces complete operator-owned values.
type Store interface {
	Load(ctx context.Context, key string) ([]byte, error)
	Save(ctx context.Context, key string, value []byte) error
}

// backendStore adapts a Podplane Secrets backend to operator-owned state.
type backendStore struct {
	backend  secretsbackend.Backend
	reader   secretsbackend.ValueReader
	keyspace secretsbackend.Keyspace
}

// NewBackendStore stores certificate state in a configured Podplane Secrets backend.
func NewBackendStore(backend secretsbackend.Backend, prefix string) (Store, error) {
	reader, ok := backend.(secretsbackend.ValueReader)
	if !ok {
		return nil, fmt.Errorf("secrets provider %q cannot read operator-owned state", backend.ProviderName())
	}
	keyspace := secretsbackend.Keyspace{
		ProviderName: backend.ProviderName(),
		Namespace:    stateNamespace,
		BindingName:  stateBinding,
		Prefix:       prefix,
	}
	if _, err := keyspace.SlashPath("probe"); err != nil {
		return nil, err
	}
	return &backendStore{backend: backend, reader: reader, keyspace: keyspace}, nil
}

// Load reads the backend's current complete value.
func (s *backendStore) Load(ctx context.Context, key string) ([]byte, error) {
	return s.reader.Read(ctx, s.keyspace, key)
}

// Save replaces an existing value or creates it without an upsert race.
func (s *backendStore) Save(ctx context.Context, key string, value []byte) error {
	if _, err := s.backend.Update(ctx, s.keyspace, key, value); err == nil {
		return nil
	} else if !errors.Is(err, secretsbackend.ErrNotFound) {
		return err
	}
	if _, err := s.backend.Create(ctx, s.keyspace, key, value); err == nil {
		return nil
	} else if !errors.Is(err, secretsbackend.ErrAlreadyExists) {
		return err
	}
	_, err := s.backend.Update(ctx, s.keyspace, key, value)
	return err
}
