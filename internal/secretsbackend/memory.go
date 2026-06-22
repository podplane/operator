// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsbackend

import (
	"context"
	"sort"
	"sync"
)

// MemoryBackend stores keys in memory for local development and tests.
type MemoryBackend struct {
	name, kind string
	mu         sync.Mutex
	values     map[string]memEntry
}
type memEntry struct {
	value       []byte
	archived    bool
	backendPath string
}

// NewMemoryBackend creates an empty in-memory backend.
func NewMemoryBackend(name, kind string) *MemoryBackend {
	return &MemoryBackend{name: name, kind: kind, values: map[string]memEntry{}}
}

// ProviderName returns the configured provider name.
func (m *MemoryBackend) ProviderName() string { return m.name }

// ProviderKind returns the configured provider kind.
func (m *MemoryBackend) ProviderKind() string { return m.kind }

// key returns the internal map key and backend path.
func (m *MemoryBackend) key(ks Keyspace, k string) (string, string, error) {
	p, err := ks.SlashPath(k)
	return ks.ProviderName + ":" + p, p, err
}

// Create stores a new in-memory key.
func (m *MemoryBackend) Create(_ context.Context, ks Keyspace, key string, value []byte) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, p, err := m.key(ks, key)
	if err != nil {
		return Entry{}, err
	}
	if e, ok := m.values[id]; ok {
		if e.archived {
			return Entry{}, ArchivedError(key)
		}
		return Entry{}, ErrAlreadyExists
	}
	m.values[id] = memEntry{value: append([]byte(nil), value...), backendPath: p}
	return Entry{Key: key, Status: StatusActive, BackendPath: p}, nil
}

// Update overwrites an active in-memory key.
func (m *MemoryBackend) Update(_ context.Context, ks Keyspace, key string, value []byte) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, p, err := m.key(ks, key)
	if err != nil {
		return Entry{}, err
	}
	e, ok := m.values[id]
	if !ok {
		return Entry{}, ErrNotFound
	}
	if e.archived {
		return Entry{}, ArchivedError(key)
	}
	e.value = append([]byte(nil), value...)
	e.backendPath = p
	m.values[id] = e
	return Entry{Key: key, Status: StatusActive, BackendPath: p}, nil
}

// List lists in-memory keys in a keyspace.
func (m *MemoryBackend) List(_ context.Context, ks Keyspace) ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := ks.ProviderName + ":" + "/" + ks.Prefix + "/" + ks.Namespace + "/" + ks.BindingName + "/"
	out := []Entry{}
	for id, e := range m.values {
		if len(id) >= len(prefix) && id[:len(prefix)] == prefix {
			key := id[len(prefix):]
			st := StatusActive
			if e.archived {
				st = StatusArchived
			}
			out = append(out, Entry{Key: key, Status: st, BackendPath: e.backendPath})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Archive marks an in-memory key as archived.
func (m *MemoryBackend) Archive(_ context.Context, ks Keyspace, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, _, err := m.key(ks, key)
	if err != nil {
		return err
	}
	e, ok := m.values[id]
	if !ok {
		return ErrNotFound
	}
	e.archived = true
	m.values[id] = e
	return nil
}

// ArchiveAll archives every key in a keyspace.
func (m *MemoryBackend) ArchiveAll(ctx context.Context, ks Keyspace) error {
	entries, err := m.List(ctx, ks)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := m.Archive(ctx, ks, e.Key); err != nil {
			return err
		}
	}
	return nil
}

// Restore marks an archived in-memory key as active.
func (m *MemoryBackend) Restore(_ context.Context, ks Keyspace, key string) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, p, err := m.key(ks, key)
	if err != nil {
		return Entry{}, err
	}
	e, ok := m.values[id]
	if !ok {
		return Entry{}, ErrNotFound
	}
	e.archived = false
	m.values[id] = e
	return Entry{Key: key, Status: StatusActive, BackendPath: p}, nil
}

// Destroy deletes an in-memory key.
func (m *MemoryBackend) Destroy(_ context.Context, ks Keyspace, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, _, err := m.key(ks, key)
	if err != nil {
		return err
	}
	delete(m.values, id)
	return nil
}

// DestroyAll deletes every key in a keyspace.
func (m *MemoryBackend) DestroyAll(ctx context.Context, ks Keyspace) error {
	entries, err := m.List(ctx, ks)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := m.Destroy(ctx, ks, e.Key); err != nil {
			return err
		}
	}
	return nil
}
