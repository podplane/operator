// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsbackend

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	// StatusActive means the backend key is usable.
	StatusActive = "active"
	// StatusArchived means the backend key is recoverably deleted.
	StatusArchived = "archived"
	// StatusUnknown means the backend listed the key but status lookup failed.
	StatusUnknown = "unknown"
)

var (
	// ErrAlreadyExists reports that an active key already exists.
	ErrAlreadyExists = errors.New("secret key already exists")
	// ErrNotFound reports that a key does not exist.
	ErrNotFound = errors.New("secret key not found")
	// ErrArchived reports that a key exists only as an archived value.
	ErrArchived = errors.New("secret key is archived; restore it, or destroy it before creating a new value")
	// ErrActive reports that a key must be archived before permanent destroy.
	ErrActive = errors.New("secret key is active; archive it before destroy")
	// ErrArchiveUnsupported reports that recoverable delete is unavailable.
	ErrArchiveUnsupported = errors.New("archive delete is not supported by this provider; use destroy instead")
	// ErrRestoreUnsupported reports that restore is unavailable.
	ErrRestoreUnsupported = errors.New("restore is not supported by this provider")
	// ErrDestroyUnsupported reports that permanent destroy is unavailable.
	ErrDestroyUnsupported = errors.New("destroy is not supported by this provider")
	// ErrInvalidProviderName reports an invalid provider name.
	ErrInvalidProviderName = errors.New("invalid provider name")
)

// Keyspace identifies the backend namespace for a binding.
type Keyspace struct {
	ProviderName string
	Namespace    string
	BindingName  string
	Prefix       string
}

// Entry describes one backend key without exposing its value.
type Entry struct {
	Key          string     `json:"key"`
	Status       string     `json:"status"`
	BackendPath  string     `json:"backendPath,omitempty"`
	RestoreUntil *time.Time `json:"restoreUntil,omitempty"`
}

// Backend is implemented by secrets provider adapters.
type Backend interface {
	ProviderName() string
	ProviderKind() string
	Create(ctx context.Context, ks Keyspace, key string, value []byte) (Entry, error)
	Update(ctx context.Context, ks Keyspace, key string, value []byte) (Entry, error)
	List(ctx context.Context, ks Keyspace) ([]Entry, error)
	Archive(ctx context.Context, ks Keyspace, key string) error
	ArchiveAll(ctx context.Context, ks Keyspace) error
	Restore(ctx context.Context, ks Keyspace, key string) (Entry, error)
	Destroy(ctx context.Context, ks Keyspace, key string) error
	DestroyAll(ctx context.Context, ks Keyspace) error
}

var dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ValidateProviderName validates a cluster-unique provider name.
func ValidateProviderName(name string) error {
	if len(name) == 0 || len(name) > 32 || strings.Contains(name, ".") || strings.Contains(name, "--") || !dnsLabelRE.MatchString(name) {
		return fmt.Errorf("%w: %q", ErrInvalidProviderName, name)
	}
	return nil
}

// ValidateClusterPrefix validates the path prefix for cluster secrets.
func ValidateClusterPrefix(prefix string) error {
	if len(prefix) == 0 || len(prefix) > 32 || strings.Contains(prefix, "--") || !dnsLabelRE.MatchString(prefix) {
		return fmt.Errorf("invalid cluster secrets prefix %q", prefix)
	}
	switch prefix {
	case "local", "k8s", "oidc":
		return fmt.Errorf("invalid cluster secrets prefix %q: reserved", prefix)
	}
	return nil
}

// ValidateSegment validates one slash-free backend path segment.
func ValidateSegment(name, value string) error {
	if len(value) == 0 || len(value) > 63 || strings.Contains(value, "--") || !dnsLabelRE.MatchString(value) {
		return fmt.Errorf("invalid %s %q", name, value)
	}
	return nil
}

// ParseKeyspaceName splits a SecretProviderKeyspace name.
func ParseKeyspaceName(name string) (providerName, bindingName string, err error) {
	parts := strings.SplitN(name, ".", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("SecretProviderKeyspace name must be <provider-name>.<binding-name>")
	}
	if err := ValidateProviderName(parts[0]); err != nil {
		return "", "", err
	}
	if err := ValidateSegment("binding name", parts[1]); err != nil {
		return "", "", err
	}
	return parts[0], parts[1], nil
}

// NewKeyspace constructs and validates a backend keyspace.
func NewKeyspace(prefix, namespace, resourceName string) (Keyspace, error) {
	provider, binding, err := ParseKeyspaceName(resourceName)
	if err != nil {
		return Keyspace{}, err
	}
	if err := ValidateClusterPrefix(prefix); err != nil {
		return Keyspace{}, err
	}
	if err := ValidateSegment("namespace", namespace); err != nil {
		return Keyspace{}, err
	}
	return Keyspace{ProviderName: provider, Namespace: namespace, BindingName: binding, Prefix: prefix}, nil
}

// SlashPath returns the absolute backend path for key.
func (k Keyspace) SlashPath(key string) (string, error) {
	if err := ValidateSegment("key", key); err != nil {
		return "", err
	}
	return "/" + path.Join(k.Prefix, k.Namespace, k.BindingName, key), nil
}

// RelativePath returns the backend path for key without a leading slash.
func (k Keyspace) RelativePath(key string) (string, error) {
	p, err := k.SlashPath(key)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(p, "/"), nil
}

// GCPSecretID returns the Google Secret Manager secret ID for key.
func (k Keyspace) GCPSecretID(key string) (string, error) {
	if err := ValidateSegment("key", key); err != nil {
		return "", err
	}
	return strings.Join([]string{k.Prefix, k.Namespace, k.BindingName, key}, "_"), nil
}

// ArchivedError returns an operator-facing archived-key error.
func ArchivedError(key string) error {
	return fmt.Errorf("%w: use podplane secret restore %s --for ..., or podplane secret destroy %s --for ... followed by create", ErrArchived, key, key)
}
