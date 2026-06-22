// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

// VaultBackend stores keys in Vault or OpenBao KV-v2.
type VaultBackend struct {
	name, kind, address, token, mount string
	client                            *http.Client
}

type vaultHTTPError struct {
	method, path, status, body string
}

func (e vaultHTTPError) Error() string {
	return fmt.Sprintf("%s %s failed: %s: %s", e.method, e.path, e.status, e.body)
}

type vaultMetadata struct {
	currentVersion int
	archived       bool
}

// VaultOptions configures a VaultBackend.
type VaultOptions struct{ Name, Kind, Address, Token, Mount string }

// NewVaultBackend creates a Vault or OpenBao backend.
func NewVaultBackend(o VaultOptions) *VaultBackend {
	kind := o.Kind
	if kind == "" {
		kind = "vault"
	}
	mount := strings.Trim(o.Mount, "/")
	if mount == "" {
		mount = "secret"
	}
	return &VaultBackend{name: o.Name, kind: kind, address: strings.TrimRight(o.Address, "/"), token: o.Token, mount: mount, client: &http.Client{Timeout: 30 * time.Second}}
}

// ProviderName returns the configured provider name.
func (v *VaultBackend) ProviderName() string { return v.name }

// ProviderKind returns the CSI provider kind.
func (v *VaultBackend) ProviderKind() string { return v.kind }

// dataPath returns the relative and KV-v2 data API paths for key.
func (v *VaultBackend) dataPath(ks Keyspace, key string) (string, string, error) {
	rel, err := ks.RelativePath(key)
	if err != nil {
		return "", "", err
	}
	return rel, v.mount + "/data/" + rel, nil
}

// metadataPrefix returns the KV-v2 metadata list path for a keyspace.
func (v *VaultBackend) metadataPrefix(ks Keyspace) string {
	return v.mount + "/metadata/" + path.Join(ks.Prefix, ks.Namespace, ks.BindingName)
}

// request sends one Vault or OpenBao API request.
func (v *VaultBackend) request(ctx context.Context, method, apiPath string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.address+"/v1/"+strings.TrimLeft(apiPath, "/"), r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if v.token != "" {
		req.Header.Set("X-Vault-Token", v.token)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == 404 {
			return nil, ErrNotFound
		}
		return nil, vaultHTTPError{method: method, path: apiPath, status: resp.Status, body: string(b)}
	}
	return resp, nil
}

// Create creates a new KV-v2 value.
func (v *VaultBackend) Create(ctx context.Context, ks Keyspace, key string, value []byte) (Entry, error) {
	meta, err := v.metadataInfo(ctx, ks, key)
	if err == nil {
		if meta.currentVersion == 0 {
			return v.write(ctx, ks, key, value, 0)
		}
		if meta.archived {
			return Entry{}, ArchivedError(key)
		}
		return Entry{}, ErrAlreadyExists
	}
	if !errors.Is(err, ErrNotFound) {
		return Entry{}, err
	}
	return v.write(ctx, ks, key, value, 0)
}

// Update overwrites an existing active KV-v2 value.
func (v *VaultBackend) Update(ctx context.Context, ks Keyspace, key string, value []byte) (Entry, error) {
	meta, err := v.metadataInfo(ctx, ks, key)
	if err != nil {
		return Entry{}, err
	}
	if meta.currentVersion == 0 {
		return Entry{}, ErrNotFound
	}
	if meta.archived {
		return Entry{}, ArchivedError(key)
	}
	return v.write(ctx, ks, key, value, meta.currentVersion)
}

// write writes a KV-v2 value.
func (v *VaultBackend) write(ctx context.Context, ks Keyspace, key string, value []byte, cas int) (Entry, error) {
	rel, dp, err := v.dataPath(ks, key)
	if err != nil {
		return Entry{}, err
	}
	body := map[string]any{"data": map[string]string{"value": string(value)}, "options": map[string]int{"cas": cas}}
	resp, err := v.request(ctx, http.MethodPost, dp, body)
	if err != nil {
		if cas == 0 && isVaultCheckAndSetError(err) {
			return Entry{}, ErrAlreadyExists
		}
		return Entry{}, err
	}
	resp.Body.Close()
	return Entry{Key: key, Status: StatusActive, BackendPath: v.mount + "/data/" + rel}, nil
}

// List lists KV-v2 metadata entries in a keyspace.
func (v *VaultBackend) List(ctx context.Context, ks Keyspace) ([]Entry, error) {
	resp, err := v.request(ctx, "LIST", v.metadataPrefix(ks), nil)
	if err != nil {
		if err == ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer resp.Body.Close()
	var raw struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&raw)
	out := []Entry{}
	for _, k := range raw.Data.Keys {
		k = strings.TrimSuffix(k, "/")
		if k == "" {
			continue
		}
		st := StatusActive
		meta, err := v.metadataInfo(ctx, ks, k)
		if err != nil {
			st = StatusUnknown
		} else if meta.archived {
			st = StatusArchived
		}
		bp := v.mount + "/data/" + path.Join(ks.Prefix, ks.Namespace, ks.BindingName, k)
		out = append(out, Entry{Key: k, Status: st, BackendPath: bp})
	}
	return out, nil
}

// metadataInfo returns KV-v2 metadata for the current version.
func (v *VaultBackend) metadataInfo(ctx context.Context, ks Keyspace, key string) (vaultMetadata, error) {
	rel, err := ks.RelativePath(key)
	if err != nil {
		return vaultMetadata{}, err
	}
	api := v.mount + "/metadata/" + rel
	resp, err := v.request(ctx, http.MethodGet, api, nil)
	if err != nil {
		return vaultMetadata{}, err
	}
	defer resp.Body.Close()
	var raw struct {
		Data struct {
			CurrentVersion int `json:"current_version"`
			Versions       map[string]struct {
				DeletionTime string `json:"deletion_time"`
				Destroyed    bool   `json:"destroyed"`
			} `json:"versions"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return vaultMetadata{}, err
	}
	if raw.Data.CurrentVersion == 0 {
		return vaultMetadata{}, nil
	}
	ver := fmt.Sprint(raw.Data.CurrentVersion)
	m := raw.Data.Versions[ver]
	return vaultMetadata{currentVersion: raw.Data.CurrentVersion, archived: m.Destroyed || m.DeletionTime != ""}, nil
}

// Archive soft-deletes the latest KV-v2 version.
func (v *VaultBackend) Archive(ctx context.Context, ks Keyspace, key string) error {
	_, dp, err := v.dataPath(ks, key)
	if err != nil {
		return err
	}
	resp, err := v.request(ctx, http.MethodDelete, dp, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ArchiveAll archives every key in a keyspace.
func (v *VaultBackend) ArchiveAll(ctx context.Context, ks Keyspace) error {
	es, err := v.List(ctx, ks)
	if err != nil {
		return err
	}
	for _, e := range es {
		if err := v.Archive(ctx, ks, e.Key); err != nil {
			return err
		}
	}
	return nil
}

// Restore undeletes the current retained KV-v2 version.
func (v *VaultBackend) Restore(ctx context.Context, ks Keyspace, key string) (Entry, error) {
	meta, err := v.metadataInfo(ctx, ks, key)
	if err != nil {
		return Entry{}, err
	}
	if meta.currentVersion == 0 {
		return Entry{}, ErrNotFound
	}
	rel, err := ks.RelativePath(key)
	if err != nil {
		return Entry{}, err
	}
	if !meta.archived {
		return Entry{Key: key, Status: StatusActive, BackendPath: v.mount + "/data/" + rel}, nil
	}
	resp, err := v.request(ctx, http.MethodPost, v.mount+"/undelete/"+rel, map[string]any{"versions": []int{meta.currentVersion}})
	if err != nil {
		return Entry{}, err
	}
	resp.Body.Close()
	return Entry{Key: key, Status: StatusActive, BackendPath: v.mount + "/data/" + rel}, nil
}

// Destroy deletes KV-v2 metadata and all versions for a key.
func (v *VaultBackend) Destroy(ctx context.Context, ks Keyspace, key string) error {
	rel, err := ks.RelativePath(key)
	if err != nil {
		return err
	}
	api := v.mount + "/metadata/" + rel
	resp, err := v.request(ctx, http.MethodDelete, api, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// DestroyAll destroys every key in a keyspace.
func (v *VaultBackend) DestroyAll(ctx context.Context, ks Keyspace) error {
	es, err := v.List(ctx, ks)
	if err != nil {
		return err
	}
	for _, e := range es {
		if err := v.Destroy(ctx, ks, e.Key); err != nil {
			return err
		}
	}
	return nil
}

// isVaultCheckAndSetError reports whether Vault rejected a stale CAS write.
func isVaultCheckAndSetError(err error) bool {
	var httpErr vaultHTTPError
	if !errors.As(err, &httpErr) {
		return false
	}
	return strings.Contains(strings.ToLower(httpErr.body), "check-and-set") || strings.Contains(strings.ToLower(httpErr.body), "cas")
}
