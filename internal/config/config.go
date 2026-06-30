// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/podplane/operator/internal/controllers"
)

// File is the top-level operator configuration file.
type File struct {
	Cluster  Cluster  `json:"cluster"`
	Secrets  Secrets  `json:"secrets"`
	Registry Registry `json:"registry"`
}

// Cluster configures shared cluster identity.
type Cluster struct {
	ID   string `json:"id"`
	OIDC OIDC   `json:"oidc"`
}

// OIDC configures the cluster OIDC issuer used by operator modules.
type OIDC struct {
	IssuerURL     string `json:"issuer_url,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	UsernameClaim string `json:"username_claim,omitempty"`
	GroupsClaim   string `json:"groups_claim,omitempty"`
}

// Secrets configures the Podplane secrets module.
type Secrets struct {
	KeyRotation                  string                                `json:"key_rotation,omitempty"`
	AllowSyncToKubernetesSecrets bool                                  `json:"allow_sync_to_kubernetes_secrets,omitempty"`
	Providers                    map[string]controllers.ProviderConfig `json:"providers"`
}

// Registry configures the Podplane registry module.
type Registry struct {
	Auth RegistryAuth `json:"auth,omitempty"`
}

// RegistryAuth configures optional Docker-compatible registry authorization.
type RegistryAuth struct {
	Enabled bool `json:"enabled,omitempty"`
}

// Load reads and normalizes an operator configuration file.
func Load(path string) (File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, err
	}
	if f.Cluster.OIDC.ClientID == "" {
		f.Cluster.OIDC.ClientID = f.Cluster.ID
	}
	if f.Secrets.Providers == nil {
		f.Secrets.Providers = map[string]controllers.ProviderConfig{}
	}
	if _, err := f.KeyRotationDuration(); err != nil {
		return File{}, err
	}
	if f.Registry.Auth.Enabled {
		if f.Cluster.ID == "" {
			return File{}, fmt.Errorf("cluster.id is required when registry auth is enabled")
		}
		if f.Cluster.OIDC.IssuerURL == "" {
			return File{}, fmt.Errorf("cluster.oidc.issuer_url is required when registry auth is enabled")
		}
	}
	names := make([]string, 0, len(f.Secrets.Providers))
	for name := range f.Secrets.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "" {
			return File{}, fmt.Errorf("provider name is required")
		}
		p := f.Secrets.Providers[name]
		if p.Name != "" && p.Name != name {
			return File{}, fmt.Errorf("providers.%s.name must be omitted or match the provider map key", name)
		}
		p.Name = name
		f.Secrets.Providers[name] = p
	}
	return f, nil
}

// DefaultRotation returns the default public-key rotation interval.
func DefaultRotation() time.Duration { return 6 * time.Hour }

// KeyRotationDuration returns the parsed public-key rotation interval.
func (f File) KeyRotationDuration() (time.Duration, error) {
	if f.Secrets.KeyRotation == "" {
		return DefaultRotation(), nil
	}
	d, err := time.ParseDuration(f.Secrets.KeyRotation)
	if err != nil {
		return 0, fmt.Errorf("parse key_rotation: %w", err)
	}
	return d, nil
}
