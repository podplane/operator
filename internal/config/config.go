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
	ClusterID                    string                                `json:"clusterID"`
	SecretsPrefix                string                                `json:"secretsPrefix,omitempty"`
	AllowSyncToKubernetesSecrets bool                                  `json:"allowSyncToKubernetesSecrets,omitempty"`
	Providers                    map[string]controllers.ProviderConfig `json:"providers"`
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
	if f.SecretsPrefix == "" {
		f.SecretsPrefix = f.ClusterID
	}
	names := make([]string, 0, len(f.Providers))
	for name := range f.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "" {
			return File{}, fmt.Errorf("provider name is required")
		}
		p := f.Providers[name]
		if p.Name != "" && p.Name != name {
			return File{}, fmt.Errorf("providers.%s.name must be omitted or match the provider map key", name)
		}
		p.Name = name
		f.Providers[name] = p
	}
	return f, nil
}

// DefaultRotation returns the default public-key rotation interval.
func DefaultRotation() time.Duration { return 6 * time.Hour }
