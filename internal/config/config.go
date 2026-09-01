// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/podplane/operator/internal/controllers"
)

// File is the top-level operator configuration file.
type File struct {
	Cluster             Cluster             `json:"cluster"`
	Secrets             Secrets             `json:"secrets"`
	Registry            Registry            `json:"registry"`
	Certificates        Certificates        `json:"certificates,omitempty"`
	IngressCertificates IngressCertificates `json:"ingress_certificates,omitempty"`
}

// Cluster configures shared cluster identity.
type Cluster struct {
	ID     string `json:"id"`
	OIDC   OIDC   `json:"oidc"`
	SPIFFE SPIFFE `json:"spiffe,omitempty"`
}

// SPIFFE configures the cluster SPIFFE trust domain.
type SPIFFE struct {
	TrustDomain string `json:"trust_domain,omitempty"`
}

// Certificates configures the workload signer. It is enabled when trust_domain is resolved.
type Certificates struct {
	CAPath string `json:"ca_path,omitempty"`
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
	DefaultProvider              string                                `json:"default_provider,omitempty"`
	Providers                    map[string]controllers.ProviderConfig `json:"providers"`
}

// IngressCertificates configures externally persisted apex and wildcard certificates.
type IngressCertificates struct {
	Provider      string                           `json:"provider,omitempty"`
	KeyPrefix     string                           `json:"key_prefix,omitempty"`
	CheckInterval string                           `json:"check_interval,omitempty"`
	RenewBefore   string                           `json:"renew_before,omitempty"`
	ACME          *IngressACME                     `json:"acme,omitempty"`
	Domains       map[string]IngressCertificateDNS `json:"domains,omitempty"`
}

// IngressACME configures the public ACME account.
type IngressACME struct {
	Server string `json:"server"`
	Email  string `json:"email"`
}

// IngressCertificateDNS configures DNS-01 for one ingress domain.
type IngressCertificateDNS struct {
	Provider *IngressDNSProvider `json:"dns_provider,omitempty"`
}

// IngressDNSProvider configures one supported DNS provider.
type IngressDNSProvider struct {
	Kind         string `json:"kind"`
	Region       string `json:"region,omitempty"`
	HostedZoneID string `json:"hosted_zone_id,omitempty"`
	RoleARN      string `json:"role_arn,omitempty"`
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
	if len(f.Secrets.Providers) > 0 && f.Cluster.ID == "" {
		return File{}, fmt.Errorf("cluster.id is required when secrets providers are configured")
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
	if len(f.IngressCertificates.Domains) > 0 {
		if f.IngressCertificates.Provider == "" {
			f.IngressCertificates.Provider = f.Secrets.DefaultProvider
		}
		provider, ok := f.Secrets.Providers[f.IngressCertificates.Provider]
		if !ok {
			return File{}, fmt.Errorf("ingress_certificates.provider must name a configured secrets provider")
		}
		if f.IngressCertificates.KeyPrefix == "" {
			f.IngressCertificates.KeyPrefix = provider.KeyPrefix
			if f.IngressCertificates.KeyPrefix == "" {
				f.IngressCertificates.KeyPrefix = f.Cluster.ID
			}
		}
		if f.IngressCertificates.ACME != nil {
			if f.IngressCertificates.ACME.Server == "" || f.IngressCertificates.ACME.Email == "" {
				return File{}, fmt.Errorf("ingress_certificates.acme.server and email are required")
			}
		}
		for domain, dns := range f.IngressCertificates.Domains {
			if err := validateDNSName(domain); err != nil {
				return File{}, fmt.Errorf("ingress_certificates.domains.%s: %w", domain, err)
			}
			if dns.Provider != nil && dns.Provider.Kind != "aws-route53" {
				return File{}, fmt.Errorf("ingress_certificates.domains.%s.dns_provider.kind must be aws-route53", domain)
			}
		}
	}
	if _, _, err := f.IngressCertificates.Durations(); err != nil {
		return File{}, err
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

// Durations parses optional ingress certificate reconciliation intervals.
func (c IngressCertificates) Durations() (time.Duration, time.Duration, error) {
	var checkInterval, renewBefore time.Duration
	var err error
	if c.CheckInterval != "" {
		checkInterval, err = time.ParseDuration(c.CheckInterval)
		if err != nil {
			return 0, 0, fmt.Errorf("parse ingress_certificates.check_interval: %w", err)
		}
		if checkInterval <= 0 {
			return 0, 0, fmt.Errorf("ingress_certificates.check_interval must be greater than zero")
		}
	}
	if c.RenewBefore != "" {
		renewBefore, err = time.ParseDuration(c.RenewBefore)
		if err != nil {
			return 0, 0, fmt.Errorf("parse ingress_certificates.renew_before: %w", err)
		}
		if renewBefore <= 0 {
			return 0, 0, fmt.Errorf("ingress_certificates.renew_before must be greater than zero")
		}
	}
	return checkInterval, renewBefore, nil
}

// validateDNSName enforces the policy constraints for dnsname.
func validateDNSName(name string) error {
	if len(name) == 0 || len(name) > 253 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return fmt.Errorf("invalid DNS name")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("invalid DNS name")
		}
		for _, r := range label {
			if r < 'a' || r > 'z' {
				if r < '0' || r > '9' {
					if r != '-' {
						return fmt.Errorf("invalid DNS name")
					}
				}
			}
		}
	}
	return nil
}
