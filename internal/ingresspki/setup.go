// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package ingresspki

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/manager"

	operatorconfig "github.com/podplane/operator/internal/config"
	"github.com/podplane/operator/internal/secretsbackend"
)

// Setup configures ingress certificate management when domains are present.
func Setup(ctx context.Context, mgr manager.Manager, cfg operatorconfig.IngressCertificates, registry *secretsbackend.Registry) error {
	if len(cfg.Domains) == 0 {
		return nil
	}
	backend, err := registry.Backend(cfg.Provider)
	if err != nil {
		return err
	}
	store, err := NewBackendStore(backend, cfg.KeyPrefix)
	if err != nil {
		return err
	}
	domains := make([]Domain, 0, len(cfg.Domains))
	for name, domainConfig := range cfg.Domains {
		domain := Domain{Name: name}
		if domainConfig.Provider != nil {
			domain.DNSProvider = DNSProvider{
				Kind:         domainConfig.Provider.Kind,
				Region:       domainConfig.Provider.Region,
				HostedZoneID: domainConfig.Provider.HostedZoneID,
				RoleARN:      domainConfig.Provider.RoleARN,
			}
		}
		domains = append(domains, domain)
	}
	var issuer Issuer
	if cfg.ACME != nil {
		issuer = NewLegoIssuer(ACMEConfig{Server: cfg.ACME.Server, Email: cfg.ACME.Email}, store)
	}
	checkInterval, renewBefore, err := cfg.Durations()
	if err != nil {
		return err
	}
	certificateManager, err := NewManager(Config{
		Domains:       domains,
		CheckInterval: checkInterval,
		RenewBefore:   renewBefore,
	}, store, issuer)
	if err != nil {
		return err
	}
	if err := certificateManager.Initialize(ctx); err != nil {
		return err
	}
	if err := mgr.Add(certificateManager); err != nil {
		return err
	}
	return mgr.AddReadyzCheck("ingress-certificates", certificateManager.Ready)
}
