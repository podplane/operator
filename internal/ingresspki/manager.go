// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package ingresspki

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/podplane/operator/internal/secretsbackend"
)

const (
	defaultCheckInterval = time.Hour
	defaultRenewBefore   = 30 * 24 * time.Hour
	fallbackRenewBefore  = 7 * 24 * time.Hour
)

var (
	expiryMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "podplane_ingress_certificate_expiration_timestamp_seconds",
		Help: "Expiration time of the active externally stored ingress certificate.",
	}, []string{"domain", "source"})
	errorMetric = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "podplane_ingress_certificate_reconcile_errors_total",
		Help: "Ingress certificate reconciliation errors.",
	}, []string{"domain", "stage"})
)

// init registers the ingress certificate metrics.
func init() {
	ctrlmetrics.Registry.MustRegister(expiryMetric, errorMetric)
}

// Config configures the ingress certificate manager.
type Config struct {
	Domains       []Domain
	CheckInterval time.Duration
	RenewBefore   time.Duration
}

// Manager maintains self-signed fallback and optional ACME certificates.
type Manager struct {
	config Config
	store  Store
	issuer Issuer
	now    func() time.Time

	mu    sync.RWMutex
	ready map[string]bool
}

// NewManager creates an ingress certificate manager.
func NewManager(config Config, store Store, issuer Issuer) (*Manager, error) {
	if len(config.Domains) == 0 {
		return nil, fmt.Errorf("at least one ingress certificate domain is required")
	}
	if config.CheckInterval == 0 {
		config.CheckInterval = defaultCheckInterval
	}
	if config.RenewBefore == 0 {
		config.RenewBefore = defaultRenewBefore
	}
	if config.CheckInterval <= 0 || config.RenewBefore <= 0 {
		return nil, fmt.Errorf("certificate intervals must be greater than zero")
	}
	config.Domains = slices.Clone(config.Domains)
	sort.Slice(config.Domains, func(i, j int) bool { return config.Domains[i].Name < config.Domains[j].Name })
	ready := make(map[string]bool, len(config.Domains))
	for i, domain := range config.Domains {
		if domain.Name == "" {
			return nil, fmt.Errorf("ingress certificate domain is required")
		}
		if i > 0 && domain.Name == config.Domains[i-1].Name {
			return nil, fmt.Errorf("duplicate ingress certificate domain %q", domain.Name)
		}
		ready[domain.Name] = false
	}
	return &Manager{config: config, store: store, issuer: issuer, now: time.Now, ready: ready}, nil
}

// Initialize guarantees that every domain has a valid persisted fallback before startup.
func (m *Manager) Initialize(ctx context.Context) error {
	for _, domain := range m.config.Domains {
		if _, _, err := m.ensureCurrent(ctx, domain); err != nil {
			return fmt.Errorf("initialize ingress certificate for %s: %w", domain.Name, err)
		}
	}
	return nil
}

// Start runs periodic public certificate issuance and renewal.
func (m *Manager) Start(ctx context.Context) error {
	m.reconcileAll(ctx)
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			m.reconcileAll(ctx)
		}
	}
}

// NeedLeaderElection keeps singleton certificate writes on the elected manager.
func (m *Manager) NeedLeaderElection() bool { return true }

// Ready reports whether every domain has a valid externally persisted bundle.
func (m *Manager) Ready(*http.Request) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for domain, ready := range m.ready {
		if !ready {
			return fmt.Errorf("ingress certificate for %s is not ready", domain)
		}
	}
	return nil
}

// reconcileAll processes every domain even when one reconciliation fails.
func (m *Manager) reconcileAll(ctx context.Context) {
	for _, domain := range m.config.Domains {
		if err := m.reconcile(ctx, domain); err != nil {
			slog.Error("reconcile ingress certificate", "domain", domain.Name, "error", err)
		}
	}
}

// reconcile renews one domain when its current certificate requires replacement.
func (m *Manager) reconcile(ctx context.Context, domain Domain) error {
	info, _, err := m.ensureCurrent(ctx, domain)
	if err != nil {
		errorMetric.WithLabelValues(domain.Name, "fallback").Inc()
		return err
	}
	if m.issuer == nil || domain.DNSProvider.Kind == "" {
		return nil
	}
	if !info.selfSigned && info.leaf.NotAfter.Sub(m.now()) > m.config.RenewBefore {
		return nil
	}
	bundle, err := m.issuer.Obtain(ctx, domain)
	if err != nil {
		errorMetric.WithLabelValues(domain.Name, "acme").Inc()
		return err
	}
	info, err = validateBundle(bundle, domain.Name, m.now())
	if err != nil {
		errorMetric.WithLabelValues(domain.Name, "validation").Inc()
		return fmt.Errorf("validate ACME bundle: %w", err)
	}
	if info.selfSigned {
		errorMetric.WithLabelValues(domain.Name, "validation").Inc()
		return fmt.Errorf("ACME returned a self-signed certificate")
	}
	if err := m.store.Save(ctx, bundleKey(domain.Name), bundle); err != nil {
		errorMetric.WithLabelValues(domain.Name, "publication").Inc()
		return fmt.Errorf("publish ACME bundle: %w", err)
	}
	m.setReady(domain.Name, true)
	expiryMetric.WithLabelValues(domain.Name, "acme").Set(float64(info.leaf.NotAfter.Unix()))
	expiryMetric.DeleteLabelValues(domain.Name, "self-signed")
	slog.Info("published ACME ingress certificate", "domain", domain.Name, "notAfter", info.leaf.NotAfter)
	return nil
}

// ensureCurrent loads a valid bundle or atomically publishes a fresh fallback.
func (m *Manager) ensureCurrent(ctx context.Context, domain Domain) (bundleInfo, []byte, error) {
	now := m.now()
	bundle, err := m.store.Load(ctx, bundleKey(domain.Name))
	if err == nil {
		info, validationErr := validateBundle(bundle, domain.Name, now)
		if validationErr == nil {
			if !info.selfSigned || info.leaf.NotAfter.Sub(now) > fallbackRenewBefore {
				m.setReady(domain.Name, true)
				source := "acme"
				if info.selfSigned {
					source = "self-signed"
				}
				expiryMetric.WithLabelValues(domain.Name, source).Set(float64(info.leaf.NotAfter.Unix()))
				return info, bundle, nil
			}
		}
	} else if !errors.Is(err, secretsbackend.ErrNotFound) {
		m.setReady(domain.Name, false)
		return bundleInfo{}, nil, fmt.Errorf("load current bundle: %w", err)
	}
	bundle, err = selfSignedBundle(domain.Name, now)
	if err != nil {
		m.setReady(domain.Name, false)
		return bundleInfo{}, nil, fmt.Errorf("generate self-signed fallback: %w", err)
	}
	info, err := validateBundle(bundle, domain.Name, now)
	if err != nil {
		m.setReady(domain.Name, false)
		return bundleInfo{}, nil, fmt.Errorf("validate self-signed fallback: %w", err)
	}
	if err := m.store.Save(ctx, bundleKey(domain.Name), bundle); err != nil {
		m.setReady(domain.Name, false)
		return bundleInfo{}, nil, fmt.Errorf("publish self-signed fallback: %w", err)
	}
	m.setReady(domain.Name, true)
	expiryMetric.WithLabelValues(domain.Name, "self-signed").Set(float64(info.leaf.NotAfter.Unix()))
	expiryMetric.DeleteLabelValues(domain.Name, "acme")
	slog.Warn("published self-signed fallback ingress certificate", "domain", domain.Name, "notAfter", info.leaf.NotAfter)
	return info, bundle, nil
}

// setReady updates ready while preserving unrelated state.
func (m *Manager) setReady(domain string, ready bool) {
	m.mu.Lock()
	m.ready[domain] = ready
	m.mu.Unlock()
}

// bundleKey returns the stable, backend-safe key for a domain bundle.
func bundleKey(domain string) string {
	digest := sha256.Sum256([]byte(domain))
	return "bundle-" + hex.EncodeToString(digest[:12])
}

// accountKey returns the stable, backend-safe key for an ACME account.
func accountKey(server string) string {
	digest := sha256.Sum256([]byte(server))
	return "acme-account-" + hex.EncodeToString(digest[:12])
}
