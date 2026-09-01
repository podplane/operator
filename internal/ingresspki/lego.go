// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package ingresspki

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns/route53"
	"github.com/go-acme/lego/v4/registration"

	"github.com/podplane/operator/internal/secretsbackend"
)

// ACMEConfig configures one ACME account.
type ACMEConfig struct {
	Server string
	Email  string
}

// DNSProvider configures DNS-01 for one domain.
type DNSProvider struct {
	Kind         string
	Region       string
	HostedZoneID string
	RoleARN      string
}

// Domain is one apex and wildcard certificate managed by the operator.
type Domain struct {
	Name        string
	DNSProvider DNSProvider
}

// account is Lego's persisted ACME user and its parsed private key.
type account struct {
	Email        string                 `json:"email"`
	PrivateKey   string                 `json:"private_key"`
	Registration *registration.Resource `json:"registration,omitempty"`
	key          crypto.PrivateKey
}

// GetEmail returns the ACME account email address.
func (a *account) GetEmail() string { return a.Email }

// GetRegistration returns the ACME registration state.
func (a *account) GetRegistration() *registration.Resource { return a.Registration }

// GetPrivateKey returns the ACME account private key.
func (a *account) GetPrivateKey() crypto.PrivateKey { return a.key }

// Issuer obtains publicly trusted certificate bundles.
type Issuer interface {
	Obtain(ctx context.Context, domain Domain) ([]byte, error)
}

// legoIssuer serializes Lego operations over one persisted ACME account.
type legoIssuer struct {
	config ACMEConfig
	store  Store
	mu     sync.Mutex
}

// NewLegoIssuer creates an ACME issuer backed by persisted account state.
func NewLegoIssuer(config ACMEConfig, store Store) Issuer {
	// Lego's default logger includes account and challenge details. Reconciliation
	// emits bounded, structured status without those payloads.
	legolog.Logger = log.New(io.Discard, "", 0)
	return &legoIssuer{config: config, store: store}
}

// Obtain issues a certificate bundle for domain through ACME DNS-01.
func (l *legoIssuer) Obtain(ctx context.Context, domain Domain) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	user, err := l.loadAccount(ctx)
	if err != nil {
		return nil, err
	}
	config := lego.NewConfig(user)
	config.CADirURL = l.config.Server
	config.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("create ACME client: %w", err)
	}
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("register ACME account: %w", err)
		}
		user.Registration = reg
		if err := l.saveAccount(ctx, user); err != nil {
			return nil, fmt.Errorf("persist ACME account: %w", err)
		}
		config = lego.NewConfig(user)
		config.CADirURL = l.config.Server
		config.Certificate.KeyType = certcrypto.EC256
		client, err = lego.NewClient(config)
		if err != nil {
			return nil, fmt.Errorf("create registered ACME client: %w", err)
		}
	}
	provider, err := route53Provider(domain.DNSProvider)
	if err != nil {
		return nil, err
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("configure ACME DNS-01: %w", err)
	}
	resource, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{domain.Name, "*." + domain.Name},
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("obtain ACME certificate: %w", err)
	}
	return joinBundle(resource.Certificate, resource.PrivateKey), nil
}

// route53Provider constructs the allowlisted Route53 DNS-01 provider.
func route53Provider(provider DNSProvider) (*route53.DNSProvider, error) {
	if provider.Kind != "aws-route53" {
		return nil, fmt.Errorf("unsupported ACME DNS provider %q", provider.Kind)
	}
	config := route53.NewDefaultConfig()
	config.AccessKeyID = ""
	config.SecretAccessKey = ""
	config.SessionToken = ""
	config.AssumeRoleArn = provider.RoleARN
	config.Region = provider.Region
	config.HostedZoneID = provider.HostedZoneID
	configured, err := route53.NewDNSProviderConfig(config)
	if err != nil {
		return nil, fmt.Errorf("configure Route53 DNS-01: %w", err)
	}
	return configured, nil
}

// loadAccount restores account from durable storage.
func (l *legoIssuer) loadAccount(ctx context.Context) (*account, error) {
	value, err := l.store.Load(ctx, accountKey(l.config.Server))
	if err != nil {
		if !errors.Is(err, secretsbackend.ErrNotFound) {
			return nil, fmt.Errorf("load ACME account: %w", err)
		}
		key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
		if err != nil {
			return nil, fmt.Errorf("generate ACME account key: %w", err)
		}
		user := &account{Email: l.config.Email, PrivateKey: string(certcrypto.PEMEncode(key)), key: key}
		if err := l.saveAccount(ctx, user); err != nil {
			return nil, fmt.Errorf("persist new ACME account key: %w", err)
		}
		return user, nil
	}
	var user account
	if err := json.Unmarshal(value, &user); err != nil {
		return nil, fmt.Errorf("decode ACME account: %w", err)
	}
	key, err := certcrypto.ParsePEMPrivateKey([]byte(user.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("parse ACME account key: %w", err)
	}
	user.Email = l.config.Email
	user.key = key
	return &user, nil
}

// saveAccount persists account to durable storage.
func (l *legoIssuer) saveAccount(ctx context.Context, user *account) error {
	value, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return l.store.Save(ctx, accountKey(l.config.Server), value)
}
