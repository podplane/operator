// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package sds

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"time"
)

// validateWorkloadBundle validates a podCertificate credentialBundlePath file.
// Unlike the ingress validators, it requires a service hostname, not apex/wildcard SANs.
// Trust roots are configured by the TLS client, not by this credential loader.
func validateWorkloadBundle(bundle []byte, hostname string, now time.Time) ([]byte, []byte, error) {
	var chain, key []byte
	for rest := bytes.TrimSpace(bundle); len(rest) > 0; {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, nil, fmt.Errorf("invalid PEM data")
		}
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, nil, fmt.Errorf("invalid PEM data")
		}
		rest = bytes.TrimSpace(remaining)
		switch block.Type {
		case "CERTIFICATE":
			chain = append(chain, pem.EncodeToMemory(block)...)
		case "EC PRIVATE KEY", "PRIVATE KEY", "RSA PRIVATE KEY":
			if len(key) > 0 {
				return nil, nil, fmt.Errorf("bundle must contain exactly one private key")
			}
			key = pem.EncodeToMemory(block)
		default:
			return nil, nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
	}
	// Use the standard TLS parser to validate supported key types and the leaf/key match.
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, nil, fmt.Errorf("validate keypair: %w", err)
	}
	certificates := make([]*x509.Certificate, len(pair.Certificate))
	for i, der := range pair.Certificate {
		certificates[i], err = x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("parse certificate: %w", err)
		}
		if now.Before(certificates[i].NotBefore) || !now.Before(certificates[i].NotAfter) {
			return nil, nil, fmt.Errorf("certificate is not currently valid")
		}
	}
	leaf := certificates[0]
	if leaf.IsCA {
		return nil, nil, fmt.Errorf("workload certificate leaf must not be a CA")
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, nil, fmt.Errorf("certificate does not permit server authentication")
	}
	if err := leaf.VerifyHostname(hostname); err != nil {
		return nil, nil, fmt.Errorf("validate service hostname: %w", err)
	}
	for i := 0; i+1 < len(certificates); i++ {
		if err := certificates[i].CheckSignatureFrom(certificates[i+1]); err != nil {
			return nil, nil, fmt.Errorf("validate certificate chain: %w", err)
		}
	}
	return chain, key, nil
}
