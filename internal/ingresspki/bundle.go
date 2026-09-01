// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package ingresspki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"time"
)

const fallbackLifetime = 30 * 24 * time.Hour

// bundleInfo is the validated leaf and its trust classification.
type bundleInfo struct {
	leaf       *x509.Certificate
	selfSigned bool
}

// ValidateBundle splits and validates a combined ingress certificate bundle.
func ValidateBundle(bundle []byte, domain string, now time.Time) ([]byte, []byte, error) {
	_, certPEM, keyPEM, err := parseBundle(bundle, domain, now)
	return certPEM, keyPEM, err
}

// selfSignedBundle creates a fresh apex-and-wildcard fallback bundle.
func selfSignedBundle(domain string, now time.Time) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(fallbackLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{domain, "*." + domain},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return append(certPEM, keyPEM...), nil
}

// joinBundle combines a certificate chain and private key as one stored value.
func joinBundle(certificate, privateKey []byte) []byte {
	bundle := append([]byte(nil), certificate...)
	if len(bundle) > 0 && bundle[len(bundle)-1] != '\n' {
		bundle = append(bundle, '\n')
	}
	return append(bundle, privateKey...)
}

// validateBundle enforces the policy constraints for bundle.
func validateBundle(bundle []byte, domain string, now time.Time) (bundleInfo, error) {
	info, _, _, err := parseBundle(bundle, domain, now)
	return info, err
}

// parseBundle splits a combined PEM bundle and enforces ingress certificate policy.
func parseBundle(bundle []byte, domain string, now time.Time) (bundleInfo, []byte, []byte, error) {
	var certPEM, keyPEM bytes.Buffer
	var certificates []*x509.Certificate
	rest := bundle
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return bundleInfo{}, nil, nil, fmt.Errorf("invalid PEM data")
		}
		rest = remaining
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return bundleInfo{}, nil, nil, fmt.Errorf("parse certificate: %w", err)
			}
			certificates = append(certificates, cert)
			_ = pem.Encode(&certPEM, block)
		case "EC PRIVATE KEY", "PRIVATE KEY", "RSA PRIVATE KEY":
			_ = pem.Encode(&keyPEM, block)
		default:
			return bundleInfo{}, nil, nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
	}
	if len(certificates) == 0 || keyPEM.Len() == 0 {
		return bundleInfo{}, nil, nil, fmt.Errorf("bundle must contain a certificate chain and private key")
	}
	if _, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes()); err != nil {
		return bundleInfo{}, nil, nil, fmt.Errorf("validate keypair: %w", err)
	}
	leaf := certificates[0]
	wantNames := []string{domain, "*." + domain}
	gotNames := append([]string(nil), leaf.DNSNames...)
	slices.Sort(wantNames)
	slices.Sort(gotNames)
	if !slices.Equal(gotNames, wantNames) {
		return bundleInfo{}, nil, nil, fmt.Errorf("certificate DNS names %v do not match %v", gotNames, wantNames)
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return bundleInfo{}, nil, nil, fmt.Errorf("certificate is not currently valid")
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return bundleInfo{}, nil, nil, fmt.Errorf("certificate does not permit server authentication")
	}
	for i := 0; i+1 < len(certificates); i++ {
		if err := certificates[i].CheckSignatureFrom(certificates[i+1]); err != nil {
			return bundleInfo{}, nil, nil, fmt.Errorf("validate certificate chain: %w", err)
		}
	}
	selfSigned := len(certificates) == 1 && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
	return bundleInfo{leaf: leaf, selfSigned: selfSigned}, certPEM.Bytes(), keyPEM.Bytes(), nil
}
