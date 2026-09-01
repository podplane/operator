// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package workloadpki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

const servingRefreshBefore = 12 * time.Hour

// ServingCertificate describes one operator-owned serving key pair.
type ServingCertificate struct {
	Name     string
	CertFile string
	KeyFile  string
	DNSNames []string
}

// validate checks one serving certificate's file and identity configuration.
func (c ServingCertificate) validate() error {
	if c.Name == "" || c.CertFile == "" || c.KeyFile == "" {
		return errors.New("serving certificate name, certificate file, and key file are required")
	}
	if filepath.Dir(c.CertFile) != filepath.Dir(c.KeyFile) {
		return fmt.Errorf("serving certificate %q files must share a directory", c.Name)
	}
	if len(c.DNSNames) == 0 {
		return fmt.Errorf("serving certificate %q requires DNS names", c.Name)
	}
	for _, name := range c.DNSNames {
		if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
			return fmt.Errorf("serving certificate %q has invalid DNS name %q", c.Name, name)
		}
	}
	return nil
}

// reconcileServing ensures every operator endpoint has a current key pair.
func (m *Manager) reconcileServing() error {
	m.mu.RLock()
	pair := m.active
	canSign := m.canSign
	m.mu.RUnlock()
	if !canSign || pair == nil {
		return errors.New("certificate signer unavailable for serving certificates")
	}
	for _, cfg := range m.cfg.Serving {
		if err := ensureServingCertificate(cfg, pair, time.Now()); err != nil {
			return fmt.Errorf("reconcile serving certificate %q: %w", cfg.Name, err)
		}
	}
	return nil
}

// ensureServingCertificate makes serving certificate available and current.
func ensureServingCertificate(cfg ServingCertificate, pair *signingPair, now time.Time) error {
	if servingCertificateCurrent(cfg, pair.cert, now) {
		return nil
	}
	key, err := parseServingPrivateKeyFile(cfg.KeyFile)
	if errors.Is(err, os.ErrNotExist) {
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	notBefore := now.Add(-2 * time.Minute)
	notAfter := notBefore.Add(maxLifetime)
	if notAfter.After(pair.cert.NotAfter) {
		notAfter = pair.cert.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              slices.Clone(cfg.DNSNames),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, pair.cert, key.Public(), pair.key)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if err := verifyLeaf(leaf, key.Public(), pair.cert, template); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return writeServingPair(cfg.CertFile, certPEM, cfg.KeyFile, keyPEM)
}

// servingCertificateCurrent reports whether the on-disk pair is valid and outside its refresh window.
func servingCertificateCurrent(cfg ServingCertificate, issuer *x509.Certificate, now time.Time) bool {
	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return false
	}
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.CheckSignatureFrom(issuer) != nil || !cert.NotAfter.After(now.Add(servingRefreshBefore)) || !slices.Equal(cert.DNSNames, cfg.DNSNames) {
		return false
	}
	_, err = parseServingKeyPair(certPEM, keyPEM)
	return err == nil
}

// parseServingKeyPair strictly parses and matches an Ed25519 serving key pair.
func parseServingKeyPair(certPEM, keyPEM []byte) (*x509.Certificate, error) {
	key, err := parseServingPrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	certBlock, rest := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid serving certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, mustSPKI(key.Public())) {
		return nil, errors.New("serving certificate and private key do not match")
	}
	return cert, nil
}

// parseServingPrivateKeyFile loads a serving private key from path.
func parseServingPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseServingPrivateKey(keyPEM)
}

// parseServingPrivateKey strictly parses an Ed25519 serving private key.
func parseServingPrivateKey(keyPEM []byte) (ed25519.PrivateKey, error) {
	keyBlock, rest := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid serving private key PEM")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("serving private key must be Ed25519")
	}
	return key, nil
}

// writeServingPair publishes a complete serving pair through one generation link.
func writeServingPair(certFile string, certPEM []byte, keyFile string, keyPEM []byte) error {
	dir := filepath.Dir(certFile)
	if dir != filepath.Dir(keyFile) || certFile == keyFile {
		return errors.New("serving certificate and key must be distinct files in one directory")
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	id := servingPairID(certFile, keyFile)
	prefix := ".serving-" + id + "-"
	current := filepath.Join(dir, prefix+"current")
	oldGeneration, _ := os.Readlink(current)
	generation, err := os.MkdirTemp(dir, prefix)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(generation)
		}
	}()
	if err := os.WriteFile(filepath.Join(generation, filepath.Base(certFile)), certPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(generation, filepath.Base(keyFile)), keyPEM, 0600); err != nil {
		return err
	}
	currentName := filepath.Base(current)
	if err := ensureServingLink(certFile, filepath.Join(currentName, filepath.Base(certFile))); err != nil {
		return err
	}
	if err := ensureServingLink(keyFile, filepath.Join(currentName, filepath.Base(keyFile))); err != nil {
		return err
	}
	newGeneration := filepath.Base(generation)
	if err := removeStaleServingGenerations(dir, prefix, oldGeneration, newGeneration); err != nil {
		return err
	}
	if err := replaceServingLink(current, newGeneration); err != nil {
		return err
	}
	published = true
	return nil
}

// servingPairID returns a short stable identifier for a pair of public paths.
func servingPairID(certFile, keyFile string) string {
	digest := sha256.Sum256([]byte(filepath.Base(certFile) + "\x00" + filepath.Base(keyFile)))
	return hex.EncodeToString(digest[:8])
}

// ensureServingLink leaves an expected symlink in place or atomically replaces it.
func ensureServingLink(path, target string) error {
	if existing, err := os.Readlink(path); err == nil && existing == target {
		return nil
	}
	return replaceServingLink(path, target)
}

// replaceServingLink atomically replaces path with a relative symlink to target.
func replaceServingLink(path, target string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".serving-link-")
	if err != nil {
		return err
	}
	temporary := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporary) }()
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// removeStaleServingGenerations retains the current and next complete pairs.
func removeStaleServingGenerations(dir, prefix, current, next string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) || entry.Name() == current || entry.Name() == next {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
