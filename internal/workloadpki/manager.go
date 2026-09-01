// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package workloadpki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// SignerName identifies the Podplane workload certificate signer.
	SignerName = "certificates.podplane.dev/workload"
	// BundleName identifies the authoritative workload trust bundle.
	BundleName = "certificates.podplane.dev:workload:roots"
	// ModeAnnotation selects the workload certificate identity mode.
	ModeAnnotation = "certificates.podplane.dev/mode"
	// ServiceAnnotation names the Service authorized for service-mode certificates.
	ServiceAnnotation = "certificates.podplane.dev/service"
	maxLifetime       = 24 * time.Hour
	retentionMargin   = 6 * time.Hour
)

var (
	pcrTotal        = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "podplane_workload_certificate_pcr_reconciliations_total", Help: "Completed workload certificate reconciliations."}, []string{"result", "reason", "key_type", "mode"})
	pcrPending      = prometheus.NewGauge(prometheus.GaugeOpts{Name: "podplane_workload_certificate_pcr_pending", Help: "Workload certificate reconciliations currently pending."})
	statusConflicts = prometheus.NewCounter(prometheus.CounterOpts{Name: "podplane_workload_certificate_pcr_terminal_update_conflicts_total", Help: "Terminal PCR status update conflicts."})
	caNotAfter      = prometheus.NewGauge(prometheus.GaugeOpts{Name: "podplane_workload_certificate_ca_not_after_seconds", Help: "Active workload CA expiry as Unix time."})
	caLoadErrors    = prometheus.NewCounter(prometheus.CounterOpts{Name: "podplane_workload_certificate_ca_load_errors_total", Help: "Workload CA key load errors."})
	bundleErrors    = prometheus.NewCounter(prometheus.CounterOpts{Name: "podplane_workload_certificate_trust_bundle_reconcile_errors_total", Help: "Trust bundle reconciliation errors."})
	servingErrors   = prometheus.NewCounter(prometheus.CounterOpts{Name: "podplane_workload_certificate_serving_reconcile_errors_total", Help: "Operator serving certificate reconciliation errors."})
)

// init registers package defaults with their supporting libraries.
func init() {
	metrics.Registry.MustRegister(pcrTotal, pcrPending, statusConflicts, caNotAfter, caLoadErrors, bundleErrors, servingErrors)
}

var trustDomainRE = regexp.MustCompile(`^[a-z0-9._-]+$`)

// Config is the complete signer configuration.
type Config struct {
	TrustDomain string
	CAPath      string
	Serving     []ServingCertificate
}

// Validate checks the signer configuration.
func (c Config) Validate() error {
	if c.TrustDomain == "" || len(c.TrustDomain) > 255 || !trustDomainRE.MatchString(c.TrustDomain) {
		return fmt.Errorf("invalid resolved certificates trust domain")
	}
	if c.CAPath == "" {
		return fmt.Errorf("certificates CA path is required")
	}
	for _, serving := range c.Serving {
		if err := serving.validate(); err != nil {
			return err
		}
	}
	return nil
}

// Manager owns the in-memory signer and publication readiness.
type Manager struct {
	client  client.Client
	reader  client.Reader
	cfg     Config
	mu      sync.RWMutex
	active  *signingPair
	canSign bool
	ready   bool
	lastKey [32]byte
}

// signingPair is the active CA key, certificate, and published trust bundle.
type signingPair struct {
	key    ed25519.PrivateKey
	cert   *x509.Certificate
	bundle string
}

// NewManager creates a workload certificate manager.
func NewManager(c client.Client, reader client.Reader, cfg Config) (*Manager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Manager{client: c, reader: reader, cfg: cfg}, nil
}

// NeedLeaderElection restricts signing and publication to the elected manager.
func (m *Manager) NeedLeaderElection() bool { return true }

// Ready reports whether the signer and its published certificates are ready.
func (m *Manager) Ready(_ *http.Request) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.ready {
		return errors.New("workload certificate signer is not ready")
	}
	return nil
}

// Initialize publishes the trust bundle and writes initial serving certificates
// before HTTPS listeners are created.
func (m *Manager) Initialize(ctx context.Context) error {
	m.reconcileCA(ctx)
	m.mu.RLock()
	canSign := m.canSign
	m.mu.RUnlock()
	if !canSign {
		return errors.New("workload certificate signer failed to initialize")
	}
	if err := m.reconcileServing(); err != nil {
		servingErrors.Inc()
		m.setReady(false)
		return err
	}
	return nil
}

// Start loads and periodically revalidates the CSI file and authoritative bundle.
func (m *Manager) Start(ctx context.Context) error {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		m.reconcileCA(ctx)
		if err := m.reconcileServing(); err != nil {
			servingErrors.Inc()
			m.setReady(false)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Bundle returns a copy of the authoritative workload trust bundle.
func (m *Manager) Bundle() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil || !m.canSign {
		return nil, errors.New("workload certificate signer unavailable")
	}
	return []byte(m.active.bundle), nil
}

// parseKeyFile loads a strict PKCS#8 Ed25519 workload CA key.
func parseKeyFile(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, errors.New("CA file must contain exactly one unencrypted PKCS#8 private key")
	}
	v, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 CA key: %w", err)
	}
	k, ok := v.(ed25519.PrivateKey)
	if !ok || len(k) != ed25519.PrivateKeySize {
		return nil, errors.New("CA key must be Ed25519")
	}
	return k, nil
}

// parseRoots decodes a PEM bundle containing only CA certificates.
func parseRoots(s string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(strings.TrimSpace(s)) > 0 {
		b, rest := pem.Decode([]byte(s))
		if b == nil || b.Type != "CERTIFICATE" {
			return nil, errors.New("invalid trust bundle PEM")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		if !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageCertSign == 0 || c.CheckSignatureFrom(c) != nil {
			return nil, errors.New("trust anchor is not a self-signed signing CA")
		}
		out = append(out, c)
		s = string(rest)
	}
	return out, nil
}

// newRoot creates a self-signed workload CA certificate for key.
func newRoot(key ed25519.PrivateKey, now time.Time) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Podplane Workload CA"}, NotBefore: now.Add(-2 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, t, t, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// encodeRoots returns the roots as a PEM certificate bundle.
func encodeRoots(cs []*x509.Certificate) string {
	var b strings.Builder
	for _, c := range cs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.String()
}

// reconcileCA publishes and activates the CA represented by authoritative storage.
func (m *Manager) reconcileCA(ctx context.Context) {
	key, err := parseKeyFile(m.cfg.CAPath)
	if err != nil {
		caLoadErrors.Inc()
		return
	} // last-known-good
	fp := sha256.Sum256(key.Public().(ed25519.PublicKey))
	m.mu.RLock()
	keyChanged := m.active != nil && m.lastKey != fp
	m.mu.RUnlock()
	if keyChanged {
		// Automatic private-key replacement is forbidden. Keep serving with the
		// last known-good pair and, critically, do not publish the candidate key.
		caLoadErrors.Inc()
		return
	}
	var obj certv1.ClusterTrustBundle
	err = m.reader.Get(ctx, types.NamespacedName{Name: BundleName}, &obj)
	var roots []*x509.Certificate
	if apierrors.IsNotFound(err) {
		root, e := newRoot(key, time.Now())
		if e != nil {
			return
		}
		roots = []*x509.Certificate{root}
	} else if err != nil {
		bundleErrors.Inc()
		m.reconcileFailed()
		return
	} else {
		if obj.Spec.SignerName != SignerName {
			bundleErrors.Inc()
			m.disableSigner()
			return
		}
		roots, err = parseRoots(obj.Spec.TrustBundle)
		if err != nil {
			bundleErrors.Inc()
			m.disableSigner()
			return
		}
	}
	var selected *x509.Certificate
	seen := map[string]bool{}
	deduped := roots[:0]
	for _, r := range roots {
		if r.PublicKeyAlgorithm != x509.Ed25519 || !bytes.Equal(r.RawSubjectPublicKeyInfo, mustSPKI(key.Public())) {
			// This implementation has no deliberate manual key-rollover mode, so
			// an unrelated anchor is trust-bundle drift rather than retained trust.
			bundleErrors.Inc()
			m.disableSigner()
			return
		}
		id := string(r.Raw)
		if seen[id] {
			continue
		}
		seen[id] = true
		deduped = append(deduped, r)
		if selected == nil || r.NotAfter.After(selected.NotAfter) {
			selected = r
		}
	}
	roots = deduped
	if selected == nil {
		bundleErrors.Inc()
		m.disableSigner()
		return
	}
	if time.Until(selected.NotAfter) < maxLifetime+2*time.Minute {
		m.disableSigner()
		return
	}
	if time.Until(selected.NotAfter) < 365*24*time.Hour {
		n, e := newRoot(key, time.Now())
		if e != nil {
			return
		}
		roots = append(roots, n)
		selected = n
	}
	// A same-key superseded root is safe to remove only after every leaf it may
	// have issued, plus refresh/cache margin, has expired.
	cutoff := time.Now().Add(-(maxLifetime + retentionMargin))
	kept := roots[:0]
	for _, root := range roots {
		if root == selected || root.NotAfter.After(cutoff) {
			kept = append(kept, root)
		}
	}
	roots = kept
	sort.Slice(roots, func(i, j int) bool { return roots[i].NotAfter.Before(roots[j].NotAfter) })
	bundle := encodeRoots(roots)
	if obj.Name == "" {
		obj = certv1.ClusterTrustBundle{ObjectMeta: metav1.ObjectMeta{Name: BundleName}, Spec: certv1.ClusterTrustBundleSpec{SignerName: SignerName, TrustBundle: bundle}}
		err = m.client.Create(ctx, &obj)
	} else if obj.Spec.TrustBundle != bundle {
		obj.Spec.TrustBundle = bundle
		err = m.client.Update(ctx, &obj)
	}
	if err != nil {
		bundleErrors.Inc()
		m.reconcileFailed()
		return
	}
	m.activate(key, selected, bundle, fp)
}

// activate replaces the active signer after its trust bundle is published.
func (m *Manager) activate(key ed25519.PrivateKey, cert *x509.Certificate, bundle string, fingerprint [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active = &signingPair{key: key, cert: cert, bundle: bundle}
	m.lastKey = fingerprint
	m.canSign = true
	m.ready = true
	caNotAfter.Set(float64(cert.NotAfter.Unix()))
}

// reconcileFailed preserves a known signer but marks the manager unready.
func (m *Manager) reconcileFailed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		m.canSign = false
	}
	m.ready = false
}

// disableSigner prevents issuance after authoritative state fails validation.
func (m *Manager) disableSigner() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.canSign = false
	m.ready = false
}

// mustSPKI encodes a public key already accepted by certificate policy.
func mustSPKI(k crypto.PublicKey) []byte { b, _ := x509.MarshalPKIXPublicKey(k); return b }

// setReady updates the manager readiness state.
func (m *Manager) setReady(v bool) { m.mu.Lock(); m.ready = v; m.mu.Unlock() }

// isTerminal reports whether a request already has a terminal condition.
func isTerminal(p *certv1.PodCertificateRequest) bool {
	for _, c := range p.Status.Conditions {
		if c.Status == metav1.ConditionTrue && (c.Type == "Issued" || c.Type == "Denied" || c.Type == "Failed") {
			return true
		}
	}
	return false
}

// Reconciler signs only Podplane PCRs. Pod and Service reads use the uncached reader.
type Reconciler struct {
	client.Client
	Reader client.Reader
	Signer *Manager
}

// Reconcile validates and signs one PodCertificateRequest.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var p certv1.PodCertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &p); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if p.Spec.SignerName != SignerName || isTerminal(&p) {
		return ctrl.Result{}, nil
	}
	pcrPending.Inc()
	defer pcrPending.Dec()
	csr, reason, err := validateCSR(p.Spec.StubPKCS10Request)
	if err != nil {
		return ctrl.Result{}, r.deny(ctx, &p, reason, err.Error(), "", "")
	}
	mode, svc, err := parseAnnotations(p.Spec.UnverifiedUserAnnotations)
	if err != nil {
		return ctrl.Result{}, r.deny(ctx, &p, "InvalidUnverifiedUserAnnotations", err.Error(), keyType(csr.PublicKey), "")
	}
	if err = validateKey(csr.PublicKey); err != nil {
		return ctrl.Result{}, r.deny(ctx, &p, "UnsupportedKeyType", err.Error(), keyType(csr.PublicKey), mode)
	}
	var auth *authorization
	if svc != "" {
		auth, err = r.authorize(ctx, &p, svc)
		if err != nil {
			var d *denial
			if errors.As(err, &d) {
				return ctrl.Result{}, r.deny(ctx, &p, d.reason, d.Error(), keyType(csr.PublicKey), mode)
			}
			pcrTotal.WithLabelValues("error", "AuthorizationError", keyType(csr.PublicKey), mode).Inc()
			return ctrl.Result{}, err
		}
	}
	status, err := r.Signer.sign(&p, csr.PublicKey, mode, auth)
	if err != nil {
		pcrTotal.WithLabelValues("error", "SigningError", keyType(csr.PublicKey), mode).Inc()
		return ctrl.Result{}, err
	}
	var latest certv1.PodCertificateRequest
	if err = r.Get(ctx, req.NamespacedName, &latest); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if isTerminal(&latest) {
		return ctrl.Result{}, nil
	}
	if auth != nil {
		fresh, e := r.authorize(ctx, &latest, svc)
		if e != nil {
			return ctrl.Result{}, e
		}
		if !auth.equal(fresh) {
			return ctrl.Result{Requeue: true}, nil
		}
	}
	latest.Status = status
	err = r.Status().Update(ctx, &latest)
	if apierrors.IsConflict(err) {
		statusConflicts.Inc()
		var after certv1.PodCertificateRequest
		if getErr := r.Reader.Get(ctx, req.NamespacedName, &after); getErr != nil {
			return ctrl.Result{}, client.IgnoreNotFound(getErr)
		}
		if isTerminal(&after) {
			return ctrl.Result{}, nil
		}
		pcrTotal.WithLabelValues("error", "StatusConflict", keyType(csr.PublicKey), mode).Inc()
		return ctrl.Result{Requeue: true}, nil
	}
	if err != nil {
		pcrTotal.WithLabelValues("error", "StatusUpdateError", keyType(csr.PublicKey), mode).Inc()
		return ctrl.Result{}, err
	}
	pcrTotal.WithLabelValues("issued", "Issued", keyType(csr.PublicKey), mode).Inc()
	return ctrl.Result{}, nil
}

// denial carries a stable Kubernetes condition reason with a safe message.
type denial struct{ reason, msg string }

// Error renders the error without exposing sensitive state.
func (d *denial) Error() string { return d.msg }

// deny records a terminal denial unless another reconciler won the update race.
func (r *Reconciler) deny(ctx context.Context, p *certv1.PodCertificateRequest, reason, msg, key, mode string) error {
	p.Status = certv1.PodCertificateRequestStatus{Conditions: []metav1.Condition{{Type: "Denied", Status: metav1.ConditionTrue, Reason: reason, Message: msg, ObservedGeneration: p.Generation, LastTransitionTime: metav1.Now()}}}
	err := r.Status().Update(ctx, p)
	if apierrors.IsConflict(err) {
		statusConflicts.Inc()
		var latest certv1.PodCertificateRequest
		if getErr := r.Reader.Get(ctx, client.ObjectKeyFromObject(p), &latest); getErr == nil && isTerminal(&latest) {
			return nil
		}
	}
	if err == nil {
		pcrTotal.WithLabelValues("denied", reason, key, mode).Inc()
	}
	return err
}

// validateCSR accepts a signed, extension-free PKCS#10 request with a supported key.
func validateCSR(der []byte) (*x509.CertificateRequest, string, error) {
	c, e := x509.ParseCertificateRequest(der)
	if e != nil {
		return nil, "InvalidRequest", errors.New("invalid PKCS#10 request")
	}
	if e = c.CheckSignature(); e != nil {
		return nil, "InvalidRequest", errors.New("invalid PKCS#10 proof of possession")
	}
	// Attributes is deprecated for extension handling, but remains the only
	// parsed representation of arbitrary PKCS#10 attributes that we must reject.
	if !bytes.Equal(c.RawSubject, []byte{0x30, 0x00}) || len(c.Subject.Names) != 0 || len(c.Subject.ExtraNames) != 0 || len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs) > 0 || len(c.Extensions) > 0 || len(c.ExtraExtensions) > 0 || len(c.Attributes) > 0 { //nolint:staticcheck
		return nil, "InvalidRequest", errors.New("CSR must have an empty subject, SANs, extensions, and attributes")
	}
	return c, "", nil
}

// keyType returns the bounded metric label for a public key.
func keyType(k any) string {
	switch v := k.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA%d", v.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSAP%d", v.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "ED25519"
	default:
		return "unsupported"
	}
}

// validateKey accepts only keys and strengths allowed by the signer policy.
func validateKey(k any) error {
	switch v := k.(type) {
	case *rsa.PublicKey:
		if v.N.BitLen() != 3072 && v.N.BitLen() != 4096 {
			return errors.New("RSA key must be 3072 or 4096 bits")
		}
		if v.E != 65537 {
			return errors.New("unsupported RSA exponent")
		}
	case *ecdsa.PublicKey:
		b := v.Curve.Params().BitSize
		if b != 256 && b != 384 && b != 521 {
			return errors.New("unsupported ECDSA curve")
		}
	case ed25519.PublicKey:
		if len(v) != ed25519.PublicKeySize {
			return errors.New("invalid Ed25519 key")
		}
	default:
		return errors.New("unsupported public key")
	}
	return nil
}

// parseAnnotations resolves a fail-closed certificate identity request.
func parseAnnotations(a map[string]string) (string, string, error) {
	for k := range a {
		if k != ModeAnnotation && k != ServiceAnnotation {
			return "", "", fmt.Errorf("unsupported annotation %q", k)
		}
	}
	mode := a[ModeAnnotation]
	if mode == "" {
		mode = "spiffe"
	}
	if mode != "spiffe" && mode != "service" {
		return "", "", errors.New("mode must be spiffe or service")
	}
	svc := a[ServiceAnnotation]
	if svc != "" {
		if errs := validation.IsDNS1123Label(svc); len(errs) > 0 {
			return "", "", errors.New("service must be a DNS label")
		}
	}
	if mode == "service" && svc == "" {
		return "", "", errors.New("service mode requires a service")
	}
	return mode, svc, nil
}

// authorization captures the Pod and Service state authorized before signing.
type authorization struct {
	podUID     types.UID
	serviceUID types.UID
	selector   map[string]string
	dns        []string
}

// equal reports whether two authorization snapshots contain the same policy state.
func (a *authorization) equal(b *authorization) bool {
	return a.podUID == b.podUID && a.serviceUID == b.serviceUID && apiequality.Semantic.DeepEqual(a.selector, b.selector)
}

// authorize proves that the named Service currently selects the requesting Pod.
func (r *Reconciler) authorize(ctx context.Context, p *certv1.PodCertificateRequest, name string) (*authorization, error) {
	var pod corev1.Pod
	if e := r.Reader.Get(ctx, types.NamespacedName{Namespace: p.Namespace, Name: p.Spec.PodName}, &pod); e != nil {
		return nil, e
	}
	if pod.UID != p.Spec.PodUID {
		return nil, errors.New("pod UID changed")
	}
	var svc corev1.Service
	if e := r.Reader.Get(ctx, types.NamespacedName{Namespace: p.Namespace, Name: name}, &svc); e != nil {
		return nil, e
	}
	if svc.Spec.Type == corev1.ServiceTypeExternalName || len(svc.Spec.Selector) == 0 {
		return nil, &denial{"ServiceDoesNotSelectPod", "service does not have an eligible selector"}
	}
	for k, v := range svc.Spec.Selector {
		if pod.Labels[k] != v {
			return nil, &denial{"ServiceDoesNotSelectPod", "service does not select pod"}
		}
	}
	return &authorization{
		podUID:     pod.UID,
		serviceUID: svc.UID,
		selector:   maps.Clone(svc.Spec.Selector),
		dns:        ServiceDNSNames(name, p.Namespace),
	}, nil
}

// ServiceDNSNames returns the canonical Kubernetes DNS names for a Service.
func ServiceDNSNames(name, namespace string) []string {
	base := name + "." + namespace
	return []string{name, base, base + ".svc", base + ".svc.cluster.local"}
}

// randomSerial creates a cryptographically random serial.
func randomSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return nil, e
	}
	if bytes.Equal(b, make([]byte, 16)) {
		b[15] = 1
	}
	return new(big.Int).SetBytes(b), nil
}

// sign issues a bounded-lifetime certificate from the active workload CA.
func (m *Manager) sign(p *certv1.PodCertificateRequest, pub crypto.PublicKey, mode string, a *authorization) (certv1.PodCertificateRequestStatus, error) {
	m.mu.RLock()
	pair := m.active
	canSign := m.canSign
	m.mu.RUnlock()
	if !canSign || pair == nil {
		return certv1.PodCertificateRequestStatus{}, errors.New("certificate signer unavailable")
	}
	now := time.Now()
	life := maxLifetime
	if p.Spec.MaxExpirationSeconds != nil && time.Duration(*p.Spec.MaxExpirationSeconds)*time.Second < life {
		life = time.Duration(*p.Spec.MaxExpirationSeconds) * time.Second
	}
	if d := pair.cert.NotAfter.Sub(now); d < life {
		life = d
	}
	nb := now.Add(-2 * time.Minute)
	na := nb.Add(life)
	serial, e := randomSerial()
	if e != nil {
		return certv1.PodCertificateRequestStatus{}, e
	}
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{}, NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if mode == "spiffe" {
		u, _ := url.Parse("spiffe://" + m.cfg.TrustDomain + "/ns/" + p.Namespace + "/sa/" + p.Spec.ServiceAccountName)
		t.URIs = []*url.URL{u}
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}
	if a != nil {
		t.DNSNames = a.dns
	}
	der, e := x509.CreateCertificate(rand.Reader, t, pair.cert, pub, pair.key)
	if e != nil {
		return certv1.PodCertificateRequestStatus{}, e
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		return certv1.PodCertificateRequestStatus{}, e
	}
	if e = verifyLeaf(leaf, pub, pair.cert, t); e != nil {
		return certv1.PodCertificateRequestStatus{}, e
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	nbtn, nat, mid := metav1.NewTime(leaf.NotBefore), metav1.NewTime(leaf.NotAfter), metav1.NewTime(leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore)/2))
	return certv1.PodCertificateRequestStatus{Conditions: []metav1.Condition{{Type: "Issued", Status: metav1.ConditionTrue, Reason: "Issued", Message: "Podplane workload certificate issued", ObservedGeneration: p.Generation, LastTransitionTime: metav1.Now()}}, CertificateChain: chain, NotBefore: &nbtn, NotAfter: &nat, BeginRefreshAt: &mid}, nil
}

// verifyLeaf checks a locally issued leaf against its complete intended contract.
func verifyLeaf(c *x509.Certificate, pub crypto.PublicKey, ca *x509.Certificate, want *x509.Certificate) error {
	if c.CheckSignatureFrom(ca) != nil || !bytes.Equal(c.RawSubjectPublicKeyInfo, mustSPKI(pub)) || c.IsCA || !c.BasicConstraintsValid || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.Subject.Names) != 0 || len(c.IPAddresses)+len(c.EmailAddresses) > 0 || c.NotBefore.Before(ca.NotBefore) || c.NotAfter.After(ca.NotAfter) || !c.NotAfter.After(c.NotBefore) {
		return errors.New("locally issued certificate failed verification")
	}
	if !apiequality.Semantic.DeepEqual(c.DNSNames, want.DNSNames) || !apiequality.Semantic.DeepEqual(c.URIs, want.URIs) || !apiequality.Semantic.DeepEqual(c.ExtKeyUsage, want.ExtKeyUsage) {
		return errors.New("locally issued certificate contract mismatch")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: c.NotBefore.Add(time.Second), KeyUsages: want.ExtKeyUsage}); err != nil {
		return fmt.Errorf("locally issued certificate chain failed verification: %w", err)
	}
	foundSAN := false
	for _, ext := range c.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) {
			foundSAN = ext.Critical
		}
	}
	if !foundSAN {
		return errors.New("locally issued certificate SAN extension is absent or non-critical")
	}
	return nil
}

// SetupWithManager registers the PodCertificateRequest controller.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&certv1.PodCertificateRequest{}).Complete(r)
}
