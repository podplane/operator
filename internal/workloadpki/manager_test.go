// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package workloadpki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

func metricValue(t *testing.T, name string) float64 {
	t.Helper()
	families, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == name {
			metric := family.Metric[0]
			if metric.Gauge != nil {
				return metric.Gauge.GetValue()
			}
			return metric.Counter.GetValue()
		}
	}
	t.Fatalf("metric %s not registered", name)
	return 0
}

type failingListClient struct{ client.Client }

func (c failingListClient) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("cache unavailable")
}

func TestRequestBacklogMetrics(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := certv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	p := &certv1.PodCertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "test", CreationTimestamp: metav1.NewTime(created)}, Spec: certv1.PodCertificateRequestSpec{SignerName: SignerName, StubPKCS10Request: csr}}
	other := p.DeepCopy()
	other.Name, other.Spec.SignerName = "other", "example.com/other"
	terminal := p.DeepCopy()
	terminal.Name = "terminal"
	terminal.Status.Conditions = []metav1.Condition{{Type: "Denied", Status: metav1.ConditionTrue}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(p).WithObjects(p, other, terminal).Build()
	m := &Manager{client: c}
	check := func(count, timestamp, success float64) {
		t.Helper()
		for name, want := range map[string]float64{"pcr_pending": count, "pcr_oldest_pending_timestamp_seconds": timestamp, "pcr_collection_success": success} {
			if got := metricValue(t, "podplane_workload_certificate_"+name); got != want {
				t.Errorf("%s = %v, want %v", name, got, want)
			}
		}
	}
	m.collectRequests(ctx) // Existing objects after restart, without reconcile events.
	check(1, float64(created.Unix()), 1)
	r := &Reconciler{Client: c, Reader: c, Signer: m}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)}); err == nil {
		t.Fatal("expected unavailable signer error")
	}
	m.collectRequests(ctx)
	check(1, float64(created.Unix()), 1)
	before := metricValue(t, "podplane_workload_certificate_pcr_collection_errors_total")
	m.client = failingListClient{c}
	m.collectRequests(ctx)
	check(1, float64(created.Unix()), 0)
	if metricValue(t, "podplane_workload_certificate_pcr_collection_errors_total") != before+1 {
		t.Fatal("collection failure not counted")
	}
	m.client = c
	for _, condition := range []string{"Issued", "Denied", "Failed"} {
		p.Status.Conditions = []metav1.Condition{{Type: condition, Status: metav1.ConditionTrue}}
		if err := c.Status().Update(ctx, p); err != nil {
			t.Fatal(err)
		}
		m.collectRequests(ctx)
		check(0, 0, 1)
	}
	p.Status.Conditions = nil
	if err := c.Status().Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	m.collectRequests(ctx)
	check(1, float64(created.Unix()), 1)
	if err := c.Delete(ctx, p); err != nil {
		t.Fatal(err)
	}
	m.collectRequests(ctx)
	check(0, 0, 1)
}

func TestSignerReadinessMetric(t *testing.T) {
	m := &Manager{}
	for _, ready := range []bool{false, true, false, true} {
		m.setReady(ready)
		want := float64(0)
		if ready {
			want = 1
		}
		if (m.Ready(nil) == nil) != ready || metricValue(t, "podplane_workload_certificate_signer_ready") != want {
			t.Fatal("readiness metric disagrees with Ready")
		}
	}
	m.disableSigner()
	if m.Ready(nil) == nil || metricValue(t, "podplane_workload_certificate_signer_ready") != 0 {
		t.Fatal("disabled signer remains ready")
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	cert, err := newRoot(key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m.activate(key, cert, encodeRoots([]*x509.Certificate{cert}))
	if m.Ready(nil) != nil || metricValue(t, "podplane_workload_certificate_signer_ready") != 1 {
		t.Fatal("activated signer is not ready")
	}
	m.reconcileFailed()
	if m.Ready(nil) == nil || metricValue(t, "podplane_workload_certificate_signer_ready") != 0 {
		t.Fatal("failed reconciliation remains ready")
	}
}

// TestServiceDNSNames verifies canonical Kubernetes Service identity derivation.
func TestServiceDNSNames(t *testing.T) {
	want := []string{"api", "api.payments", "api.payments.svc", "api.payments.svc.cluster.local"}
	if got := ServiceDNSNames("api", "payments"); !slices.Equal(got, want) {
		t.Fatalf("ServiceDNSNames() = %v, want %v", got, want)
	}
}

// TestValidateCSRProofContentsAndAllSupportedKeys covers the complete CSR policy.
func TestValidateCSRProofContentsAndAllSupportedKeys(t *testing.T) {
	keys := map[string]crypto.Signer{}
	for _, bits := range []int{3072, 4096} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		keys[keyType(&key.PublicKey)] = key
	}
	for _, curve := range []struct {
		name  string
		curve elliptic.Curve
	}{
		{"ECDSAP256", elliptic.P256()}, {"ECDSAP384", elliptic.P384()}, {"ECDSAP521", elliptic.P521()},
	} {
		key, err := ecdsa.GenerateKey(curve.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[curve.name] = key
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys["ED25519"] = edKey
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			if err != nil {
				t.Fatal(err)
			}
			csr, _, err := validateCSR(der)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateKey(csr.PublicKey); err != nil {
				t.Fatal(err)
			}
			der[len(der)-1] ^= 1
			if _, _, err := validateCSR(der); err == nil {
				t.Fatal("accepted invalid proof of possession")
			}
		})
	}

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for name, template := range map[string]*x509.CertificateRequest{
		"subject":   {Subject: pkix.Name{CommonName: "injected"}},
		"extension": {DNSNames: []string{"injected.example"}},
		"attribute": {Attributes: []pkix.AttributeTypeAndValueSET{{Type: []int{1, 2, 3}, Value: [][]pkix.AttributeTypeAndValue{{{Type: []int{1, 2, 3, 4}, Value: "x"}}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := validateCSR(der); err == nil {
				t.Fatal("accepted nonempty CSR")
			}
		})
	}
}

// TestRandomSerialIsPositiveBounded128Bit bounds generated certificate serials.
func TestRandomSerialIsPositiveBounded128Bit(t *testing.T) {
	for range 100 {
		n, err := randomSerial()
		if err != nil {
			t.Fatal(err)
		}
		if n.Sign() <= 0 || n.BitLen() > 128 || n.Cmp(big.NewInt(0)) == 0 {
			t.Fatalf("invalid serial %v", n)
		}
	}
}

// TestAnnotationsFailClosed rejects unknown or incomplete identity annotations.
func TestAnnotationsFailClosed(t *testing.T) {
	tests := []struct {
		name string
		a    map[string]string
		mode string
		svc  string
		bad  bool
	}{
		{"default", nil, "spiffe", "", false},
		{"spiffe service", map[string]string{ServiceAnnotation: "api"}, "spiffe", "api", false},
		{"service", map[string]string{ModeAnnotation: "service", ServiceAnnotation: "api"}, "service", "api", false},
		{"service missing", map[string]string{ModeAnnotation: "service"}, "", "", true},
		{"unknown", map[string]string{"example.com/san": "evil"}, "", "", true},
		{"invalid name", map[string]string{ServiceAnnotation: "other/api"}, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, svc, err := parseAnnotations(tt.a)
			if (err != nil) != tt.bad || (!tt.bad && (mode != tt.mode || svc != tt.svc)) {
				t.Fatalf("parseAnnotations() = %q, %q, %v", mode, svc, err)
			}
		})
	}
}

// TestStrictPKCS8Ed25519Loading rejects unsupported workload CA encodings.
func TestStrictPKCS8Ed25519Loading(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	path := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseKeyFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), []byte("junk")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseKeyFile(path); err == nil {
		t.Fatal("accepted trailing data")
	}
}

// TestTrustBundleSync verifies public bundle publication, renewal, and drift repair
// while preserving unrelated resource data and metadata.
func TestTrustBundleSync(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := certv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "trust", Namespace: "router", Labels: map[string]string{"owner": "chart"}}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"keep": []byte("unrelated")}}
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "trust", Namespace: "other", Annotations: map[string]string{"owner": "chart"}}, BinaryData: map[string][]byte{"keep": {1, 2, 3}}}
	untouched := secret.DeepCopy()
	untouched.Namespace = "unconfigured"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret, configMap, untouched).Build()
	path := filepath.Join(t.TempDir(), "ca.pem")
	key := writePKCS8Key(t, path)
	m, err := NewManager(c, c, Config{TrustDomain: "cluster.example", CAPath: path, TrustBundleSync: TrustBundleSyncConfig{Resources: []TrustBundleSyncTarget{
		{Kind: "Secret", Namespace: "router", Name: "trust", Key: "tls.crt"},
		{Kind: "ConfigMap", Namespace: "other", Name: "trust", Key: "ca.crt"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	// check reconciles the signer and verifies every destination against the published bundle.
	check := func() string {
		t.Helper()
		if err := m.Initialize(ctx); err != nil {
			t.Fatal(err)
		}
		if err := m.Ready(nil); err != nil {
			t.Fatal(err)
		}
		var bundle certv1.ClusterTrustBundle
		if err := c.Get(ctx, client.ObjectKey{Name: BundleName}, &bundle); err != nil {
			t.Fatal(err)
		}
		// Comparing whole objects also protects unrelated fields and namespaces.
		for _, original := range []client.Object{secret, configMap, untouched} {
			got := original.DeepCopyObject().(client.Object)
			if err := c.Get(ctx, client.ObjectKeyFromObject(original), got); err != nil {
				t.Fatal(err)
			}
			want := original.DeepCopyObject().(client.Object)
			switch obj := want.(type) {
			case *corev1.Secret:
				if obj.Namespace == "router" {
					obj.Data["tls.crt"] = []byte(bundle.Spec.TrustBundle)
				}
			case *corev1.ConfigMap:
				obj.Data = map[string]string{"ca.crt": bundle.Spec.TrustBundle}
			}
			got.SetResourceVersion("")
			want.SetResourceVersion("")
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("unexpected fields changed in %T %s", got, client.ObjectKeyFromObject(got))
			}
		}
		return bundle.Spec.TrustBundle
	}
	first := check()
	var synced corev1.Secret
	if err := c.Get(ctx, client.ObjectKeyFromObject(secret), &synced); err != nil {
		t.Fatal(err)
	}
	version := synced.ResourceVersion
	check()
	if err := c.Get(ctx, client.ObjectKeyFromObject(secret), &synced); err != nil {
		t.Fatal(err)
	}
	if synced.ResourceVersion != version {
		t.Fatal("unchanged bundle rewrote the Secret")
	}
	// Repair drift even when the source bundle has not changed.
	synced.Data["tls.crt"] = []byte("drift")
	if err := c.Update(ctx, &synced); err != nil {
		t.Fatal(err)
	}
	check()
	// A CA approaching expiry must publish both the renewed and retained root.
	old, err := newRoot(key, time.Now().AddDate(-10, 6, 0))
	if err != nil {
		t.Fatal(err)
	}
	var bundle certv1.ClusterTrustBundle
	if err := c.Get(ctx, client.ObjectKey{Name: BundleName}, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle.Spec.TrustBundle = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: old.Raw}))
	if err := c.Update(ctx, &bundle); err != nil {
		t.Fatal(err)
	}
	renewed := check()
	if first == renewed {
		t.Fatal("CA did not renew")
	}
	var certificates []*x509.Certificate
	for rest := []byte(renewed); len(rest) > 0; {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("sync included non-certificate material")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certificates = append(certificates, cert)
		rest = remaining
	}
	if len(certificates) != 2 || !certificates[0].Equal(old) || !certificates[1].IsCA || certificates[1].CheckSignatureFrom(certificates[1]) != nil {
		t.Fatal("sync did not preserve both public roots")
	}
}

// rejectingTrustSyncClient simulates missing write permission for one namespace.
type rejectingTrustSyncClient struct {
	client.Client
	reject bool
}

// Patch rejects the blocked namespace until the test restores permission.
func (c *rejectingTrustSyncClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if c.reject && obj.GetNamespace() == "blocked" {
		return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, obj.GetName(), errors.New("not permitted"))
	}
	return c.Client.Patch(ctx, obj, patch, opts...)
}

// TestTrustBundleSyncFailureAndRecovery verifies failures affect readiness without
// blocking issuance or other destinations, and recover once targets are writable.
func TestTrustBundleSyncFailureAndRecovery(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := certv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	blocked := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "trust", Namespace: "blocked"}}
	healthy := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "trust", Namespace: "healthy"}}
	c := &rejectingTrustSyncClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(blocked, healthy).Build(), reject: true}
	path := filepath.Join(t.TempDir(), "ca.pem")
	writePKCS8Key(t, path)
	m, err := NewManager(c, c.Client, Config{TrustDomain: "cluster.example", CAPath: path, TrustBundleSync: TrustBundleSyncConfig{Resources: []TrustBundleSyncTarget{
		{Kind: "Secret", Namespace: "missing", Name: "trust", Key: "ca.crt"},
		{Kind: "Secret", Namespace: "blocked", Name: "trust", Key: "ca.crt"},
		{Kind: "ConfigMap", Namespace: "healthy", Name: "trust", Key: "ca.crt"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Initialize(ctx); err != nil {
		t.Fatalf("sync failure prevented startup: %v", err)
	}
	if m.Ready(nil) == nil {
		t.Fatal("failed destinations must fail readiness")
	}
	bundle, err := m.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := m.sign(&certv1.PodCertificateRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "app"}, Spec: certv1.PodCertificateRequestSpec{ServiceAccountName: "app"}}, leafKey.Public(), "spiffe", nil); err != nil {
		t.Fatalf("sync failure disabled issuance: %v", err)
	}
	missing := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "trust", Namespace: "missing"}}
	if err := c.Get(ctx, client.ObjectKeyFromObject(missing), missing); !apierrors.IsNotFound(err) {
		t.Fatalf("missing target was created: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(healthy), healthy); err != nil {
		t.Fatal(err)
	}
	if healthy.Data["ca.crt"] != string(bundle) {
		t.Fatal("failed destinations prevented healthy destination sync")
	}
	if err := c.Create(ctx, missing); err != nil {
		t.Fatal(err)
	}
	c.reject = false
	if err := m.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Ready(nil); err != nil {
		t.Fatalf("readiness did not recover: %v", err)
	}
	for _, target := range []*corev1.Secret{missing, blocked} {
		if err := c.Get(ctx, client.ObjectKeyFromObject(target), target); err != nil {
			t.Fatal(err)
		}
		if string(target.Data["ca.crt"]) != string(bundle) {
			t.Fatal("failed destination did not recover")
		}
	}
}

// racingTrustSyncClient simulates another writer creating a target first.
type racingTrustSyncClient struct {
	client.Client
	race bool
}

// Create inserts an independently owned target before attempting the requested create.
func (c *racingTrustSyncClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if c.race && obj.GetNamespace() == "app" {
		other := obj.DeepCopyObject().(client.Object)
		other.SetLabels(map[string]string{"owner": "other"})
		switch other := other.(type) {
		case *corev1.Secret:
			other.Type = "example.com/custom"
			other.Data = map[string][]byte{"keep": []byte("unrelated")}
		case *corev1.ConfigMap:
			other.Data = map[string]string{"keep": "unrelated"}
		}
		if err := c.Client.Create(ctx, other); err != nil {
			return err
		}
	}
	return c.Client.Create(ctx, obj, opts...)
}

// TestTrustBundleSyncCreation verifies inheritance, explicit overrides, creation
// races, and deletion recovery for both resource kinds through signer initialization.
func TestTrustBundleSyncCreation(t *testing.T) {
	on, off := true, false
	for _, kind := range []string{"Secret", "ConfigMap"} {
		for _, tc := range []struct {
			name          string
			defaultCreate bool
			override      *bool
			wantCreate    bool
			race          bool
		}{
			{name: "default false"},
			{name: "default true", defaultCreate: true, wantCreate: true},
			{name: "override true", override: &on, wantCreate: true},
			{name: "override false", defaultCreate: true, override: &off},
			{name: "creation race", defaultCreate: true, wantCreate: true, race: true},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				ctx := context.Background()
				scheme := runtime.NewScheme()
				if err := certv1.AddToScheme(scheme); err != nil {
					t.Fatal(err)
				}
				if err := corev1.AddToScheme(scheme); err != nil {
					t.Fatal(err)
				}
				c := &racingTrustSyncClient{Client: fake.NewClientBuilder().WithScheme(scheme).Build(), race: tc.race}
				path := filepath.Join(t.TempDir(), "ca.pem")
				m, err := NewManager(c, c.Client, Config{TrustDomain: "cluster.example", CAPath: path, TrustBundleSync: TrustBundleSyncConfig{
					CreateIfMissing: tc.defaultCreate,
					Resources:       []TrustBundleSyncTarget{{Kind: kind, Namespace: "app", Name: "trust", Key: "ca.crt", CreateIfMissing: tc.override}},
				}})
				if err != nil {
					t.Fatal(err)
				}
				var obj client.Object = &corev1.Secret{}
				if kind == "ConfigMap" {
					obj = &corev1.ConfigMap{}
				}
				name := client.ObjectKey{Namespace: "app", Name: "trust"}
				if err := m.Initialize(ctx); err == nil {
					t.Fatal("initialized without a CA key")
				}
				if err := c.Get(ctx, name, obj); !apierrors.IsNotFound(err) {
					t.Fatalf("created a target before a valid bundle was available: %v", err)
				}
				writePKCS8Key(t, path)
				if err := m.Initialize(ctx); err != nil {
					t.Fatal(err)
				}
				err = c.Get(ctx, name, obj)
				if !tc.wantCreate {
					if !apierrors.IsNotFound(err) || m.Ready(nil) == nil {
						t.Fatalf("missing pre-created target: get=%v, ready=%v", err, m.Ready(nil))
					}
					return
				}
				if err != nil || m.Ready(nil) != nil {
					t.Fatalf("creation failed: get=%v, ready=%v", err, m.Ready(nil))
				}
				bundle, err := m.Bundle()
				if err != nil {
					t.Fatal(err)
				}
				var got, keep string
				switch obj := obj.(type) {
				case *corev1.Secret:
					got, keep = string(obj.Data["ca.crt"]), string(obj.Data["keep"])
					wantType := corev1.SecretTypeOpaque
					if tc.race {
						wantType = "example.com/custom"
					}
					if obj.Type != wantType {
						t.Fatalf("Secret type = %s, want %s", obj.Type, wantType)
					}
				case *corev1.ConfigMap:
					got, keep = obj.Data["ca.crt"], obj.Data["keep"]
				}
				if got != string(bundle) || len(obj.GetOwnerReferences()) != 0 {
					t.Fatal("created target has incorrect bundle or unexpected ownership")
				}
				if tc.race && (keep != "unrelated" || obj.GetLabels()["owner"] != "other") {
					t.Fatal("creation race overwrote another writer's fields")
				}
				if err := c.Delete(ctx, obj); err != nil {
					t.Fatal(err)
				}
				if err := m.Initialize(ctx); err != nil {
					t.Fatal(err)
				}
				if err := c.Get(ctx, name, obj); err != nil || m.Ready(nil) != nil {
					t.Fatalf("deleted target was not recreated: %v", err)
				}
			})
		}
	}
}

// TestChangedCAKeyCannotPublishWhenBundleIsMissing prevents accidental trust replacement.
func TestChangedCAKeyCannotPublishWhenBundleIsMissing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := certv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	path := t.TempDir() + "/ca.pem"
	first := writePKCS8Key(t, path)
	m := &Manager{client: c, reader: c, cfg: Config{TrustDomain: "k8s.example", CAPath: path}}
	m.reconcileCA(ctx)
	if !m.ready || m.active == nil || !m.active.key.Equal(first) {
		t.Fatal("initial CA did not become active")
	}
	var bundle certv1.ClusterTrustBundle
	if err := c.Get(ctx, types.NamespacedName{Name: BundleName}, &bundle); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, &bundle); err != nil {
		t.Fatal(err)
	}
	writePKCS8Key(t, path)
	m.reconcileCA(ctx)
	if !m.ready || !m.active.key.Equal(first) {
		t.Fatal("changed key displaced the last known-good signer")
	}
	if err := c.Get(ctx, types.NamespacedName{Name: BundleName}, &bundle); err != nil {
		t.Fatalf("retained trust bundle was not restored: %v", err)
	}
	if bundle.Spec.TrustBundle != m.active.bundle {
		t.Fatal("restored bundle differs from retained trust")
	}
}

// TestAuthorizeRequiresSelectorLabelPresence distinguishes an absent label from an empty value.
func TestAuthorizeRequiresSelectorLabelPresence(t *testing.T) {
	for _, present := range []bool{false, true} {
		scheme := runtime.NewScheme()
		if err := corev1.AddToScheme(scheme); err != nil {
			t.Fatal(err)
		}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: "pod-uid"}}
		if present {
			pod.Labels = map[string]string{"selected": ""}
		}
		svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "ns"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"selected": ""}}}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, svc).Build()
		r := &Reconciler{Reader: c}
		p := &certv1.PodCertificateRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "ns"}, Spec: certv1.PodCertificateRequestSpec{PodName: "pod", PodUID: "pod-uid"}}
		_, err := r.authorize(context.Background(), p, "svc")
		if (err == nil) != present {
			t.Fatalf("present=%v: authorization error = %v", present, err)
		}
	}
}

// TestInvalidCandidateDoesNotSkipTrustValidation checks authoritative drift despite a bad CSI update.
func TestInvalidCandidateDoesNotSkipTrustValidation(t *testing.T) {
	for _, candidate := range []string{"missing", "malformed", "changed"} {
		t.Run(candidate, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			if err := certv1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			c := fake.NewClientBuilder().WithScheme(scheme).Build()
			path := filepath.Join(t.TempDir(), "ca.pem")
			first := writePKCS8Key(t, path)
			m := &Manager{client: c, reader: c, cfg: Config{TrustDomain: "k8s.example", CAPath: path}}
			m.reconcileCA(ctx)
			switch candidate {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed":
				writePKCS8Key(t, path)
			}
			m.reconcileCA(ctx)
			if m.Ready(nil) != nil || !m.active.key.Equal(first) {
				t.Fatal("candidate failure lost healthy retained signer")
			}
			var bundle certv1.ClusterTrustBundle
			if err := c.Get(ctx, types.NamespacedName{Name: BundleName}, &bundle); err != nil {
				t.Fatal(err)
			}
			bundle.Spec.TrustBundle = "invalid"
			if err := c.Update(ctx, &bundle); err != nil {
				t.Fatal(err)
			}
			m.reconcileCA(ctx)
			if m.Ready(nil) == nil {
				t.Fatal("invalid authoritative bundle left signer ready")
			}
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			if _, err := m.sign(&certv1.PodCertificateRequest{}, pub, "service", nil); err == nil {
				t.Fatal("issued despite invalid authoritative trust")
			}
		})
	}
}

// TestRetainedSignerRenewsWithoutCandidate verifies renewal and outage readiness using the retained key.
func TestRetainedSignerRenewsWithoutCandidate(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := certv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	path := filepath.Join(t.TempDir(), "ca.pem")
	key := writePKCS8Key(t, path)
	root, err := newRoot(key, time.Now().AddDate(-9, -6, 0))
	if err != nil {
		t.Fatal(err)
	}
	bundle := encodeRoots([]*x509.Certificate{root})
	obj := &certv1.ClusterTrustBundle{ObjectMeta: metav1.ObjectMeta{Name: BundleName}, Spec: certv1.ClusterTrustBundleSpec{SignerName: SignerName, TrustBundle: bundle}}
	if err := c.Create(ctx, obj); err != nil {
		t.Fatal(err)
	}
	m := &Manager{client: c, reader: c, cfg: Config{TrustDomain: "k8s.example", CAPath: path}, active: &signingPair{key: key, cert: root, bundle: bundle}, canSign: true, ready: true}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	m.reader = unavailableReader{Reader: c}
	m.reconcileCA(ctx)
	if m.Ready(nil) == nil || !m.canSign {
		t.Fatal("API outage must mark unready while retaining valid issuance")
	}
	m.reader = c
	m.reconcileCA(ctx)
	if m.Ready(nil) != nil || !m.active.key.Equal(key) || !m.active.cert.NotAfter.After(root.NotAfter) {
		t.Fatal("retained signer did not renew and recover")
	}
	if err := c.Get(ctx, types.NamespacedName{Name: BundleName}, obj); err != nil {
		t.Fatal(err)
	}
	roots, err := parseRoots(obj.Spec.TrustBundle)
	if err != nil || len(roots) != 2 {
		t.Fatalf("renewal did not retain overlapping roots: count=%d error=%v", len(roots), err)
	}
	if obj.Spec.TrustBundle != m.active.bundle {
		t.Fatal("renewed signer activated before publication")
	}
	// Even during a later API outage, insufficient retained validity disables issuance.
	m.active = &signingPair{key: key, cert: &x509.Certificate{NotAfter: time.Now().Add(time.Hour)}, bundle: bundle}
	m.reader = unavailableReader{Reader: c}
	m.reconcileCA(ctx)
	if m.Ready(nil) == nil || m.canSign {
		t.Fatal("insufficient retained validity allowed issuance")
	}
}

type unavailableReader struct{ client.Reader }

func (r unavailableReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("API unavailable")
}

// writePKCS8Key persists pkcs8 key with the required encoding and permissions.
func writePKCS8Key(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return key
}

// TestSPIFFEAndServiceCertificateContracts verifies both supported leaf identities.
func TestSPIFFEAndServiceCertificateContracts(t *testing.T) {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	root, err := newRoot(caKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{cfg: Config{TrustDomain: "k8s.example"}, active: &signingPair{key: caKey, cert: root}, canSign: true, ready: true}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	p := &certv1.PodCertificateRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Generation: 7}, Spec: certv1.PodCertificateRequestSpec{ServiceAccountName: "api"}}

	spiffe, err := m.sign(p, pub, "spiffe", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := parseLeaf(t, spiffe.CertificateChain)
	if len(c.URIs) != 1 || c.URIs[0].String() != "spiffe://k8s.example/ns/payments/sa/api" || len(c.DNSNames) != 0 || len(c.ExtKeyUsage) != 2 {
		t.Fatalf("unexpected SPIFFE certificate: %+v", c)
	}
	if c.Subject.String() != "" || c.SerialNumber.Sign() <= 0 || c.NotAfter.Sub(c.NotBefore) > maxLifetime {
		t.Fatal("leaf invariant violated")
	}

	a := &authorization{dns: []string{"web", "web.payments", "web.payments.svc", "web.payments.svc.cluster.local"}}
	service, err := m.sign(p, pub, "service", a)
	if err != nil {
		t.Fatal(err)
	}
	c = parseLeaf(t, service.CertificateChain)
	if len(c.URIs) != 0 || len(c.DNSNames) != 4 || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("unexpected service certificate: %+v", c)
	}
}

// TestOperatorServingCertificateGenerationAndRotation covers fixed endpoint key-pair lifecycle.
func TestOperatorServingCertificateGenerationAndRotation(t *testing.T) {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	root, err := newRoot(caKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := ServingCertificate{
		Name:     "aggregated-api",
		CertFile: dir + "/tls.crt",
		KeyFile:  dir + "/tls.key",
		DNSNames: []string{"platform-podplane-operator-aggregated-api", "platform-podplane-operator-aggregated-api.platform-podplane-operator.svc.cluster.local"},
	}
	now := time.Now()
	if err := ensureServingCertificate(cfg, &signingPair{key: caKey, cert: root}, now); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseServingKeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cert.DNSNames, cfg.DNSNames) || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || cert.CheckSignatureFrom(root) != nil {
		t.Fatalf("unexpected serving certificate: %+v", cert)
	}
	if cert.NotAfter.Sub(cert.NotBefore) > maxLifetime {
		t.Fatalf("serving lifetime = %s", cert.NotAfter.Sub(cert.NotBefore))
	}
	if err := ensureServingCertificate(cfg, &signingPair{key: caKey, cert: root}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := os.ReadFile(cfg.CertFile)
	if !slices.Equal(certPEM, unchanged) {
		t.Fatal("current serving certificate was replaced")
	}
	if err := ensureServingCertificate(cfg, &signingPair{key: caKey, cert: root}, cert.NotAfter.Add(-servingRefreshBefore+time.Second)); err != nil {
		t.Fatal(err)
	}
	rotated, _ := os.ReadFile(cfg.CertFile)
	if slices.Equal(certPEM, rotated) {
		t.Fatal("serving certificate did not rotate before expiry")
	}
	rotatedKey, _ := os.ReadFile(cfg.KeyFile)
	if !slices.Equal(keyPEM, rotatedKey) {
		t.Fatal("serving private key changed during certificate renewal")
	}
	info, err := os.Stat(cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("serving key mode = %o", info.Mode().Perm())
	}
}

// TestWriteServingPairPublishesCompleteGenerations verifies stable public paths and bounded retention.
func TestWriteServingPairPublishesCompleteGenerations(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	current := filepath.Join(dir, ".serving-"+servingPairID(certFile, keyFile)+"-current")
	if err := writeServingPair(certFile, []byte("certificate one"), keyFile, []byte("private key")); err != nil {
		t.Fatal(err)
	}
	first, err := os.Readlink(current)
	if err != nil {
		t.Fatal(err)
	}
	for path, name := range map[string]string{certFile: "tls.crt", keyFile: "tls.key"} {
		link, err := os.Readlink(path)
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(filepath.Base(current), name); link != want {
			t.Fatalf("%s link = %q, want %q", name, link, want)
		}
	}
	if err := writeServingPair(certFile, []byte("certificate two"), keyFile, []byte("private key")); err != nil {
		t.Fatal(err)
	}
	second, err := os.Readlink(current)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("serving generation did not change")
	}
	if got, _ := os.ReadFile(certFile); string(got) != "certificate two" {
		t.Fatalf("certificate = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, first)); err != nil {
		t.Fatalf("previous generation was not retained: %v", err)
	}
	if err := writeServingPair(certFile, []byte("certificate three"), keyFile, []byte("private key")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, first)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale generation still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, second)); err != nil {
		t.Fatalf("previous generation was not retained: %v", err)
	}
}

// parseLeaf decodes the first certificate in an issued test chain.
func parseLeaf(t *testing.T, s string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		t.Fatal("missing PEM")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
