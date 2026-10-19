// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package extensionserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/kube-openapi/pkg/validation/spec"

	"github.com/podplane/operator/internal/secretsapi"
)

// TestServerServesOpenAPI verifies discoverable schemas and public-key reads over authenticated HTTPS.
func TestServerServesOpenAPI(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	for path, data := range map[string][]byte{certFile: certPEM, keyFile: keyPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	authConfig := corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "extension-apiserver-authentication"},
		Data: map[string]string{
			"requestheader-client-ca-file":       string(certPEM),
			"requestheader-username-headers":     `["X-Remote-User"]`,
			"requestheader-group-headers":        `["X-Remote-Group"]`,
			"requestheader-extra-headers-prefix": `["X-Remote-Extra-"]`,
			"requestheader-allowed-names":        `[]`,
		},
	}
	kubeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("watch") == "true" {
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "ADDED", "object": authConfig})
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "BOOKMARK", "object": corev1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
				ObjectMeta: metav1.ObjectMeta{ResourceVersion: "1", Annotations: map[string]string{"k8s.io/initial-events-end": "true"}},
			}})
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system/configmaps/extension-apiserver-authentication":
			_ = json.NewEncoder(w).Encode(authConfig)
		case "/api/v1/namespaces/kube-system/configmaps":
			_ = json.NewEncoder(w).Encode(corev1.ConfigMapList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMapList"}, Items: []corev1.ConfigMap{authConfig}})
		case "/apis/authorization.k8s.io/v1/subjectaccessreviews":
			_ = json.NewEncoder(w).Encode(authv1.SubjectAccessReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"}, Status: authv1.SubjectAccessReviewStatus{Allowed: true}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(kubeAPI.Close)
	kube, err := kubernetes.NewForConfig(&restclient.Config{Host: kubeAPI.URL})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secretsapi.NewKeyRing(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Kube: kube, Secrets: &secretsapi.KeyspaceStorage{}, KeyStore: &secretsapi.PublicKeyStorage{Keys: keys}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := server.Run(ctx, Options{Addr: addr, CertFile: certFile, KeyFile: keyFile, RestConfig: &restclient.Config{Host: "https://" + addr}}); err != nil {
		t.Fatal(err)
	}
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	get := func(t *testing.T, path string, result any) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Remote-User", "openapi-reader")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: HTTP %d", path, resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
	}
	var index struct {
		Paths map[string]struct{ ServerRelativeURL string }
	}
	get(t, "/openapi/v3", &index)
	v3Path := index.Paths["apis/"+secretsapi.GroupVersion].ServerRelativeURL
	if v3Path == "" {
		t.Fatal("OpenAPI v3 index does not advertise the secrets API")
	}
	for _, path := range []string{"/openapi/v2", v3Path} {
		t.Run(path, func(t *testing.T) {
			var document struct {
				Definitions map[string]spec.Schema
				Components  struct{ Schemas map[string]spec.Schema }
			}
			get(t, path, &document)
			schemas := document.Definitions
			if schemas == nil {
				schemas = document.Components.Schemas
			}
			resolve := func(schema spec.Schema) spec.Schema {
				for {
					if len(schema.AllOf) == 1 {
						schema = schema.AllOf[0]
					}
					ref := schema.Ref.String()
					if ref == "" {
						return schema
					}
					name := strings.NewReplacer("~1", "/", "~0", "~").Replace(ref[strings.LastIndex(ref, "/")+1:])
					var ok bool
					schema, ok = schemas[name]
					if !ok {
						t.Fatalf("unresolved schema reference %s", ref)
					}
				}
			}
			for _, check := range []struct{ kind, field, wantType string }{
				{"PublicKey", "metadata.name", "string"},
				{"PublicKey", "spec.publicKey", "string"},
				{"SecretProviderKeyspace", "spec.entries.[].encryptedValue.ciphertext", "string"},
				{"SecretProviderKeyspace", "status.entries.[].restoreUntil", "string"},
			} {
				var root *spec.Schema
				for _, schema := range schemas {
					gvks, _ := json.Marshal(schema.Extensions["x-kubernetes-group-version-kind"])
					var kinds []struct{ Group, Version, Kind string }
					if err := json.Unmarshal(gvks, &kinds); err != nil {
						t.Fatal(err)
					}
					for _, gvk := range kinds {
						if gvk.Group == secretsapi.SchemeGroupVersion.Group && gvk.Version == "v1beta1" && gvk.Kind == check.kind {
							root = &schema
						}
					}
				}
				if root == nil {
					t.Fatalf("no schema advertises secrets API kind %s", check.kind)
				}
				schema := *root
				for _, field := range strings.Split(check.field, ".") {
					schema = resolve(schema)
					if field == "[]" {
						if schema.Items == nil || schema.Items.Schema == nil {
							t.Fatalf("%s.%s: missing array items", check.kind, check.field)
						}
						schema = *schema.Items.Schema
					} else {
						schema = schema.Properties[field]
					}
				}
				schema = resolve(schema)
				if len(schema.Type) != 1 || schema.Type[0] != check.wantType {
					t.Errorf("%s.%s: type = %v, want %s", check.kind, check.field, schema.Type, check.wantType)
				}
			}
		})
	}
	var publicKey secretsapi.PublicKey
	get(t, "/apis/"+secretsapi.GroupVersion+"/publickeys/latest", &publicKey)
	if publicKey.Spec.PublicKey != keys.PublicKey().Spec.PublicKey {
		t.Fatal("public key response changed")
	}
}
