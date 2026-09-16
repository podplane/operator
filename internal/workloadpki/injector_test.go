// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package workloadpki

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// missingInjectionTargetReader records named reads and rejects list operations.
type missingInjectionTargetReader struct {
	gets int
}

// Get records one named read and reports the target absent.
func (r *missingInjectionTargetReader) Get(_ context.Context, key client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	r.gets++
	return apierrors.NewNotFound(schema.GroupResource{Resource: "injection target"}, key.Name)
}

// List rejects cluster-wide discovery.
func (*missingInjectionTargetReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("unexpected list")
}

// staticBundle is an immutable test CA bundle source.
type staticBundle []byte

// Bundle returns the test CA bundle.
func (b staticBundle) Bundle() ([]byte, error) { return b, nil }

// TestInjectorGetsOnlyNamedTargets verifies reconciliation performs no cluster-wide discovery.
func TestInjectorGetsOnlyNamedTargets(t *testing.T) {
	reader := &missingInjectionTargetReader{}
	injector := NewInjector(nil, reader, staticBundle("roots"))
	if err := injector.inject(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reader.gets != len(injectionTargets) {
		t.Fatalf("GET count = %d, want %d", reader.gets, len(injectionTargets))
	}
}

// TestInjectorAcceptsOnlyWorkloadSource verifies injection source aliases are closed.
func TestInjectorAcceptsOnlyWorkloadSource(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   bool
	}{
		{"workload", workloadCASource, true},
		{"signer name", SignerName, false},
		{"unknown", "other", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			target := injectionTargets[0]
			obj := &unstructured.Unstructured{Object: map[string]any{
				"metadata": map[string]any{
					"name":        target.name,
					"annotations": map[string]any{InjectCAFromAnnotation: tt.source},
				},
				"spec": map[string]any{"service": map[string]any{
					"namespace": target.service.Namespace,
					"name":      target.service.Name,
				}},
			}}
			obj.SetGroupVersionKind(target.gvk)
			c := fake.NewClientBuilder().WithObjects(obj).Build()
			if err := NewInjector(c, c, staticBundle("roots")).inject(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := &unstructured.Unstructured{}
			got.SetGroupVersionKind(target.gvk)
			if err := c.Get(context.Background(), client.ObjectKey{Name: target.name}, got); err != nil {
				t.Fatal(err)
			}
			_, found, err := unstructured.NestedString(got.Object, "spec", "caBundle")
			if err != nil {
				t.Fatal(err)
			}
			if found != tt.want {
				t.Fatalf("caBundle present = %t, want %t", found, tt.want)
			}
		})
	}
}

// TestSetInjectedBundle updates supported extension resources and reports drift.
func TestSetInjectedBundle(t *testing.T) {
	bundle := []byte("workload roots")
	want := base64.StdEncoding.EncodeToString(bundle)
	tests := []struct {
		kind    string
		object  map[string]any
		path    []string
		service types.NamespacedName
	}{
		{
			kind:    "APIService",
			object:  map[string]any{"spec": map[string]any{"service": map[string]any{"namespace": "operator", "name": "api"}}},
			path:    []string{"spec", "caBundle"},
			service: types.NamespacedName{Namespace: "operator", Name: "api"},
		},
		{
			kind: "CustomResourceDefinition",
			object: map[string]any{"spec": map[string]any{"conversion": map[string]any{
				"strategy": "Webhook",
				"webhook": map[string]any{"clientConfig": map[string]any{
					"service": map[string]any{"namespace": "capi", "name": "webhook"},
				}},
			}}},
			path:    []string{"spec", "conversion", "webhook", "clientConfig", "caBundle"},
			service: types.NamespacedName{Namespace: "capi", Name: "webhook"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			obj := &unstructured.Unstructured{Object: tt.object}
			obj.SetKind(tt.kind)
			changed, err := setInjectedBundle(obj, bundle, tt.service)
			if err != nil || !changed {
				t.Fatalf("setInjectedBundle() = %v, %v", changed, err)
			}
			got, found, err := unstructured.NestedString(obj.Object, tt.path...)
			if err != nil || !found || got != want {
				t.Fatalf("caBundle = %q, %v, %v", got, found, err)
			}
			changed, err = setInjectedBundle(obj, bundle, tt.service)
			if err != nil || changed {
				t.Fatalf("idempotent set = %v, %v", changed, err)
			}
		})
	}
}

// TestSetInjectedBundleUpdatesAllWebhooks updates every client configuration.
func TestSetInjectedBundleUpdatesAllWebhooks(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"webhooks": []any{
			map[string]any{"name": "one", "clientConfig": map[string]any{"service": map[string]any{"namespace": "capi", "name": "webhook"}}},
			map[string]any{"name": "two", "clientConfig": map[string]any{"caBundle": "old", "service": map[string]any{"namespace": "capi", "name": "webhook"}}},
		},
	}}
	obj.SetKind("ValidatingWebhookConfiguration")
	changed, err := setInjectedBundle(obj, []byte("roots"), types.NamespacedName{Namespace: "capi", Name: "webhook"})
	if err != nil || !changed {
		t.Fatalf("setInjectedBundle() = %v, %v", changed, err)
	}
	webhooks, _, _ := unstructured.NestedSlice(obj.Object, "webhooks")
	want := base64.StdEncoding.EncodeToString([]byte("roots"))
	for _, entry := range webhooks {
		clientConfig := entry.(map[string]any)["clientConfig"].(map[string]any)
		if clientConfig["caBundle"] != want {
			t.Fatalf("caBundle = %v", clientConfig["caBundle"])
		}
	}
}

// TestSetInjectedBundleRejectsOtherServices prevents an allow-listed object from redirecting trust.
func TestSetInjectedBundleRejectsOtherServices(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"webhooks": []any{map[string]any{"clientConfig": map[string]any{
			"service": map[string]any{"namespace": "other", "name": "webhook"},
		}}},
	}}
	obj.SetKind("MutatingWebhookConfiguration")
	if _, err := setInjectedBundle(obj, []byte("roots"), types.NamespacedName{Namespace: "capi", Name: "webhook"}); err == nil {
		t.Fatal("setInjectedBundle accepted another Service")
	}
}
