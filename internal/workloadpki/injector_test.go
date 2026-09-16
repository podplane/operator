// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package workloadpki

import (
	"context"
	"encoding/base64"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// staticBundle is an immutable test CA bundle source.
type staticBundle []byte

// Bundle returns the test CA bundle.
func (b staticBundle) Bundle() ([]byte, error) { return b, nil }

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
			obj := &unstructured.Unstructured{Object: map[string]any{
				"metadata": map[string]any{
					"name":        "example",
					"annotations": map[string]any{InjectCAFromAnnotation: tt.source},
				},
				"spec": map[string]any{"service": map[string]any{
					"namespace": "example",
					"name":      "webhook",
				}},
			}}
			obj.SetAPIVersion("apiregistration.k8s.io/v1")
			obj.SetKind("APIService")
			service := &unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{
				"namespace": "example",
				"name":      "webhook",
			}}}
			service.SetAPIVersion("v1")
			service.SetKind("Service")
			c := fake.NewClientBuilder().WithObjects(obj, service).Build()
			if err := NewInjector(c, c, staticBundle("roots")).inject(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := &unstructured.Unstructured{}
			got.SetAPIVersion("apiregistration.k8s.io/v1")
			got.SetKind("APIService")
			if err := c.Get(context.Background(), types.NamespacedName{Name: "example"}, got); err != nil {
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

// TestInjectorRequiresReferencedService prevents injection into stale endpoints.
func TestInjectorRequiresReferencedService(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{
			"name":        "example",
			"annotations": map[string]any{InjectCAFromAnnotation: workloadCASource},
		},
		"spec": map[string]any{"service": map[string]any{
			"namespace": "example",
			"name":      "missing",
		}},
	}}
	obj.SetAPIVersion("apiregistration.k8s.io/v1")
	obj.SetKind("APIService")
	c := fake.NewClientBuilder().WithObjects(obj).Build()
	if err := NewInjector(c, c, staticBundle("roots")).inject(context.Background()); err == nil {
		t.Fatal("inject accepted a missing Service")
	}
}

// TestSetInjectedBundle updates supported extension resources and reports drift.
func TestSetInjectedBundle(t *testing.T) {
	bundle := []byte("workload roots")
	want := base64.StdEncoding.EncodeToString(bundle)
	tests := []struct {
		kind   string
		object map[string]any
		path   []string
	}{
		{
			kind:   "APIService",
			object: map[string]any{"spec": map[string]any{"service": map[string]any{"namespace": "operator", "name": "api"}}},
			path:   []string{"spec", "caBundle"},
		},
		{
			kind: "CustomResourceDefinition",
			object: map[string]any{"spec": map[string]any{"conversion": map[string]any{
				"strategy": "Webhook",
				"webhook": map[string]any{"clientConfig": map[string]any{
					"service": map[string]any{"namespace": "capi", "name": "webhook"},
				}},
			}}},
			path: []string{"spec", "conversion", "webhook", "clientConfig", "caBundle"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			obj := &unstructured.Unstructured{Object: tt.object}
			obj.SetKind(tt.kind)
			changed, err := setInjectedBundle(obj, bundle)
			if err != nil || !changed {
				t.Fatalf("setInjectedBundle() = %v, %v", changed, err)
			}
			got, found, err := unstructured.NestedString(obj.Object, tt.path...)
			if err != nil || !found || got != want {
				t.Fatalf("caBundle = %q, %v, %v", got, found, err)
			}
			changed, err = setInjectedBundle(obj, bundle)
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
	changed, err := setInjectedBundle(obj, []byte("roots"))
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

// TestServiceReferencesRejectsURLs requires annotated webhooks to use in-cluster Services.
func TestServiceReferencesRejectsURLs(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"webhooks": []any{map[string]any{"clientConfig": map[string]any{
			"url": "https://webhook.example",
		}}},
	}}
	obj.SetKind("MutatingWebhookConfiguration")
	if _, err := serviceReferences(obj); err == nil {
		t.Fatal("serviceReferences accepted a URL")
	}
}
