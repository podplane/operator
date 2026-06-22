// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"strings"
	"testing"

	secretsv1beta1 "github.com/podplane/operator/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSecretProviderClassChangedIgnoresServerMetadata(t *testing.T) {
	binding := &secretsv1beta1.SecretProviderBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "namespace", UID: types.UID("uid")}}
	desired := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "secrets-store.csi.x-k8s.io/v1",
		"kind":       "SecretProviderClass",
		"metadata": map[string]any{
			"name":      "binding",
			"namespace": "namespace",
			"labels":    map[string]any{"app.kubernetes.io/managed-by": "podplane", BindingLabel: "binding"},
		},
		"spec": map[string]any{"provider": "aws", "parameters": map[string]any{"objects": "[]\n"}},
	}}
	desired.SetGroupVersionKind(SecretProviderClassGVK)
	desired.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: secretsv1beta1.GroupVersion.String(), Kind: "SecretProviderBinding", Name: binding.Name, UID: binding.UID, Controller: ptr(true), BlockOwnerDeletion: ptr(true)}})
	existing := desired.DeepCopy()
	existing.SetResourceVersion("123")
	existing.SetGeneration(4)
	existing.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "kube-apiserver"}})

	if secretProviderClassChanged(existing, desired) {
		t.Fatal("server-managed metadata should not force an update")
	}

	desired.Object["spec"] = map[string]any{"provider": "aws", "parameters": map[string]any{"objects": "changed\n"}}
	if !secretProviderClassChanged(existing, desired) {
		t.Fatal("spec changes must force an update")
	}
}

func TestSyncToKubernetesSecretsRequiresGlobalFlagAndNamespaceAnnotation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	binding := &secretsv1beta1.SecretProviderBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "namespace"},
		Spec:       secretsv1beta1.SecretProviderBindingSpec{SyncToKubernetesSecrets: []secretsv1beta1.KubernetesSecretSync{{SecretName: "secret", Data: []secretsv1beta1.KubernetesSecretSyncData{{FromKey: "key", Key: "key"}}}}},
	}
	ctx := context.Background()

	r := &SecretProviderBindingReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}
	if err := r.syncToKubernetesSecretsAllowed(ctx, binding); err == nil || !strings.Contains(err.Error(), "disabled by operator configuration") {
		t.Fatalf("disabled sync error = %v", err)
	}

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "namespace"}}
	r = &SecretProviderBindingReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build(), Renderer: Renderer{AllowSyncToKubernetesSecrets: true}}
	if err := r.syncToKubernetesSecretsAllowed(ctx, binding); err == nil || !strings.Contains(err.Error(), SyncToKubernetesSecretsAnnotation) {
		t.Fatalf("missing annotation error = %v", err)
	}

	ns.SetAnnotations(map[string]string{SyncToKubernetesSecretsAnnotation: "true"})
	r = &SecretProviderBindingReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build(), Renderer: Renderer{AllowSyncToKubernetesSecrets: true}}
	if err := r.syncToKubernetesSecretsAllowed(ctx, binding); err != nil {
		t.Fatalf("allowed sync error = %v", err)
	}
}
