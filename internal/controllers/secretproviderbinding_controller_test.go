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
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestBindingProviderInheritance(t *testing.T) {
	for _, explicit := range []string{"", "aws-store"} {
		t.Run("provider="+explicit, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := secretsv1beta1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			binding := &secretsv1beta1.SecretProviderBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "team-a", UID: types.UID("binding-uid")},
				Spec: secretsv1beta1.SecretProviderBindingSpec{
					ProviderName: explicit,
					Items:        []secretsv1beta1.SecretProviderBindingItem{{Key: "password"}},
				},
			}
			r := &SecretProviderBindingReconciler{
				Client: fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(binding).WithObjects(binding).Build(),
				Renderer: Renderer{ClusterID: "cluster", Providers: map[string]ProviderConfig{
					"aws-store":    {Name: "aws-store", Kind: "aws"},
					"google-store": {Name: "google-store", Kind: "gcp", ProjectID: "project"},
				}},
			}
			request := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: binding.Namespace, Name: binding.Name}}
			for _, defaultProvider := range []string{"aws-store", "google-store", "aws-store"} {
				r.Renderer.DefaultProvider = defaultProvider
				if _, err := r.Reconcile(context.Background(), request); err != nil {
					t.Fatal(err)
				}
				var got secretsv1beta1.SecretProviderBinding
				if err := r.Get(context.Background(), request.NamespacedName, &got); err != nil {
					t.Fatal(err)
				}
				if !apiequality.Semantic.DeepEqual(got.Spec, binding.Spec) {
					t.Fatalf("reconciliation changed binding spec: %+v", got.Spec)
				}
				wantName := explicit
				if wantName == "" {
					wantName = defaultProvider
				}
				wantKind := "aws"
				if wantName == "google-store" {
					wantKind = "gcp"
				}
				if got.Status.Provider.Name != wantName || got.Status.Provider.Kind != wantKind || !apiMeta.IsStatusConditionTrue(got.Status.Conditions, "Ready") {
					t.Fatalf("default %q: incorrect binding status: %+v", defaultProvider, got.Status)
				}
				spc := secretProviderClassObject()
				if err := r.Get(context.Background(), request.NamespacedName, spc); err != nil {
					t.Fatal(err)
				}
				if kind, _, _ := unstructured.NestedString(spc.Object, "spec", "provider"); kind != wantKind {
					t.Fatalf("default %q: generated provider = %q, want %q", defaultProvider, kind, wantKind)
				}
			}
		})
	}
}

func TestBindingProviderResolutionErrors(t *testing.T) {
	for _, tc := range []struct{ name, explicit, defaultProvider, wantError string }{
		{"missing default", "", "", "no default secrets provider"},
		{"unknown default", "", "missing", `unknown provider "missing"`},
		{"invalid default", "", "not/a/provider", `unknown provider "not/a/provider"`},
		{"unknown explicit does not fall back", "missing", "aws-store", `unknown provider "missing"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := secretsv1beta1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			binding := &secretsv1beta1.SecretProviderBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "team-a"},
				Spec: secretsv1beta1.SecretProviderBindingSpec{
					ProviderName: tc.explicit,
					Items:        []secretsv1beta1.SecretProviderBindingItem{{Key: "password"}},
				},
			}
			r := &SecretProviderBindingReconciler{
				Client: fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(binding).WithObjects(binding).Build(),
				Renderer: Renderer{ClusterID: "cluster", DefaultProvider: tc.defaultProvider, Providers: map[string]ProviderConfig{
					"aws-store": {Name: "aws-store", Kind: "aws"},
				}},
			}
			request := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: binding.Namespace, Name: binding.Name}}
			if _, err := r.Reconcile(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			var got secretsv1beta1.SecretProviderBinding
			if err := r.Get(context.Background(), request.NamespacedName, &got); err != nil {
				t.Fatal(err)
			}
			condition := apiMeta.FindStatusCondition(got.Status.Conditions, "Ready")
			if condition == nil || condition.Status != metav1.ConditionFalse || condition.Reason != "Invalid" || !strings.Contains(condition.Message, tc.wantError) {
				t.Fatalf("incorrect provider resolution condition: %+v", condition)
			}
			if err := r.Get(context.Background(), request.NamespacedName, secretProviderClassObject()); !apierrors.IsNotFound(err) {
				t.Fatalf("provider resolution failure should not create a SecretProviderClass: %v", err)
			}
			existing := secretProviderClassObject()
			existing.SetName(binding.Name)
			existing.SetNamespace(binding.Namespace)
			existing.Object["spec"] = map[string]any{"provider": "vault", "parameters": map[string]any{"objects": "previous"}}
			existing.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: secretsv1beta1.GroupVersion.String(), Kind: "SecretProviderBinding", Name: binding.Name, UID: binding.UID, Controller: ptr(true)}})
			if err := r.Create(context.Background(), existing); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			gotClass := secretProviderClassObject()
			if err := r.Get(context.Background(), request.NamespacedName, gotClass); err != nil {
				t.Fatal(err)
			}
			if !apiequality.Semantic.DeepEqual(gotClass.Object, existing.Object) {
				t.Fatal("provider resolution failure changed the existing SecretProviderClass")
			}
		})
	}
}

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

// TestRendererGoogleAuthentication checks that bindings use the shared provider
// identity while deriving their resource paths from the Kubernetes keyspace.
func TestRendererGoogleAuthentication(t *testing.T) {
	r := Renderer{ClusterID: "fallback", Providers: map[string]ProviderConfig{
		"google": {Name: "google", Kind: "gcp", ProjectID: "123", KeyPrefix: "cluster"},
	}}
	binding := &secretsv1beta1.SecretProviderBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "team-a"},
		Spec:       secretsv1beta1.SecretProviderBindingSpec{ProviderName: "google", Items: []secretsv1beta1.SecretProviderBindingItem{{Key: "password", Path: "database/password"}}},
	}
	spc, _, err := r.Render(binding)
	if err != nil {
		t.Fatal(err)
	}
	params, _, err := unstructured.NestedStringMap(spc.Object, "spec", "parameters")
	if err != nil {
		t.Fatal(err)
	}
	if params["auth"] != "provider-adc" || !strings.Contains(params["secrets"], "projects/123/secrets/cluster_team-a_api_password/versions/latest") || !strings.Contains(params["secrets"], "database/password") {
		t.Fatalf("incorrect shared-provider authentication or secret path: %v", params)
	}
	binding.Spec.Items[0].Key = "../other"
	if _, _, err := r.Render(binding); err == nil {
		t.Fatal("accepted a keyspace escape")
	}
}

func TestRendererVaultAuthentication(t *testing.T) {
	binding := &secretsv1beta1.SecretProviderBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "hello", Namespace: "default"},
		Spec: secretsv1beta1.SecretProviderBindingSpec{
			ProviderName: "local-fakevault",
			Items:        []secretsv1beta1.SecretProviderBindingItem{{Key: "api-key"}},
		},
	}
	for _, provider := range []struct{ kind, prefix string }{{"vault", "vault"}, {"openbao", "bao"}} {
		for _, auth := range []struct{ path, mount string }{
			{"", "kubernetes"},
			{"auth/k8s-jwt", "k8s-jwt"},
			{"/auth/team/kubernetes/", "team/kubernetes"},
		} {
			t.Run(provider.kind+"/"+auth.mount, func(t *testing.T) {
				renderer := Renderer{ClusterID: "default", Providers: map[string]ProviderConfig{
					"local-fakevault": {Name: "local-fakevault", Kind: provider.kind, Address: "https://10.0.2.15:19443/vault/default", CACert: "-----BEGIN CERTIFICATE-----\nlocal\n-----END CERTIFICATE-----", AuthPath: auth.path},
				}}
				spc, _, err := renderer.Render(binding)
				if err != nil {
					t.Fatalf("Render: %v", err)
				}
				params, ok, err := unstructured.NestedStringMap(spc.Object, "spec", "parameters")
				if err != nil || !ok {
					t.Fatalf("parameters = %v, %v", ok, err)
				}
				if got, want := params[provider.prefix+"CACertPath"], "/var/run/podplane/secrets-providers/local-fakevault/ca.crt"; got != want {
					t.Errorf("CA path = %q, want %q", got, want)
				}
				if got := params[provider.prefix+"AuthMountPath"]; got != auth.mount {
					t.Errorf("auth mount = %q, want %q", got, auth.mount)
				}
				if params["roleName"] != binding.Name {
					t.Errorf("role = %q, want binding role %q", params["roleName"], binding.Name)
				}
			})
		}
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
