// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

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
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SecretProviderBindingReconciler owns generated SecretProviderClass objects.
type SecretProviderBindingReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Renderer Renderer
}

// Reconcile creates or updates the SecretProviderClass for a binding.
func (r *SecretProviderBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var binding secretsv1beta1.SecretProviderBinding
	if err := r.Get(ctx, req.NamespacedName, &binding); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err := r.syncToKubernetesSecretsAllowed(ctx, &binding); err != nil {
		return ctrl.Result{}, r.setCondition(ctx, &binding, "Ready", metav1.ConditionFalse, "Invalid", err.Error())
	}
	desired, status, err := r.Renderer.Render(&binding)
	if err != nil {
		return ctrl.Result{}, r.setCondition(ctx, &binding, "Ready", metav1.ConditionFalse, "Invalid", err.Error())
	}
	var existing unstructured.Unstructured
	existing.SetGroupVersionKind(SecretProviderClassGVK)
	err = r.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: req.Name}, &existing)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, desired); err != nil {
			return ctrl.Result{}, err
		}
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		if !ownedBy(&existing, &binding) {
			return ctrl.Result{}, r.setCondition(ctx, &binding, "Ready", metav1.ConditionFalse, "Conflict", "SecretProviderClass exists and is not owned by this SecretProviderBinding")
		}
		if secretProviderClassChanged(&existing, desired) {
			desired.SetResourceVersion(existing.GetResourceVersion())
			if err := r.Update(ctx, desired); err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	status.Conditions = append([]metav1.Condition(nil), binding.Status.Conditions...)
	apiMeta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled", Message: "SecretProviderClass reconciled", ObservedGeneration: binding.Generation, LastTransitionTime: metav1.Now()})
	if apiequality.Semantic.DeepEqual(binding.Status, status) {
		return ctrl.Result{}, nil
	}
	binding.Status = status
	return ctrl.Result{}, r.Status().Update(ctx, &binding)
}

// syncToKubernetesSecretsAllowed enforces opt-in gates for Kubernetes Secret persistence.
func (r *SecretProviderBindingReconciler) syncToKubernetesSecretsAllowed(ctx context.Context, b *secretsv1beta1.SecretProviderBinding) error {
	if len(b.Spec.SyncToKubernetesSecrets) == 0 {
		return nil
	}
	if !r.Renderer.AllowSyncToKubernetesSecrets {
		return fmt.Errorf("syncToKubernetesSecrets is disabled by operator configuration")
	}
	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: b.Namespace}, &ns); err != nil {
		return err
	}
	if ns.GetAnnotations()[SyncToKubernetesSecretsAnnotation] != "true" {
		return fmt.Errorf("namespace %q must be annotated with %s=true to use syncToKubernetesSecrets", b.Namespace, SyncToKubernetesSecretsAnnotation)
	}
	return nil
}

// setCondition updates a binding status condition.
func (r *SecretProviderBindingReconciler) setCondition(ctx context.Context, b *secretsv1beta1.SecretProviderBinding, typ string, status metav1.ConditionStatus, reason, msg string) error {
	old := b.Status.DeepCopy()
	apiMeta.SetStatusCondition(&b.Status.Conditions, metav1.Condition{Type: typ, Status: status, Reason: reason, Message: msg, ObservedGeneration: b.Generation, LastTransitionTime: metav1.Now()})
	if old != nil && apiequality.Semantic.DeepEqual(*old, b.Status) {
		return nil
	}
	return r.Status().Update(ctx, b)
}

// secretProviderClassChanged reports whether the owned fields rendered by this controller differ.
func secretProviderClassChanged(existing, desired *unstructured.Unstructured) bool {
	if !apiequality.Semantic.DeepEqual(existing.GetLabels(), desired.GetLabels()) {
		return true
	}
	if !apiequality.Semantic.DeepEqual(existing.GetAnnotations(), desired.GetAnnotations()) {
		return true
	}
	if !apiequality.Semantic.DeepEqual(existing.GetOwnerReferences(), desired.GetOwnerReferences()) {
		return true
	}
	return !apiequality.Semantic.DeepEqual(existing.Object["spec"], desired.Object["spec"])
}

// ownedBy reports whether obj is controlled by b.
func ownedBy(obj metav1.Object, b *secretsv1beta1.SecretProviderBinding) bool {
	for _, o := range obj.GetOwnerReferences() {
		if o.APIVersion == secretsv1beta1.GroupVersion.String() && o.Kind == "SecretProviderBinding" && o.Name == b.Name && o.UID == b.UID {
			return true
		}
	}
	return false
}

// SetupWithManager registers the reconciler with a controller manager.
func (r *SecretProviderBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.SecretProviderBinding{}).
		Owns(secretProviderClassObject()).
		Complete(r)
}

// secretProviderClassObject returns an unstructured SecretProviderClass watch type.
func secretProviderClassObject() *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(SecretProviderClassGVK)
	return obj
}
