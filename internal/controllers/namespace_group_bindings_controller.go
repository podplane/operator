// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	// NamespaceGroupBindingLabel marks RoleBindings owned by the namespace access controller.
	NamespaceGroupBindingLabel = "rbac.podplane.dev/managed"
	// RestrictedNamespaceLabel opts a tenant namespace out of default group access.
	RestrictedNamespaceLabel = "rbac.podplane.dev/restricted"
)

// namespaceGroupBindings lists the default group grants in every tenant namespace.
var namespaceGroupBindings = []struct{ name, group, role string }{
	{"podplane-managers", "podplane:managers", "admin"},
	{"podplane-operators", "podplane:operators", "edit"},
	{"podplane-editors", "podplane:editors", "edit"},
	{"podplane-viewers", "podplane:viewers", "view"},
}

// NamespaceGroupBindingsReconciler grants default Podplane groups access to tenant namespaces.
type NamespaceGroupBindingsReconciler struct {
	client.Client
}

// TenantNamespace reports whether ns receives default Podplane group access.
func TenantNamespace(ns *corev1.Namespace) bool {
	if strings.HasPrefix(ns.Name, "kube-") || strings.HasPrefix(ns.Name, "platform-") {
		return false
	}
	return ns.Labels[RestrictedNamespaceLabel] != "true"
}

// Reconcile converges the managed RoleBindings in one namespace.
func (r *NamespaceGroupBindingsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: req.Name}, &ns); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !ns.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	desired := map[string]*rbacv1.RoleBinding{}
	if TenantNamespace(&ns) {
		for _, a := range namespaceGroupBindings {
			desired[a.name] = groupRoleBinding(ns.Name, a.name, a.group, a.role)
		}
	}
	var existing rbacv1.RoleBindingList
	if err := r.List(ctx, &existing, client.InNamespace(ns.Name), client.MatchingLabels{NamespaceGroupBindingLabel: "true"}); err != nil {
		return ctrl.Result{}, err
	}
	for i := range existing.Items {
		current := &existing.Items[i]
		want, ok := desired[current.Name]
		// roleRef is immutable, so a changed role requires recreation.
		if !ok || current.RoleRef != want.RoleRef {
			if err := r.Delete(ctx, current); client.IgnoreNotFound(err) != nil {
				return ctrl.Result{}, err
			}
			continue
		}
		delete(desired, current.Name)
		if apiequality.Semantic.DeepEqual(current.Subjects, want.Subjects) {
			continue
		}
		current.Subjects = want.Subjects
		if err := r.Update(ctx, current); err != nil {
			return ctrl.Result{}, err
		}
	}
	for _, rb := range desired {
		err := r.Create(ctx, rb)
		if apierrors.IsAlreadyExists(err) {
			// An unmanaged RoleBinding owns this name; leave it alone.
			ctrl.LoggerFrom(ctx).Info("skipping RoleBinding not managed by Podplane", "namespace", rb.Namespace, "name", rb.Name)
			continue
		}
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// groupRoleBinding returns a managed RoleBinding granting group the ClusterRole role.
func groupRoleBinding(namespace, name, group, role string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{NamespaceGroupBindingLabel: "true", "app.kubernetes.io/managed-by": "podplane"},
		},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role},
		Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: group}},
	}
}

// SetupWithManager registers the reconciler. The manager cache should select
// RoleBindings by NamespaceGroupBindingLabel so that only managed bindings are watched.
func (r *NamespaceGroupBindingsReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("namespace-group-bindings").
		For(&corev1.Namespace{}).
		Watches(&rbacv1.RoleBinding{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
			return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: obj.GetNamespace()}}}
		})).
		Complete(r)
}
