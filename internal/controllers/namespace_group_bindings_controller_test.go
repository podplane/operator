// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNamespaceGroupBindingsGrantsTenantNamespacesOnly(t *testing.T) {
	cases := map[string]bool{
		"default":         true,
		"platformer":      true,
		"kubed":           true,
		"platform-cilium": false,
		"kube-system":     false,
	}
	for name, tenant := range cases {
		r := namespaceGroupBindingsReconciler(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
		reconcileNamespace(t, r, name)
		got := roleBindings(t, r, name)
		if !tenant {
			if len(got) != 0 {
				t.Fatalf("%s: got RoleBindings %v, want none", name, got)
			}
			continue
		}
		want := map[string]string{
			"podplane-managers":  "admin podplane:managers",
			"podplane-operators": "edit podplane:operators",
			"podplane-editors":   "edit podplane:editors",
			"podplane-viewers":   "view podplane:viewers",
		}
		if len(got) != len(want) {
			t.Fatalf("%s: got RoleBindings %v, want %v", name, got, want)
		}
		for bindingName, grant := range want {
			if got[bindingName] != grant {
				t.Fatalf("%s/%s grants %q, want %q", name, bindingName, got[bindingName], grant)
			}
		}
	}
}

func TestNamespaceGroupBindingsRestrictedRemovesOnlyManagedBindings(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{RestrictedNamespaceLabel: "true"}}}
	managed := groupRoleBinding("team-a", "podplane-editors", "podplane:editors", "edit")
	explicit := groupRoleBinding("team-a", "team-a-editors", "team-a", "edit")
	explicit.Labels = nil
	r := namespaceGroupBindingsReconciler(t, ns, managed, explicit)

	reconcileNamespace(t, r, "team-a")

	got := roleBindings(t, r, "team-a")
	if len(got) != 1 || got["team-a-editors"] != "edit team-a" {
		t.Fatalf("got RoleBindings %v, want only the explicit binding", got)
	}
}

func TestNamespaceGroupBindingsRepairsDrift(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}}
	wrongRole := groupRoleBinding("team-a", "podplane-viewers", "podplane:viewers", "admin")
	extraSubject := groupRoleBinding("team-a", "podplane-editors", "podplane:editors", "edit")
	extraSubject.Subjects = append(extraSubject.Subjects, rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: "attacker"})
	r := namespaceGroupBindingsReconciler(t, ns, wrongRole, extraSubject)

	reconcileNamespace(t, r, "team-a")

	got := roleBindings(t, r, "team-a")
	if got["podplane-viewers"] != "view podplane:viewers" {
		t.Fatalf("podplane-viewers grants %q, want view", got["podplane-viewers"])
	}
	if got["podplane-editors"] != "edit podplane:editors" {
		t.Fatalf("podplane-editors grants %q, want only podplane:editors", got["podplane-editors"])
	}
}

func TestNamespaceGroupBindingsLeavesUnmanagedNameConflict(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}}
	unmanaged := groupRoleBinding("team-a", "podplane-editors", "someone-else", "view")
	unmanaged.Labels = nil
	r := namespaceGroupBindingsReconciler(t, ns, unmanaged)

	reconcileNamespace(t, r, "team-a")

	got := roleBindings(t, r, "team-a")
	if got["podplane-editors"] != "view someone-else" {
		t.Fatalf("unmanaged podplane-editors grants %q, want it unchanged", got["podplane-editors"])
	}
	if got["podplane-viewers"] != "view podplane:viewers" {
		t.Fatalf("podplane-viewers grants %q, want view", got["podplane-viewers"])
	}
}

// namespaceGroupBindingsReconciler returns a reconciler backed by a fake client holding objs.
func namespaceGroupBindingsReconciler(t *testing.T, objs ...client.Object) *NamespaceGroupBindingsReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return &NamespaceGroupBindingsReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()}
}

// reconcileNamespace reconciles one namespace and fails on error.
func reconcileNamespace(t *testing.T, r *NamespaceGroupBindingsReconciler, name string) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
		t.Fatalf("Reconcile %s: %v", name, err)
	}
}

// roleBindings returns each RoleBinding in namespace as "<role> <subjects>".
func roleBindings(t *testing.T, r *NamespaceGroupBindingsReconciler, namespace string) map[string]string {
	t.Helper()
	var list rbacv1.RoleBindingList
	if err := r.List(context.Background(), &list, client.InNamespace(namespace)); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, rb := range list.Items {
		names := []string{}
		for _, s := range rb.Subjects {
			names = append(names, s.Name)
		}
		sort.Strings(names)
		grant := rb.RoleRef.Name
		for _, n := range names {
			grant += " " + n
		}
		got[rb.Name] = grant
	}
	return got
}
