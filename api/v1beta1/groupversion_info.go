// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion identifies the secrets API group and version.
var GroupVersion = schema.GroupVersion{Group: "secrets.podplane.dev", Version: "v1beta1"}

// SchemeBuilder registers secrets API types.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme adds secrets API types to a scheme.
var AddToScheme = SchemeBuilder.AddToScheme

// addKnownTypes registers this package's API objects.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion, &SecretProviderBinding{}, &SecretProviderBindingList{})
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
