// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsapi

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// SchemeGroupVersion is the served secrets API group and version.
var SchemeGroupVersion = schema.GroupVersion{Group: "secrets-api.podplane.dev", Version: "v1beta1"}

// GroupVersion is the served secrets API group and version string.
const GroupVersion = "secrets-api.podplane.dev/v1beta1"

// Algorithm is the supported client-side encryption envelope algorithm.
const Algorithm = "x25519-hkdf-sha256-aes-256-gcm"

// PublicKey is the aggregated API response for publickeys/latest.
type PublicKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              PublicKeySpec `json:"spec"`
}

// DeepCopyObject implements runtime.Object.
func (p *PublicKey) DeepCopyObject() runtime.Object {
	if p == nil {
		return nil
	}
	out := *p
	out.ObjectMeta = *p.ObjectMeta.DeepCopy()
	return &out
}

// PublicKeySpec carries the current encryption public key.
type PublicKeySpec struct {
	KeyID     string      `json:"keyID"`
	CreatedAt metav1.Time `json:"createdAt"`
	Algorithm string      `json:"algorithm"`
	PublicKey string      `json:"publicKey"`
}

// SecretProviderKeyspace is the aggregated API object for binding-scoped keys.
type SecretProviderKeyspace struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              SecretProviderKeyspaceSpec   `json:"spec,omitempty"`
	Status            SecretProviderKeyspaceStatus `json:"status,omitempty"`
}

// DeepCopyObject implements runtime.Object.
func (s *SecretProviderKeyspace) DeepCopyObject() runtime.Object {
	if s == nil {
		return nil
	}
	out := *s
	out.ObjectMeta = *s.ObjectMeta.DeepCopy()
	out.Spec.Entries = append([]SecretProviderKeyspaceEntry(nil), s.Spec.Entries...)
	for i := range out.Spec.Entries {
		if s.Spec.Entries[i].EncryptedValue != nil {
			ev := *s.Spec.Entries[i].EncryptedValue
			out.Spec.Entries[i].EncryptedValue = &ev
		}
	}
	out.Status.Entries = append([]SecretProviderKeyspaceStatusEntry(nil), s.Status.Entries...)
	for i := range out.Status.Entries {
		if s.Status.Entries[i].RestoreUntil != nil {
			t := s.Status.Entries[i].RestoreUntil.DeepCopy()
			out.Status.Entries[i].RestoreUntil = t
		}
	}
	return &out
}

// SecretProviderKeyspaceList is a list of SecretProviderKeyspace objects.
type SecretProviderKeyspaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecretProviderKeyspace `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (s *SecretProviderKeyspaceList) DeepCopyObject() runtime.Object {
	if s == nil {
		return nil
	}
	out := *s
	out.ListMeta = s.ListMeta
	out.Items = make([]SecretProviderKeyspace, len(s.Items))
	for i := range s.Items {
		out.Items[i] = *(s.Items[i].DeepCopyObject().(*SecretProviderKeyspace))
	}
	return &out
}

// SecretProviderKeyspaceSpec declares requested key operations.
type SecretProviderKeyspaceSpec struct {
	Entries []SecretProviderKeyspaceEntry `json:"entries"`
}

// SecretProviderKeyspaceEntry declares one key operation.
type SecretProviderKeyspaceEntry struct {
	Key            string          `json:"key"`
	Operation      string          `json:"operation"`
	EncryptedValue *EncryptedValue `json:"encryptedValue,omitempty"`
}

// EncryptedValue carries an encrypted secret value.
type EncryptedValue struct {
	KeyID      string `json:"keyID"`
	Algorithm  string `json:"algorithm"`
	Ciphertext string `json:"ciphertext"`
}

// SecretProviderKeyspaceStatus reports provider metadata and key states.
type SecretProviderKeyspaceStatus struct {
	Provider string                              `json:"provider"`
	Entries  []SecretProviderKeyspaceStatusEntry `json:"entries,omitempty"`
}

// SecretProviderKeyspaceStatusEntry reports one backend key state.
type SecretProviderKeyspaceStatusEntry struct {
	Key          string       `json:"key"`
	Status       string       `json:"status"`
	BackendPath  string       `json:"backendPath,omitempty"`
	RestoreUntil *metav1.Time `json:"restoreUntil,omitempty"`
}

// AddToScheme registers secrets API types with a runtime scheme.
func AddToScheme(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion, &PublicKey{}, &SecretProviderKeyspace{}, &SecretProviderKeyspaceList{})
	scheme.AddKnownTypes(schema.GroupVersion{Version: "v1"}, &metav1.CreateOptions{}, &metav1.DeleteOptions{}, &metav1.GetOptions{}, &metav1.ListOptions{}, &metav1.PatchOptions{}, &metav1.Status{}, &metav1.UpdateOptions{})
	scheme.AddKnownTypes(metav1.SchemeGroupVersion, &metav1.CreateOptions{}, &metav1.DeleteOptions{}, &metav1.GetOptions{}, &metav1.ListOptions{}, &metav1.PatchOptions{}, &metav1.Status{}, &metav1.UpdateOptions{})
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	metav1.AddToGroupVersion(scheme, metav1.SchemeGroupVersion)
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		return err
	}
	return nil
}
