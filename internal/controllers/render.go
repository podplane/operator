// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"fmt"
	"path"
	"strings"

	secretsv1beta1 "github.com/podplane/operator/api/v1beta1"
	"github.com/podplane/operator/internal/secretsbackend"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

// BindingLabel marks SecretProviderClass objects managed for a binding.
const BindingLabel = "secrets.podplane.dev/secret-provider-binding"

// SyncToKubernetesSecretsAnnotation enables syncToKubernetesSecrets in one namespace.
const SyncToKubernetesSecretsAnnotation = "secrets.podplane.dev/allow-sync-to-kubernetes-secrets"

// SecretProviderClassGVK identifies the Secrets Store CSI SecretProviderClass kind.
var SecretProviderClassGVK = schema.GroupVersionKind{Group: "secrets-store.csi.x-k8s.io", Version: "v1", Kind: "SecretProviderClass"}

// Renderer builds SecretProviderClass objects from SecretProviderBinding resources.
type Renderer struct {
	ClusterID                    string
	Providers                    map[string]ProviderConfig
	AllowSyncToKubernetesSecrets bool
}

// Render returns the desired SecretProviderClass and binding status.
func (r Renderer) Render(binding *secretsv1beta1.SecretProviderBinding) (*unstructured.Unstructured, secretsv1beta1.SecretProviderBindingStatus, error) {
	provider, ok := r.Providers[binding.Spec.ProviderName]
	if !ok {
		return nil, secretsv1beta1.SecretProviderBindingStatus{}, fmt.Errorf("unknown provider %q", binding.Spec.ProviderName)
	}
	ks := secretsbackend.Keyspace{ProviderName: provider.Name, Namespace: binding.Namespace, BindingName: binding.Name, Prefix: providerKeyPrefix(r.ClusterID, provider)}
	items := make([]secretsv1beta1.SecretProviderBindingItemStatus, 0, len(binding.Spec.Items))
	for _, item := range binding.Spec.Items {
		if err := secretsbackend.ValidateSegment("key", item.Key); err != nil {
			return nil, secretsv1beta1.SecretProviderBindingStatus{}, err
		}
		p := item.Path
		if p == "" {
			p = item.Key
		}
		if err := ValidateMountPath(p); err != nil {
			return nil, secretsv1beta1.SecretProviderBindingStatus{}, err
		}
		items = append(items, secretsv1beta1.SecretProviderBindingItemStatus{Key: item.Key, Path: p})
	}
	params, err := r.parameters(provider, ks, binding.Name, binding.Spec.Items)
	if err != nil {
		return nil, secretsv1beta1.SecretProviderBindingStatus{}, err
	}
	secretObjects, err := secretObjects(binding.Spec.SyncToKubernetesSecrets, items)
	if err != nil {
		return nil, secretsv1beta1.SecretProviderBindingStatus{}, err
	}
	obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "secrets-store.csi.x-k8s.io/v1", "kind": "SecretProviderClass", "metadata": map[string]any{"name": binding.Name, "namespace": binding.Namespace, "labels": map[string]any{"app.kubernetes.io/managed-by": "podplane", BindingLabel: binding.Name}}, "spec": map[string]any{"provider": provider.Kind, "parameters": params}}}
	if len(secretObjects) > 0 {
		_ = unstructured.SetNestedSlice(obj.Object, secretObjects, "spec", "secretObjects")
	}
	obj.SetGroupVersionKind(SecretProviderClassGVK)
	obj.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: secretsv1beta1.GroupVersion.String(), Kind: "SecretProviderBinding", Name: binding.Name, UID: binding.UID, Controller: ptr(true), BlockOwnerDeletion: ptr(true)}})
	status := secretsv1beta1.SecretProviderBindingStatus{Provider: secretsv1beta1.SecretProviderBindingProviderStatus{Name: provider.Name, Kind: provider.Kind}, SecretProviderClass: secretsv1beta1.SecretProviderClassStatus{Name: binding.Name}, Items: items}
	return obj, status, nil
}

// providerKeyPrefix returns the provider's configured backend key prefix,
// defaulting to the cluster ID for providers that omit it.
func providerKeyPrefix(clusterID string, provider ProviderConfig) string {
	if provider.KeyPrefix != "" {
		return provider.KeyPrefix
	}
	return clusterID
}

// parameters renders provider-specific SecretProviderClass parameters.
func (r Renderer) parameters(p ProviderConfig, ks secretsbackend.Keyspace, bindingName string, items []secretsv1beta1.SecretProviderBindingItem) (map[string]any, error) {
	switch p.Kind {
	case "aws":
		objectType := p.ObjectType
		if objectType == "" {
			objectType = "secretsmanager"
		}
		rows := []map[string]string{}
		for _, it := range items {
			bp, err := ks.SlashPath(it.Key)
			if err != nil {
				return nil, err
			}
			alias := it.Path
			if alias == "" {
				alias = it.Key
			}
			rows = append(rows, map[string]string{"objectName": bp, "objectType": objectType, "objectAlias": alias})
		}
		y, _ := yaml.Marshal(rows)
		return map[string]any{"objects": string(y)}, nil
	case "gcp":
		if p.ProjectID == "" {
			return nil, fmt.Errorf("gcp provider %q requires project_id", p.Name)
		}
		rows := []map[string]string{}
		for _, it := range items {
			id, err := ks.GCPSecretID(it.Key)
			if err != nil {
				return nil, err
			}
			rn := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", p.ProjectID, id)
			if p.Location != "" {
				rn = fmt.Sprintf("projects/%s/locations/%s/secrets/%s/versions/latest", p.ProjectID, p.Location, id)
			}
			mp := it.Path
			if mp == "" {
				mp = it.Key
			}
			rows = append(rows, map[string]string{"resourceName": rn, "path": mp})
		}
		y, _ := yaml.Marshal(rows)
		return map[string]any{"secrets": string(y)}, nil
	case "vault", "openbao":
		mount := strings.Trim(p.MountPath, "/")
		if mount == "" {
			mount = "secret"
		}
		rows := []map[string]string{}
		for _, it := range items {
			rel, err := ks.RelativePath(it.Key)
			if err != nil {
				return nil, err
			}
			obj := it.Path
			if obj == "" {
				obj = it.Key
			}
			rows = append(rows, map[string]string{"objectName": obj, "secretPath": mount + "/data/" + rel, "secretKey": "value"})
		}
		y, _ := yaml.Marshal(rows)
		prefix := "vault"
		if p.Kind == "openbao" {
			prefix = "bao"
		}
		out := map[string]any{"objects": string(y)}
		if p.Address != "" {
			out[prefix+"Address"] = p.Address
		}
		out["roleName"] = bindingName
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported provider kind %q", p.Kind)
	}
}

// secretObjects renders CSI secretObjects entries.
func secretObjects(sync []secretsv1beta1.KubernetesSecretSync, items []secretsv1beta1.SecretProviderBindingItemStatus) ([]any, error) {
	byKey := map[string]string{}
	for _, it := range items {
		byKey[it.Key] = it.Path
	}
	out := []any{}
	for _, s := range sync {
		data := []any{}
		for _, d := range s.Data {
			objectName, ok := byKey[d.FromKey]
			if !ok {
				return nil, fmt.Errorf("syncToKubernetesSecrets references unknown key %q", d.FromKey)
			}
			data = append(data, map[string]any{"objectName": objectName, "key": d.Key})
		}
		typ := s.Type
		if typ == "" {
			typ = "Opaque"
		}
		out = append(out, map[string]any{"secretName": s.SecretName, "type": typ, "data": data})
	}
	return out, nil
}

// ValidateMountPath rejects absolute, empty, and non-clean mount paths.
func ValidateMountPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "..") || strings.Contains(p, "/../") || path.Clean(p) != p {
		return fmt.Errorf("invalid mounted secret path %q", p)
	}
	return nil
}

// ptr returns a pointer to v for Kubernetes object literals.
func ptr[T any](v T) *T { return &v }
