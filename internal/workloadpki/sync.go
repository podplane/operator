// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package workloadpki

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TrustBundleSyncConfig configures destinations and their default creation policy.
type TrustBundleSyncConfig struct {
	CreateIfMissing bool                    `json:"create_if_missing,omitempty"`
	Resources       []TrustBundleSyncTarget `json:"resources,omitempty"`
}

// TrustBundleSyncTarget identifies one data key that receives the public CA bundle.
type TrustBundleSyncTarget struct {
	Kind            string `json:"kind"`
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	Key             string `json:"key"`
	CreateIfMissing *bool  `json:"create_if_missing,omitempty"`
}

// ValidateTrustBundleSync rejects invalid or duplicate destinations.
func ValidateTrustBundleSync(targets []TrustBundleSyncTarget) error {
	seen := make(map[[4]string]bool, len(targets))
	for index, target := range targets {
		identity := [4]string{target.Kind, target.Namespace, target.Name, target.Key}
		var reason string
		switch {
		case target.Kind != "Secret" && target.Kind != "ConfigMap":
			reason = "kind must be Secret or ConfigMap"
		case len(validation.IsDNS1123Label(target.Namespace)) != 0:
			reason = "namespace must be a DNS label"
		case len(validation.IsDNS1123Subdomain(target.Name)) != 0:
			reason = "name must be a DNS subdomain"
		case target.Key == "" || len(validation.IsConfigMapKey(target.Key)) != 0:
			reason = "key must be a valid Secret or ConfigMap data key"
		case seen[identity]:
			reason = "duplicate destination"
		}
		if reason != "" {
			return fmt.Errorf("certificates.trust_bundle_sync.resources[%d]: %s", index, reason)
		}
		seen[identity] = true
	}
	return nil
}

// syncTrustBundle reconciles destinations without caching or listing Secrets.
func (m *Manager) syncTrustBundle(ctx context.Context, bundle string) error {
	var errs []error
	for _, target := range m.cfg.TrustBundleSync.Resources {
		if err := m.syncTrustBundleTarget(ctx, target, bundle); err != nil {
			errs = append(errs, fmt.Errorf("sync %s %s/%s key %s: %w", target.Kind, target.Namespace, target.Name, target.Key, err))
		}
	}
	return errors.Join(errs...)
}

// syncTrustBundleTarget optionally creates a missing destination with its bundle,
// or patches only the selected key with a resource-version precondition.
func (m *Manager) syncTrustBundleTarget(ctx context.Context, target TrustBundleSyncTarget, bundle string) error {
	name := types.NamespacedName{Namespace: target.Namespace, Name: target.Name}
	metadata := metav1.ObjectMeta{Namespace: target.Namespace, Name: target.Name}
	var obj client.Object
	switch target.Kind {
	case "Secret":
		obj = &corev1.Secret{ObjectMeta: metadata}
	case "ConfigMap":
		obj = &corev1.ConfigMap{ObjectMeta: metadata}
	default:
		return fmt.Errorf("unsupported kind %q", target.Kind)
	}
	create := m.cfg.TrustBundleSync.CreateIfMissing
	if target.CreateIfMissing != nil {
		create = *target.CreateIfMissing
	}
	err := m.reader.Get(ctx, name, obj)
	if apierrors.IsNotFound(err) && create {
		candidate := obj.DeepCopyObject().(client.Object)
		switch candidate := candidate.(type) {
		case *corev1.Secret:
			candidate.Type = corev1.SecretTypeOpaque
			candidate.Data = map[string][]byte{target.Key: []byte(bundle)}
		case *corev1.ConfigMap:
			candidate.Data = map[string]string{target.Key: bundle}
		}
		if err := m.client.Create(ctx, candidate); !apierrors.IsAlreadyExists(err) {
			return err
		}
		// Another writer won creation; preserve its fields as for any existing target.
		err = m.reader.Get(ctx, name, obj)
	}
	if err != nil {
		return err
	}
	before := obj.DeepCopyObject().(client.Object)
	switch obj := obj.(type) {
	case *corev1.Secret:
		if bytes.Equal(obj.Data[target.Key], []byte(bundle)) {
			return nil
		}
		if obj.Data == nil {
			obj.Data = map[string][]byte{}
		}
		obj.Data[target.Key] = []byte(bundle)
	case *corev1.ConfigMap:
		if _, exists := obj.BinaryData[target.Key]; exists {
			return errors.New("key already exists in binaryData")
		}
		if obj.Data[target.Key] == bundle {
			return nil
		}
		if obj.Data == nil {
			obj.Data = map[string]string{}
		}
		obj.Data[target.Key] = bundle
	}
	return m.client.Patch(ctx, obj, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
}
