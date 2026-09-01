// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package workloadpki

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// InjectCAFromAnnotation opts an allow-listed API extension into workload CA injection.
const InjectCAFromAnnotation = "certificates.podplane.dev/inject-ca-from"

// injectionTarget identifies one extension and its required serving endpoint.
type injectionTarget struct {
	gvk     schema.GroupVersionKind
	name    string
	service types.NamespacedName
}

var injectionTargets = []injectionTarget{
	{schema.GroupVersionKind{Group: "apiregistration.k8s.io", Version: "v1", Kind: "APIService"}, "v1beta1.secrets-api.podplane.dev", types.NamespacedName{Namespace: "platform-podplane-operator", Name: "platform-podplane-operator-aggregated-api"}},
	{schema.GroupVersionKind{Group: "admissionregistration.k8s.io", Version: "v1", Kind: "MutatingWebhookConfiguration"}, "capi-mutating-webhook-configuration", types.NamespacedName{Namespace: "platform-cluster-api", Name: "capi-webhook-service"}},
	{schema.GroupVersionKind{Group: "admissionregistration.k8s.io", Version: "v1", Kind: "ValidatingWebhookConfiguration"}, "capi-validating-webhook-configuration", types.NamespacedName{Namespace: "platform-cluster-api", Name: "capi-webhook-service"}},
}

var capiConversionCRDs = []string{
	"clusterclasses.cluster.x-k8s.io",
	"clusterresourcesetbindings.addons.cluster.x-k8s.io",
	"clusterresourcesets.addons.cluster.x-k8s.io",
	"clusters.cluster.x-k8s.io",
	"extensionconfigs.runtime.cluster.x-k8s.io",
	"ipaddressclaims.ipam.cluster.x-k8s.io",
	"ipaddresses.ipam.cluster.x-k8s.io",
	"machinedeployments.cluster.x-k8s.io",
	"machinedrainrules.cluster.x-k8s.io",
	"machinehealthchecks.cluster.x-k8s.io",
	"machinepools.cluster.x-k8s.io",
	"machines.cluster.x-k8s.io",
	"machinesets.cluster.x-k8s.io",
}

// init adds the fixed Cluster API conversion-webhook targets.
func init() {
	gvk := schema.GroupVersionKind{Group: "apiextensions.k8s.io", Version: "v1", Kind: "CustomResourceDefinition"}
	service := types.NamespacedName{Namespace: "platform-cluster-api", Name: "capi-webhook-service"}
	for _, name := range capiConversionCRDs {
		injectionTargets = append(injectionTargets, injectionTarget{gvk: gvk, name: name, service: service})
	}
}

// Injector copies the authoritative workload CA into allow-listed Kubernetes API extensions.
type Injector struct {
	client client.Client
	reader client.Reader
	source interface{ Bundle() ([]byte, error) }

	mu    sync.RWMutex
	ready bool
}

// NewInjector constructs the workload CA injector.
func NewInjector(c client.Client, reader client.Reader, source interface{ Bundle() ([]byte, error) }) *Injector {
	return &Injector{client: c, reader: reader, source: source}
}

// NeedLeaderElection restricts CA bundle injection to the elected manager.
func (i *Injector) NeedLeaderElection() bool { return true }

// Ready reports whether the latest injection pass succeeded.
func (i *Injector) Ready(_ *http.Request) error {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if !i.ready {
		return errors.New("workload CA injector is not ready")
	}
	return nil
}

// Start continuously reconciles annotated extension resources.
func (i *Injector) Start(ctx context.Context) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		err := i.inject(ctx)
		i.mu.Lock()
		i.ready = err == nil
		i.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// inject updates every present, opted-in target with the current workload CA.
func (i *Injector) inject(ctx context.Context) error {
	bundle, err := i.source.Bundle()
	if err != nil {
		return err
	}
	for _, target := range injectionTargets {
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(target.gvk)
		if err := i.reader.Get(ctx, types.NamespacedName{Name: target.name}, obj); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("get %s %s: %w", target.gvk.Kind, target.name, err)
		}
		if obj.GetAnnotations()[InjectCAFromAnnotation] != SignerName {
			continue
		}
		before := obj.DeepCopy()
		changed, err := setInjectedBundle(obj, bundle, target.service)
		if err != nil {
			return fmt.Errorf("inject %s %s: %w", obj.GetKind(), obj.GetName(), err)
		}
		if changed {
			if err := i.client.Patch(ctx, obj, client.MergeFrom(before)); err != nil {
				return fmt.Errorf("patch %s %s: %w", obj.GetKind(), obj.GetName(), err)
			}
		}
	}
	return nil
}

// setInjectedBundle validates the target Service and updates the injected bundle.
func setInjectedBundle(obj *unstructured.Unstructured, bundle []byte, service types.NamespacedName) (bool, error) {
	encoded := base64.StdEncoding.EncodeToString(bundle)
	switch obj.GetKind() {
	case "APIService":
		if err := validateServiceReference(obj.Object, service, "spec", "service"); err != nil {
			return false, err
		}
		return setNestedString(obj.Object, encoded, "spec", "caBundle")
	case "CustomResourceDefinition":
		conversion, found, err := unstructured.NestedMap(obj.Object, "spec", "conversion")
		if err != nil || !found || conversion["strategy"] != "Webhook" {
			return false, err
		}
		if err := validateServiceReference(obj.Object, service, "spec", "conversion", "webhook", "clientConfig", "service"); err != nil {
			return false, err
		}
		return setNestedString(obj.Object, encoded, "spec", "conversion", "webhook", "clientConfig", "caBundle")
	case "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration":
		webhooks, found, err := unstructured.NestedSlice(obj.Object, "webhooks")
		if err != nil || !found {
			return false, err
		}
		changed := false
		for _, entry := range webhooks {
			webhook, ok := entry.(map[string]any)
			if !ok {
				return false, errors.New("webhook entry is not an object")
			}
			clientConfig, ok := webhook["clientConfig"].(map[string]any)
			if !ok {
				return false, errors.New("webhook clientConfig is not an object")
			}
			if err := validateServiceReference(clientConfig, service, "service"); err != nil {
				return false, err
			}
			if clientConfig["caBundle"] != encoded {
				clientConfig["caBundle"] = encoded
				changed = true
			}
		}
		if changed {
			if err := unstructured.SetNestedSlice(obj.Object, webhooks, "webhooks"); err != nil {
				return false, err
			}
		}
		return changed, nil
	default:
		return false, fmt.Errorf("unsupported injection target %q", obj.GetKind())
	}
}

// validateServiceReference requires an extension endpoint to use its assigned Service.
func validateServiceReference(obj map[string]any, expected types.NamespacedName, fields ...string) error {
	service, found, err := unstructured.NestedMap(obj, fields...)
	if err != nil {
		return err
	}
	if !found || service["namespace"] != expected.Namespace || service["name"] != expected.Name {
		return fmt.Errorf("service reference must be %s/%s", expected.Namespace, expected.Name)
	}
	return nil
}

// setNestedString updates nested string while preserving unrelated state.
func setNestedString(obj map[string]any, value string, fields ...string) (bool, error) {
	current, found, err := unstructured.NestedString(obj, fields...)
	if err != nil {
		return false, err
	}
	if found && current == value {
		return false, nil
	}
	return true, unstructured.SetNestedField(obj, value, fields...)
}
