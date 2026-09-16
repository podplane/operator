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

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// InjectCAFromAnnotation opts an API extension into workload CA injection.
const InjectCAFromAnnotation = "certificates.podplane.dev/inject-ca-from"

const workloadCASource = "workload"

var injectableKinds = []schema.GroupVersionKind{
	{Group: "apiregistration.k8s.io", Version: "v1", Kind: "APIService"},
	{Group: "admissionregistration.k8s.io", Version: "v1", Kind: "MutatingWebhookConfiguration"},
	{Group: "admissionregistration.k8s.io", Version: "v1", Kind: "ValidatingWebhookConfiguration"},
	{Group: "apiextensions.k8s.io", Version: "v1", Kind: "CustomResourceDefinition"},
}

// Injector copies the authoritative workload CA into annotated Kubernetes API extensions.
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

// inject updates every opted-in API extension with the current workload CA.
func (i *Injector) inject(ctx context.Context) error {
	bundle, err := i.source.Bundle()
	if err != nil {
		return err
	}
	for _, gvk := range injectableKinds {
		objects := &unstructured.UnstructuredList{}
		objects.SetGroupVersionKind(schema.GroupVersionKind{Group: gvk.Group, Version: gvk.Version, Kind: gvk.Kind + "List"})
		if err := i.reader.List(ctx, objects); err != nil {
			return fmt.Errorf("list %s resources: %w", gvk.Kind, err)
		}
		for index := range objects.Items {
			obj := &objects.Items[index]
			if obj.GetAnnotations()[InjectCAFromAnnotation] != workloadCASource {
				continue
			}
			services, err := serviceReferences(obj)
			if err != nil {
				return fmt.Errorf("read %s %s service references: %w", obj.GetKind(), obj.GetName(), err)
			}
			for _, name := range services {
				service := &unstructured.Unstructured{}
				service.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "Service"})
				if err := i.reader.Get(ctx, name, service); err != nil {
					return fmt.Errorf("get Service %s for %s %s: %w", name, obj.GetKind(), obj.GetName(), err)
				}
			}
			before := obj.DeepCopy()
			changed, err := setInjectedBundle(obj, bundle)
			if err != nil {
				return fmt.Errorf("inject %s %s: %w", obj.GetKind(), obj.GetName(), err)
			}
			if changed {
				if err := i.client.Patch(ctx, obj, client.MergeFrom(before)); err != nil {
					return fmt.Errorf("patch %s %s: %w", obj.GetKind(), obj.GetName(), err)
				}
			}
		}
	}
	return nil
}

// serviceReferences returns the in-cluster Services used by an API extension.
func serviceReferences(obj *unstructured.Unstructured) ([]types.NamespacedName, error) {
	switch obj.GetKind() {
	case "APIService":
		service, err := serviceReference(obj.Object, "spec", "service")
		return []types.NamespacedName{service}, err
	case "CustomResourceDefinition":
		strategy, found, err := unstructured.NestedString(obj.Object, "spec", "conversion", "strategy")
		if err != nil {
			return nil, err
		}
		if !found || strategy != "Webhook" {
			return nil, errors.New("conversion strategy must be Webhook")
		}
		service, err := serviceReference(obj.Object, "spec", "conversion", "webhook", "clientConfig", "service")
		return []types.NamespacedName{service}, err
	case "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration":
		webhooks, found, err := unstructured.NestedSlice(obj.Object, "webhooks")
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errors.New("webhooks are missing")
		}
		services := make([]types.NamespacedName, 0, len(webhooks))
		for _, entry := range webhooks {
			webhook, ok := entry.(map[string]any)
			if !ok {
				return nil, errors.New("webhook entry is not an object")
			}
			service, err := serviceReference(webhook, "clientConfig", "service")
			if err != nil {
				return nil, err
			}
			services = append(services, service)
		}
		return services, nil
	default:
		return nil, fmt.Errorf("unsupported injection target %q", obj.GetKind())
	}
}

// serviceReference reads one namespaced Service reference.
func serviceReference(obj map[string]any, fields ...string) (types.NamespacedName, error) {
	service, found, err := unstructured.NestedMap(obj, fields...)
	if err != nil {
		return types.NamespacedName{}, err
	}
	if !found {
		return types.NamespacedName{}, errors.New("service reference is missing")
	}
	namespace, namespaceOK := service["namespace"].(string)
	name, nameOK := service["name"].(string)
	if !namespaceOK || namespace == "" || !nameOK || name == "" {
		return types.NamespacedName{}, errors.New("service reference requires a namespace and name")
	}
	return types.NamespacedName{Namespace: namespace, Name: name}, nil
}

// setInjectedBundle updates the CA bundle in a supported API extension.
func setInjectedBundle(obj *unstructured.Unstructured, bundle []byte) (bool, error) {
	encoded := base64.StdEncoding.EncodeToString(bundle)
	switch obj.GetKind() {
	case "APIService":
		return setNestedString(obj.Object, encoded, "spec", "caBundle")
	case "CustomResourceDefinition":
		conversion, found, err := unstructured.NestedMap(obj.Object, "spec", "conversion")
		if err != nil || !found || conversion["strategy"] != "Webhook" {
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
