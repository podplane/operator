// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package extensionserver

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authentication/request/headerrequest"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	kubernetes "k8s.io/client-go/kubernetes"
)

// requestHeaderController keeps requestheader authentication config current.
type requestHeaderController struct {
	*dynamiccertificates.ConfigMapCAController
	*headerrequest.RequestHeaderAuthRequestController
}

// newRequestHeaderController loads kube-apiserver aggregation proxy settings.
func newRequestHeaderController(kube kubernetes.Interface) (*requestHeaderController, error) {
	ca, err := dynamiccertificates.NewDynamicCAFromConfigMapController("request-header", metav1.NamespaceSystem, "extension-apiserver-authentication", "requestheader-client-ca-file", kube)
	if err != nil {
		return nil, fmt.Errorf("create requestheader CA controller: %w", err)
	}
	headers := headerrequest.NewRequestHeaderAuthRequestController(
		"extension-apiserver-authentication",
		metav1.NamespaceSystem,
		kube,
		"requestheader-username-headers",
		"requestheader-uid-headers",
		"requestheader-group-headers",
		"requestheader-extra-headers-prefix",
		"requestheader-allowed-names",
	)
	return &requestHeaderController{ConfigMapCAController: ca, RequestHeaderAuthRequestController: headers}, nil
}

// RunOnce loads requestheader config and fails closed if required data is absent.
func (c *requestHeaderController) RunOnce(ctx context.Context) error {
	if err := utilerrors.NewAggregate([]error{c.ConfigMapCAController.RunOnce(ctx), c.RequestHeaderAuthRequestController.RunOnce(ctx)}); err != nil {
		return err
	}
	if len(c.CurrentCABundleContent()) == 0 {
		return fmt.Errorf("requestheader client CA is empty")
	}
	if len(c.UsernameHeaders()) == 0 {
		return fmt.Errorf("requestheader username headers are empty")
	}
	return nil
}

// Run keeps requestheader config current until ctx is canceled.
func (c *requestHeaderController) Run(ctx context.Context, workers int) {
	go c.ConfigMapCAController.Run(ctx, workers)
	go c.RequestHeaderAuthRequestController.Run(ctx, workers)
	<-ctx.Done()
}

// delegatedAuth returns requestheader authentication and delegated authorization for generic-apiserver.
func delegatedAuth(ctx context.Context, kube kubernetes.Interface) (*requestHeaderController, authenticator.Request, authorizer.Authorizer, *authenticatorfactory.RequestHeaderConfig, error) {
	if kube == nil {
		return nil, nil, nil, nil, fmt.Errorf("kubernetes client is required")
	}
	rh, err := newRequestHeaderController(kube)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := rh.RunOnce(ctx); err != nil {
		return nil, nil, nil, nil, err
	}
	rhConfig := &authenticatorfactory.RequestHeaderConfig{
		UsernameHeaders:     headerrequest.StringSliceProviderFunc(rh.UsernameHeaders),
		UIDHeaders:          headerrequest.StringSliceProviderFunc(rh.UIDHeaders),
		GroupHeaders:        headerrequest.StringSliceProviderFunc(rh.GroupHeaders),
		ExtraHeaderPrefixes: headerrequest.StringSliceProviderFunc(rh.ExtraHeaderPrefixes),
		CAContentProvider:   rh,
		AllowedClientNames:  headerrequest.StringSliceProviderFunc(rh.AllowedClientNames),
	}
	authn, _, err := authenticatorfactory.DelegatingAuthenticatorConfig{RequestHeaderConfig: rhConfig}.New()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	backoff := wait.Backoff{Duration: 500 * time.Millisecond, Factor: 1.5, Jitter: 0.2, Steps: 5}
	authz, err := authorizerfactory.DelegatingAuthorizerConfig{SubjectAccessReviewClient: kube.AuthorizationV1(), AllowCacheTTL: 10 * time.Second, DenyCacheTTL: 10 * time.Second, WebhookRetryBackoff: &backoff}.New()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return rh, authn, authz, rhConfig, nil
}
