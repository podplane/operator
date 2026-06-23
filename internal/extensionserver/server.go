// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package extensionserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apiopenapi "k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/client-go/informers"
	kubernetes "k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	basecompatibility "k8s.io/component-base/compatibility"
	openapicommon "k8s.io/kube-openapi/pkg/common"
	"k8s.io/kube-openapi/pkg/validation/spec"

	"github.com/podplane/operator/internal/secretsapi"
)

// Options configures the HTTPS aggregated API endpoint.
type Options struct {
	Addr       string
	CertFile   string
	KeyFile    string
	RestConfig *restclient.Config
}

// Server serves Kubernetes aggregated API groups.
type Server struct {
	Kube     kubernetes.Interface
	Secrets  *secretsapi.KeyspaceStorage
	KeyStore *secretsapi.PublicKeyStorage
}

// Run starts the aggregated API server and returns after listeners are installed.
func (s *Server) Run(ctx context.Context, opts Options) error {
	if opts.RestConfig == nil {
		return fmt.Errorf("rest config is required")
	}
	rh, authn, authz, rhConfig, err := delegatedAuth(ctx, s.Kube)
	if err != nil {
		return err
	}
	go rh.Run(ctx, 1)

	scheme := runtime.NewScheme()
	if err := secretsapi.AddToScheme(scheme); err != nil {
		return err
	}
	codecs := serializer.NewCodecFactory(scheme)
	cert, err := dynamiccertificates.NewDynamicServingContentFromFiles("podplane-operator", opts.CertFile, opts.KeyFile)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return err
	}

	config := genericapiserver.NewConfig(codecs)
	config.SecureServing = &genericapiserver.SecureServingInfo{Listener: listener, Cert: cert, ClientCA: rh, MinTLSVersion: tls.VersionTLS12}
	config.Authentication.Authenticator = authn
	config.Authentication.RequestHeaderConfig = rhConfig
	config.Authorization.Authorizer = authz
	config.LoopbackClientConfig = restclient.CopyConfig(opts.RestConfig)
	config.EffectiveVersion = basecompatibility.NewEffectiveVersionFromString("", "", "")
	config.ExternalAddress = listener.Addr().String()
	defNamer := apiopenapi.NewDefinitionNamer(scheme)
	config.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(emptyOpenAPIDefinitions, defNamer)
	config.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(emptyOpenAPIDefinitions, defNamer)
	config.SkipOpenAPIInstallation = true
	config.BuildHandlerChainFunc = func(apiHandler http.Handler, c *genericapiserver.Config) http.Handler {
		withDeleteQuery := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := secretsapi.WithDeleteQuery(r.Context(), r.URL.Query().Get("key"), r.URL.Query().Get("destroy") == "true")
			apiHandler.ServeHTTP(w, r.WithContext(ctx))
		})
		return genericapiserver.DefaultBuildHandlerChain(withDeleteQuery, c)
	}

	apiServer, err := config.Complete(informers.NewSharedInformerFactory(s.Kube, 0)).New("podplane-secrets-api", genericapiserver.NewEmptyDelegate())
	if err != nil {
		return err
	}
	apiGroup := genericapiserver.NewDefaultAPIGroupInfo(secretsapi.SchemeGroupVersion.Group, scheme, runtime.NewParameterCodec(scheme), codecs)
	apiGroup.VersionedResourcesStorageMap[secretsapi.SchemeGroupVersion.Version] = map[string]rest.Storage{
		"publickeys":              s.KeyStore,
		"secretproviderkeyspaces": s.Secrets,
	}
	if err := apiServer.InstallAPIGroup(&apiGroup); err != nil {
		return err
	}
	if _, _, err := apiServer.PrepareRun().NonBlockingRunWithContext(ctx, 10); err != nil {
		return err
	}
	return nil
}

// emptyOpenAPIDefinitions returns minimal OpenAPI schemas required by generic-apiserver installation.
func emptyOpenAPIDefinitions(openapicommon.ReferenceCallback) map[string]openapicommon.OpenAPIDefinition {
	objectSchema := spec.Schema{SchemaProps: spec.SchemaProps{Type: []string{"object"}}}
	return map[string]openapicommon.OpenAPIDefinition{
		"github.com/podplane/operator/internal/secretsapi.PublicKey":                  {Schema: objectSchema},
		"github.com/podplane/operator/internal/secretsapi.SecretProviderKeyspace":     {Schema: objectSchema},
		"github.com/podplane/operator/internal/secretsapi.SecretProviderKeyspaceList": {Schema: objectSchema},
		"io.k8s.apimachinery.pkg.apis.meta.v1.DeleteOptions":                          {Schema: objectSchema},
		"io.k8s.apimachinery.pkg.apis.meta.v1.GetOptions":                             {Schema: objectSchema},
		"io.k8s.apimachinery.pkg.apis.meta.v1.Status":                                 {Schema: objectSchema},
		"io.k8s.apimachinery.pkg.apis.meta.v1.UpdateOptions":                          {Schema: objectSchema},
	}
}
