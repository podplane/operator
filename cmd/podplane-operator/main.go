// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	kubernetes "k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"

	secretsv1beta1 "github.com/podplane/operator/api/v1beta1"
	operatorconfig "github.com/podplane/operator/internal/config"
	"github.com/podplane/operator/internal/controllers"
	"github.com/podplane/operator/internal/extensionserver"
	"github.com/podplane/operator/internal/secretsapi"
	"github.com/podplane/operator/internal/secretsbackend"
)

// main starts the controller manager and aggregated API server.
func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// run starts the controller manager and aggregated API server.
func run() error {
	var cfgPath, addr, certFile, keyFile string
	var rotation time.Duration
	flag.StringVar(&cfgPath, "config", "/etc/podplane-operator/config.json", "operator JSON config")
	flag.StringVar(&addr, "secure-bind-address", ":8443", "TLS address for APIService traffic")
	flag.StringVar(&certFile, "tls-cert-file", "/var/run/podplane/tls/tls.crt", "TLS certificate file")
	flag.StringVar(&keyFile, "tls-private-key-file", "/var/run/podplane/tls/tls.key", "TLS private key file")
	flag.DurationVar(&rotation, "key-rotation", operatorconfig.DefaultRotation(), "operator X25519 public key rotation interval")
	flag.Parse()

	ctx := ctrl.SetupSignalHandler()
	cfg, err := operatorconfig.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := secretsbackend.ValidateClusterPrefix(cfg.SecretsPrefix); err != nil {
		return err
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(secretsv1beta1.AddToScheme(scheme))
	restCfg := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{Scheme: scheme})
	if err != nil {
		return err
	}

	providerMap := map[string]controllers.ProviderConfig{}
	backends := []secretsbackend.Backend{}
	for name, p := range cfg.Providers {
		providerMap[name] = p
		b, err := backend(ctx, name, p)
		if err != nil {
			return err
		}
		backends = append(backends, b)
	}
	registry, err := secretsbackend.NewRegistry(backends...)
	if err != nil {
		return err
	}

	reconciler := &controllers.SecretProviderBindingReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), Renderer: controllers.Renderer{ClusterPrefix: cfg.SecretsPrefix, Providers: providerMap, AllowSyncToKubernetesSecrets: cfg.AllowSyncToKubernetesSecrets}}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return err
	}

	keys, err := secretsapi.NewKeyRing(rotation)
	if err != nil {
		return err
	}
	stop := make(chan struct{})
	defer close(stop)
	keys.Start(stop)
	kube, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return err
	}
	keyspaces := &secretsapi.KeyspaceStorage{ClusterID: cfg.ClusterID, Prefix: cfg.SecretsPrefix, Keys: keys, Backends: registry, Kube: kube}
	publicKeys := &secretsapi.PublicKeyStorage{Keys: keys}
	extensions := &extensionserver.Server{Kube: kube, Secrets: keyspaces, KeyStore: publicKeys}
	if err := extensions.Run(ctx, extensionserver.Options{Addr: addr, CertFile: certFile, KeyFile: keyFile, RestConfig: restCfg}); err != nil {
		return err
	}
	slog.Info("starting controller manager")
	return mgr.Start(ctx)
}

// backend constructs a secrets backend for a configured provider.
func backend(ctx context.Context, name string, p controllers.ProviderConfig) (secretsbackend.Backend, error) {
	switch p.Kind {
	case "openbao":
		token, err := providerToken(name)
		if err != nil {
			return nil, err
		}
		return secretsbackend.NewVaultBackend(secretsbackend.VaultOptions{Name: name, Kind: "openbao", Address: p.Address, Token: token, Mount: p.MountPath}), nil
	case "vault":
		token, err := providerToken(name)
		if err != nil {
			return nil, err
		}
		return secretsbackend.NewVaultBackend(secretsbackend.VaultOptions{Name: name, Kind: "vault", Address: p.Address, Token: token, Mount: p.MountPath}), nil
	case "aws":
		if p.ObjectType == "ssmparameter" {
			return secretsbackend.NewAWSParameterStoreBackend(ctx, name, p.Region)
		}
		return secretsbackend.NewAWSSecretsManagerBackend(ctx, name, p.Region, 0)
	case "gcp":
		return secretsbackend.NewGCPSecretManagerBackend(ctx, name, p.ProjectID, p.Location)
	case "memory":
		return secretsbackend.NewMemoryBackend(name, "memory"), nil
	default:
		return nil, fmt.Errorf("unsupported provider kind %q", p.Kind)
	}
}

// providerToken reads the convention-based token file for a provider when it exists.
func providerToken(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join("/var/run/podplane/providers", name, "token"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
