// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package sds

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/podplane/operator/internal/ingresspki"
)

const (
	defaultPollInterval = 5 * time.Second
	shutdownTimeout     = 10 * time.Second
)

// certificateFlags collects repeatable name-to-domain mappings.
type certificateFlags map[string]string

// String renders configured mappings without secret material.
func (f certificateFlags) String() string { return fmt.Sprint(map[string]string(f)) }

// Set parses and validates one resource-name-to-domain mapping.
func (f certificateFlags) Set(value string) error {
	name, domain, ok := strings.Cut(value, "=")
	if !ok || name == "" || domain == "" || filepath.Base(name) != name || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) {
		return fmt.Errorf("certificate mapping must be <resource-name>=<DNS-name>")
	}
	if name == "node" {
		return fmt.Errorf("certificate resource name %q is reserved for the node certificate", name)
	}
	if _, exists := f[name]; exists {
		return fmt.Errorf("duplicate certificate resource %q", name)
	}
	f[name] = domain
	return nil
}

// Run parses SDS flags and serves until ctx is canceled.
func Run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("sds", flag.ContinueOnError)
	var socket, directory string
	var interval time.Duration
	certificates := certificateFlags{}
	workloads := certificateFlags{}
	var nodeDomains []string
	flags.StringVar(&socket, "socket", "/var/run/podplane-sds/sds.sock", "Envoy SDS Unix socket")
	flags.StringVar(&directory, "certificates-dir", "/var/run/podplane/ingress-certificates", "mounted certificate bundle directory")
	flags.DurationVar(&interval, "poll-interval", defaultPollInterval, "certificate bundle polling interval")
	flags.Var(certificates, "domain-certificate", "SDS resource name and apex domain (repeatable)")
	flags.Func("workload-certificate", "SDS resource name and service DNS name: name=service-DNS-name (repeatable; exclusive with ingress modes)", func(value string) error {
		_, hostname, ok := strings.Cut(value, "=")
		if !ok || len(validation.IsDNS1123Subdomain(hostname)) != 0 || net.ParseIP(hostname) != nil {
			return fmt.Errorf("workload-certificate must be <resource-name>=<service-DNS-name>")
		}
		return workloads.Set(value)
	})
	flags.Func("node-certificate", "comma-separated apex domains served by node.pem as node (exclusive with domain-certificate)", func(value string) error {
		nodeDomains = strings.Split(value, ",")
		for _, domain := range nodeDomains {
			if domain == "" || strings.ContainsAny(domain, "=* /\\\t\r\n") {
				return fmt.Errorf("node-certificate must be a comma-separated list of apex domains")
			}
		}
		return nil
	})
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(certificates) > 0 && len(nodeDomains) > 0 {
		return fmt.Errorf("domain-certificate and node-certificate are mutually exclusive")
	}
	workload := len(workloads) > 0
	if workload {
		if len(certificates) > 0 || len(nodeDomains) > 0 {
			return fmt.Errorf("workload-certificate and ingress certificate modes are mutually exclusive")
		}
		certificates = workloads
	}
	if len(nodeDomains) > 0 {
		certificates["node"] = ""
	}
	if len(certificates) == 0 || interval <= 0 {
		return fmt.Errorf("at least one certificate and a positive poll interval are required")
	}
	cache := cachev3.NewLinearCache(resourcev3.SecretType)
	hashes, resources, err := load(directory, certificates, nodeDomains, workload)
	if err != nil {
		return fmt.Errorf("load initial SDS resources: %w", err)
	}
	cache.SetResources(resources)
	listener, err := listen(socket)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close(); _ = os.Remove(socket) }()
	grpcServer := grpc.NewServer()
	callbacks := requestCallbacks(certificates)
	secretv3.RegisterSecretDiscoveryServiceServer(grpcServer, serverv3.NewServer(ctx, cache, callbacks))
	go poll(ctx, interval, directory, certificates, nodeDomains, workload, cache, hashes)
	go func() {
		<-ctx.Done()
		stopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(shutdownTimeout):
			grpcServer.Stop()
		}
	}()
	slog.Info("serving Envoy SDS", "socket", socket, "resources", len(certificates))
	if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve SDS: %w", err)
	}
	return nil
}

// requestCallbacks rejects resources outside the configured allowlist and logs bounded NACK status.
func requestCallbacks(certificates certificateFlags) serverv3.CallbackFuncs {
	check := func(names []string) error {
		for _, name := range names {
			if _, ok := certificates[name]; !ok {
				return status.Errorf(codes.PermissionDenied, "SDS resource %q is not configured", name)
			}
		}
		return nil
	}
	stream := func(_ int64, request *cachev3.Request) error {
		if detail := request.GetErrorDetail(); detail != nil {
			message := detail.GetMessage()
			if len(message) > 256 {
				message = message[:256]
			}
			slog.Warn("Envoy rejected SDS response", "code", detail.GetCode(), "message", message)
		}
		return check(request.GetResourceNames())
	}
	return serverv3.CallbackFuncs{
		StreamRequestFunc: stream,
		FetchRequestFunc:  func(_ context.Context, request *cachev3.Request) error { return stream(0, request) },
	}
}

// listen safely replaces an existing socket and applies group-writable permissions.
func listen(path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to remove non-socket path %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

// load validates all configured files and constructs one complete resource generation.
func load(directory string, certificates certificateFlags, nodeDomains []string, workload bool) (map[string][sha256.Size]byte, map[string]cachetypes.Resource, error) {
	hashes := make(map[string][sha256.Size]byte, len(certificates))
	resources := make(map[string]cachetypes.Resource, len(certificates))
	for name, domain := range certificates {
		filename := name
		if len(nodeDomains) > 0 {
			filename = "node.pem"
		}
		value, err := os.ReadFile(filepath.Join(directory, filename))
		if err != nil {
			return nil, nil, fmt.Errorf("read resource %q: %w", name, err)
		}
		var chain, key []byte
		if workload {
			chain, key, err = validateWorkloadBundle(value, domain, time.Now())
		} else if len(nodeDomains) > 0 {
			chain, key, err = ingresspki.ValidateNodeBundle(value, nodeDomains, time.Now())
		} else {
			chain, key, err = ingresspki.ValidateBundle(value, domain, time.Now())
		}
		if err != nil {
			return nil, nil, fmt.Errorf("validate resource %q: %w", name, err)
		}
		hashes[name] = sha256.Sum256(value)
		resources[name] = &tlsv3.Secret{Name: name, Type: &tlsv3.Secret_TlsCertificate{TlsCertificate: &tlsv3.TlsCertificate{CertificateChain: inline(chain), PrivateKey: inline(key)}}}
	}
	return hashes, resources, nil
}

// inline constructs an Envoy inline byte data source.
func inline(value []byte) *corev3.DataSource {
	return &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: value}}
}

// poll publishes each valid resource independently and retains failed resources.
func poll(ctx context.Context, interval time.Duration, directory string, certificates certificateFlags, nodeDomains []string, workload bool, cache *cachev3.LinearCache, current map[string][sha256.Size]byte) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for name, domain := range certificates {
				// A node bundle remains one resource validated against every node
				// domain; per-domain resources have independent update boundaries.
				hashes, resources, err := load(directory, certificateFlags{name: domain}, nodeDomains, workload)
				if err != nil {
					slog.Warn("retaining last-known-good SDS resource", "resource", name, "error", err)
					continue
				}
				if current[name] == hashes[name] {
					continue
				}
				if err := cache.UpdateResource(name, resources[name]); err != nil {
					slog.Warn("update SDS resource failed", "resource", name, "error", err)
					continue
				}
				current[name] = hashes[name]
				slog.Info("published SDS certificate generation", "resource", name)
			}
		}
	}
}
