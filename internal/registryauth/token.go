// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package registryauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// TokenValidator validates a Docker refresh token and returns its expiry.
type TokenValidator interface {
	Validate(ctx context.Context, token string) (time.Time, error)
}

// Server handles Docker-compatible registry authorization.
type Server struct {
	Validator TokenValidator
}

// Options configures the HTTPS registry auth endpoint.
type Options struct {
	Addr     string
	CertFile string
	KeyFile  string
}

// Run starts the registry auth HTTPS endpoint.
func (s *Server) Run(ctx context.Context, opts Options) error {
	if s.Validator == nil {
		return fmt.Errorf("registry auth validator is required")
	}
	if opts.CertFile == "" || opts.KeyFile == "" {
		return fmt.Errorf("registry auth TLS certificate and private key files are required")
	}
	listener, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/token", s)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Warn("registry auth server shutdown failed", "error", err)
		}
	}()
	go func() {
		if err := server.ServeTLS(listener, opts.CertFile, opts.KeyFile); err != nil && err != http.ErrServerClosed {
			slog.Error("registry auth server failed", "error", err)
		}
	}()
	slog.Info("started registry auth endpoint", "addr", listener.Addr().String())
	return nil
}

// ServeHTTP handles Docker token exchange requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/token" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		errorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST is required")
		return
	}
	if err := r.ParseForm(); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	if got := r.PostForm.Get("grant_type"); got != "refresh_token" {
		errorResponse(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be refresh_token")
		return
	}
	refreshToken := r.PostForm.Get("refresh_token")
	if refreshToken == "" {
		errorResponse(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	expiresAt, err := s.Validator.Validate(r.Context(), refreshToken)
	if err != nil {
		errorResponse(w, http.StatusUnauthorized, "invalid_token", "refresh_token is invalid")
		return
	}
	expiresIn := int(time.Until(expiresAt).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":        refreshToken,
		"access_token": refreshToken,
		"expires_in":   expiresIn,
	})
}

// errorResponse writes a Docker token-service compatible JSON error.
func errorResponse(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": message})
}
