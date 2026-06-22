# Podplane Operator — Agent Development Guide

This repository contains `github.com/podplane/operator`, the Kubernetes
operator for Podplane.

It owns the operator binary, and for the Podplane Secrets functionality it owns:
- the `SecretProviderBinding` controller.
- the `secrets-api.podplane.dev` aggregated API.
- the backend adapters used by the Podplane CLI and Secrets Store CSI providers.

## Important

- Before editing, run `git status --short` and do not overwrite, revert, or
  tidy away changes you did not make.
- Prefer Makefile targets over raw tool commands for full-repo validation.
- Keep the secrets module self-contained so it can be split into a future
  `github.com/podplane/secrets` repository if needed.
- Do not persist, print, log, or return secret values. Normal API responses and
  list output are metadata-only.

## Build & Test Commands

- **Setup**: `make setup` — verify required tools and install git hooks.
- **Format**: `make fmt` — run `go fmt ./...`.
- **Lint**: `make lint` — run `golangci-lint run --timeout=5m`.
- **Precommit**: `make precommit` — check gofmt output and run `go vet ./...`.
- **Test**: `make test` — run `go test ./...`.
- **Build**: `make build` — build `bin/podplane-operator`.
- **Clean**: `make clean` — remove `bin/`.
- Focused package tests such as `go test ./internal/secretsbackend` are fine
  while iterating; run broader checks when touching shared API/controller paths.

## Architecture Constraints

- The operator is a single lightweight Go process that hosts:
  - the aggregated API for `secrets-api.podplane.dev/v1beta1`,
  - `SecretProviderBinding` reconciliation,
  - health/readiness endpoints.
- Avoid broad informer caches. Watch only the Kubernetes resources required by
  enabled modules.
- Use Kubernetes API machinery and Kubernetes-style API objects/responses for
  aggregated API behavior. Do not replace it with webhook-style routes or
  ad-hoc non-Kubernetes semantics.
- Aggregated API traffic must go through kube-apiserver delegated
  authentication/authorization. Reject direct service calls except health and
  readiness endpoints.
- Run as a singleton in production while the X25519 private key is in memory
  only. Default key rotation is 6 hours unless explicitly configured.

## Secrets API Semantics

- Backend identity boundary is:

  ```text
  namespace + SecretProviderBinding name
  ```

- Backend paths are derived from:

  ```text
  /<cluster-secrets-prefix>/<namespace>/<binding-name>/<key>
  ```

- Keep every backend path segment slash-free and DNS-label-like. The cluster
  secrets prefix follows the cluster ID validation rules and defaults to the
  cluster ID.
- `SecretProviderKeyspace` is named as `<provider-name>.<binding-name>` and is
  namespaced.
- Namespace-wide list of `secretproviderkeyspaces` is intentionally out of
  scope because Kubernetes RBAC cannot restrict list by `resourceNames`.
- `create` creates only missing active keys and fails if the key exists or is
  archived.
- `update` overwrites only existing active keys and requires a successful custom
  verb `overwrite` SubjectAccessReview in addition to normal named `update`.
- `delete` means recoverable archive when the provider supports it; providers
  without archive support must fail with a clear error telling the user to use
  destroy instead.
- `restore` requires normal named `update` plus custom verb `restore`.
- Permanent destroy requires normal delete authorization plus custom verb
  `destroy`.
- If provider list succeeds but per-key status lookup fails, include the listed
  key with status `unknown` rather than failing the whole list response.
- `publickeys/latest` exposes the current operator public key. Encrypted writes
  must reject stale key IDs with `409 Conflict` so clients can refetch and retry.

## SecretProviderBinding Controller

- `SecretProviderBinding` is namespaced in API group
  `secrets.podplane.dev/v1beta1`.
- Reconcile each binding to one owned same-namespace `SecretProviderClass` with
  the same name.
- Set an owner reference and Podplane labels/annotations on generated
  `SecretProviderClass` objects.
- If a target `SecretProviderClass` already exists without the matching
  Podplane owner reference, report a conflict condition and do not mutate it.
- Raw, non-owned `SecretProviderClass` resources are an operator-controlled
  escape hatch governed by normal Kubernetes RBAC. Do not validate or mutate
  them from this controller.
- Generated resources should avoid historical version references and advanced
  escape-hatch features such as AWS full ARNs, `jmesPath`, `failoverObject`, or
  provider-specific old version selectors.

## Provider Behavior

- OpenBao/Vault KV-v2: delete soft-deletes the latest/current logical key;
  restore undeletes it; destroy deletes metadata for the logical key.
- AWS Secrets Manager: delete schedules deletion with a recovery window;
  restore uses `RestoreSecret`; destroy force-deletes without recovery.
- AWS Parameter Store: archive delete and restore are unsupported; destroy
  deletes the parameter.
- GCP Secret Manager: delete disables the active/latest version; restore
  re-enables it; destroy destroys disabled archived versions.
- Local clusters should use the same path as production:

  ```text
  podplane CLI -> kube-apiserver -> podplane operator aggregated API -> provider adapter
  ```

  Do not add direct local keychain or fakevault bypasses to this repository.

## Code Style

- Go files should include the Podplane Apache-2.0 header:

  ```go
  // Podplane <https://podplane.dev>
  // Copyright The Podplane Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

- Imports are grouped stdlib → third-party → local
  (`github.com/podplane/operator/*`).
- Use concise Go names and early returns. Wrap errors with
  `fmt.Errorf("...: %w", err)` when adding useful context.
- Keep controller-runtime code in `internal/controllers`, aggregated API code in
  `internal/secretsapi`, backend implementations in `internal/secretsbackend`,
  authorization policy in `internal/secretspolicy`, and runtime config loading
  in `internal/config`.
- Prefer small, direct functions over new abstractions. Add helpers only when
  they are reused, simplify real complexity, or match an established local
  pattern.
- Do not add Go module dependencies without explicit confirmation.

## Testing Guidance

- Use the standard `testing` package and hand-written fakes where practical.
- Add focused tests for changed semantics rather than broad snapshots.
- For API behavior, assert Kubernetes-style status/object shapes, authorization
  decisions, stale-key conflicts, and backend operation calls.
- For controller behavior, assert generated `SecretProviderClass` content,
  owner references, collision handling, status conditions, and provider-specific
  path rendering.
- For backend adapters, avoid tests that require real cloud credentials unless
  explicitly requested; prefer interface-level tests with fakes for normal
  iteration.
