# Podplane Operator

Podplane is an Open Source Kubernetes distribution & PaaS.

The Podplane Operator provides features which improve the PaaS developer experience (DX).

## Current Features

- **Podplane Secrets:** CLI secret management and binding-based Secrets Store CSI
  mounts, backed by Vault/OpenBao, AWS Secrets Manager/Parameter Store, and Google
  Secret Manager.
- **Workload certificates:** Kubernetes Pod Certificate signing for SPIFFE
  identities and service TLS, trust-bundle publication, and CA injection into API
  extensions and webhooks.
- **Ingress certificates:** self-signed fallback and optional ACME DNS-01 issuance
  and renewal, with certificate bundles stored in external secrets providers.
- **Envoy SDS:** certificate delivery and live reload for secrets-backed
  per-domain or node-local ingress certificates and projected workload certificates.

## Configuration

The operator is configured with a JSON file passed to `podplane-operator --config`.
The config declares the Podplane cluster identity and the named secrets
providers the operator can use. The `providers` object mirrors the Podplane
cluster config `cluster.secrets.providers` model: provider names are map keys,
and provider entries contain non-secret provider metadata.

Example:

```json
{
  "cluster": {
    "id": "dev-cluster",
    "oidc": {
      "issuer_url": "https://oidc.example.com/dev-cluster",
      "client_id": "dev-cluster"
    },
    "spiffe": {
      "trust_domain": "cluster.example"
    }
  },
  "certificates": {
    "trust_bundle_sync": {
      "create_if_missing": false,
      "resources": [
        {"kind": "Secret", "namespace": "platform-agent-router", "name": "workload-ca", "key": "tls.crt", "create_if_missing": true},
        {"kind": "ConfigMap", "namespace": "platform-example", "name": "workload-ca", "key": "ca.crt"}
      ]
    }
  },
  "secrets": {
    "allow_sync_to_kubernetes_secrets": false,
    "key_rotation": "6h",
    "default_provider": "openbao-local",
    "providers": {
      "openbao-local": {
        "kind": "openbao",
        "key_prefix": "shared-secrets",
        "address": "https://podplane-local.example/vault/dev-cluster/v1",
        "mount_path": "secret",
        "auth_path": "auth/kubernetes",
        "operator_role": "podplane-operator"
      },
      "aws-secrets-manager": {
        "kind": "aws",
        "object_type": "secretsmanager",
        "region": "us-east-1"
      }
    }
  }
}
```

`cluster.id` identifies the Podplane cluster. The backend path prefix defaults
to `cluster.id`. `cluster.oidc` holds the cluster's OIDC settings;
`cluster.oidc.client_id` defaults to `cluster.id` when omitted. Zot receives its
OIDC configuration separately through the registry chart.
Each secrets provider has safe fields such as `kind`,
`object_type`, `region`, `project_id`, `location`, `address`, `mount_path`,
`ca_cert`, `auth_path`, or `operator_role`. Secret material must not be placed
inline.

Bindings may omit `spec.providerName` to follow `secrets.default_provider` on every
reconciliation. Explicit names stay pinned to that provider. The resolved name and
kind appear in `status.provider`; the operator never writes the default into the
binding spec. A missing default or unknown selected provider reports `Ready=False`
without changing an existing generated `SecretProviderClass`. Configuration is
loaded at startup, so propagate default changes and restart the operator to
reconcile existing bindings. This changes routing, not stored values; copy keys
and verify workload remounts before retiring the previous backend.

Google Secret Manager bindings use `auth: provider-adc`: the CSI provider reads
through its own cluster-scoped identity, while the operator uses a separate identity
for secret lifecycle operations. Applications are authorized through Kubernetes
bindings, not per-workload Google IAM. Raw SecretProviderClasses remain an
administrator escape hatch, enforced by the components chart's admission policy.

Vault/OpenBao providers authenticate with Kubernetes/JWT auth. The operator uses
its own pod service account token, logs in at `auth_path` (default
`auth/kubernetes`), and requests `operator_role` (default `podplane-operator`). Workload
CSI mounts authenticate separately as the workload pod service account using the
generated `SecretProviderClass` `roleName`.

The aggregated API endpoint uses HTTPS. Configure its serving address and certificate with
`--aggregated-api-bind-address`, `--aggregated-api-tls-cert-file`, and
`--aggregated-api-tls-private-key-file`.

`SecretProviderBinding.spec.syncToKubernetesSecrets` is disabled by default
because it causes provider secret values to be persisted into Kubernetes Secret
objects. To allow it, set `allow_sync_to_kubernetes_secrets: true` in the operator
config under `secrets` and annotate each permitted namespace with
`secrets.podplane.dev/allow-sync-to-kubernetes-secrets: "true"`.

For clients that cannot use `ClusterTrustBundle`, `certificates.trust_bundle_sync`
keeps the public workload CA bundle in the listed Secrets or ConfigMaps, checking
at startup and every 30 seconds but writing only changed data keys. It requires
`cluster.spiffe.trust_domain`; omit `resources` to disable it. `create_if_missing`
defaults to `false` and can be overridden per resource; enable it to create missing
targets (`Opaque` Secrets), or create them beforehand. Grant named `get`/`patch`
permissions and, when creation is enabled, namespace-scoped `create` permission
for that kind. Targets are never automatically deleted, private keys are never
copied, and the secret-value sync setting above does not apply. Failures mark the
operator unready and retry without stopping certificate issuance.

With `rbac.namespace_group_bindings: true`, the operator keeps RoleBindings for the
default Podplane groups (`podplane:managers` → `admin`, `podplane:operators` and
`podplane:editors` → `edit`, `podplane:viewers` → `view`) in every tenant
namespace: any namespace not prefixed `kube-` or `platform-` and not labelled
`rbac.podplane.dev/restricted: "true"`. It manages only RoleBindings labelled
`rbac.podplane.dev/managed: "true"`.

The components repository's `platform-rbac` chart installs a default Kubernetes
`ValidatingAdmissionPolicy` for Pods that use Secrets Store CSI volumes. Those
Pods must set an explicit, non-empty `spec.serviceAccountName`, and every mounted
Secrets Store CSI `secretProviderClass` must equal that service account name.
Pods that omit `serviceAccountName` are denied rather than being treated as the
Kubernetes `default` service account for this policy.

### Podplane Secrets

Adds a convention-based DX on top of the [secrets-store-csi-driver](https://secrets-store-csi-driver.sigs.k8s.io/).
  - Read path: enables `podplane secret` CLI functionality.
  - Write path: simplifies template configuration with a "binding" CRD.

This consists of:
  - A `SecretProviderBinding` CRD and controller that renders/manages Secrets Store CSI `SecretProviderClass` objects.
  - An aggregated API extension to create, update, delete, restore, and destroy upstream provider secrets.
  - Backend adapters for OpenBao/Vault KV-v2, AWS Secrets Manager, AWS Parameter Store, and GCP Secret Manager.

### Envoy SDS

`podplane-operator sds` supplies HTTPS certificates to Envoy over a Unix socket.
It reloads updated files without restarting Envoy; it does not issue or renew
certificates.

- **NLB ingress:** repeat `--domain-certificate=<resource>=<domain>` for each bundle.
- **Tunnel ingress:** use `--node-certificate=<domain>,<domain>,...` for the domains
  covered by the node's shared `node.pem` bundle.
- **Workload certificates:** repeat
  `--workload-certificate=<resource>=<service-DNS-name>` for each projected
  `podCertificate` bundle. The service name must be a lowercase DNS name, not an
  IP address or wildcard. Do not combine workload, domain, and node modes.

Domain and workload bundles use their SDS resource name as the filename under
`--certificates-dir`; no suffix is added. Names must be single path components
(not `.` or `..`), must be unique, and `node` is reserved.

```console
podplane-operator sds --node-certificate=example.com,example.net

podplane-operator sds \
  --certificates-dir=/var/run/podplane/workload-certificates \
  --workload-certificate=agent-router.pem=agent-router.podplane.svc
```

For the workload example, mount a projected `podCertificate` volume at
`/var/run/podplane/workload-certificates` with
`credentialBundlePath: agent-router.pem`. This single PEM file must contain one
private key and a leaf-first certificate chain; the key may precede or follow
the chain. SDS reads the file once per load so projected symlink-generation
rotation cannot mix keys and certificates from separate reads. Workload
validation checks the matched keypair, certificate validity periods, a non-CA
leaf, permission for TLS server authentication, the configured service hostname,
and signatures between supplied chain certificates. It does not require ingress
apex/wildcard SANs or restrict additional SANs. Client-side trust verification
still requires the appropriate CA bundle; SDS does not select trust roots.

SDS checks that certificates are valid and cover the configured domains. Missing
or invalid bundles prevent startup; invalid later updates leave the last valid
certificate in use, and a subsequent valid generation is published automatically.
Updates are independent per resource. `--poll-interval` defaults to `5s` and must
be positive. The socket defaults to `/var/run/podplane-sds/sds.sock`; the default
certificate directory remains `/var/run/podplane/ingress-certificates`.
SDS reads mounted files only: it does not fetch Kubernetes Secrets or access the
Kubernetes API. Metadata-only SDS reference Secrets, if needed by the Envoy
integration, are separate from these credential files.

## Helm Chart

The operator Helm chart lives in the Podplane components repository as the
[`podplane-operator` chart](https://github.com/podplane/components/tree/main/charts/podplane-operator).

The components repository also ships `podplane-operator-crds`, which vendors the
generated `SecretProviderBinding` CRD from this repository. Regenerate CRDs here
with `make generate-crds` and copy the generated CRD into the components chart
when the API changes.

## Learn More

Learn more about Podplane at the official project website: [podplane.dev](https://podplane.dev)

## License

Podplane is licensed under the Apache License, Version 2.0.
Copyright The Podplane Authors.

See the [LICENSE](./LICENSE) file for details.
