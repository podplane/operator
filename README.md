# Podplane Operator

Podplane is an Open Source Kubernetes distribution & PaaS.

The Podplane Operator provides features which improve the PaaS developer experience (DX).

## Current Features

Podplane Secrets:

- Adds a convention-based DX on top of the [secrets-store-csi-driver](https://secrets-store-csi-driver.sigs.k8s.io/).
    - Read path: enables `podplane secret` CLI functionality.
    - Write path: simplifies template configuration with a "binding" CRD.
- A `SecretProviderBinding` CRD and controller that renders/manages Secrets Store CSI `SecretProviderClass` objects.
- An aggregated API extension to create, update, delete, restore, and destroy upstream provider secrets.
- Backend adapters for OpenBao/Vault KV-v2, AWS Secrets Manager, AWS Parameter Store, and GCP Secret Manager.

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
    }
  },
  "secrets": {
    "allow_sync_to_kubernetes_secrets": false,
    "key_rotation": "6h",
    "providers": {
      "openbao-local": {
        "kind": "openbao",
        "key_prefix": "shared-secrets",
        "address": "https://podplane-local.example/vault/dev-cluster/v1",
        "mount_path": "secret"
      },
      "aws-secrets-manager": {
        "kind": "aws",
        "object_type": "secretsmanager",
        "region": "us-east-1"
      }
    }
  },
  "registry": {
    "auth": {
      "enabled": true
    }
  }
}
```

`cluster.id` identifies the Podplane cluster. The backend path prefix defaults
to `cluster.id`. `cluster.oidc` is shared module identity configuration; the
registry token service validates Docker refresh-token exchanges against that
issuer and uses `cluster.oidc.client_id` as the audience, defaulting it to
`cluster.id` when omitted. Each secrets provider has safe fields such as `kind`,
`object_type`, `region`, `project_id`, `location`, `address`, or `mount_path`.
Secret material must not be placed inline. When Vault/OpenBao needs a token,
mount it at `/var/run/podplane/providers/<provider-name>/token`.

Registry auth is HTTPS-only and is intended for registry ingress `/token`
routing. Configure its bind address and serving certificate with
`--registry-auth-bind-address`, `--registry-auth-tls-cert-file`, and
`--registry-auth-tls-private-key-file`. The Helm chart should issue and mount a
service DNS certificate and configure Traefik/Gateway backend TLS trust in the
same style as Podplane web template workloads.

The aggregated API endpoint uses matching serving flags:
`--aggregated-api-bind-address`, `--aggregated-api-tls-cert-file`, and
`--aggregated-api-tls-private-key-file`.

`SecretProviderBinding.spec.syncToKubernetesSecrets` is disabled by default
because it causes provider secret values to be persisted into Kubernetes Secret
objects. To allow it, set `allow_sync_to_kubernetes_secrets: true` in the operator
config under `secrets` and annotate each permitted namespace with
`secrets.podplane.dev/allow-sync-to-kubernetes-secrets: "true"`.

The operator Helm chart also installs a default Kubernetes
`ValidatingAdmissionPolicy` for Pods that use Secrets Store CSI volumes. Those
Pods must set an explicit, non-empty `spec.serviceAccountName`, and every mounted
Secrets Store CSI `secretProviderClass` must equal that service account name.
Pods that omit `serviceAccountName` are denied rather than being treated as the
Kubernetes `default` service account for this policy.

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
