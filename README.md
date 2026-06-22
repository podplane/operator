# Podplane Operator

Podplane is an Open Source Kubernetes distribution & PaaS.

The Podplane Operator provides features which improve the PaaS developer experience (DX).

## Current Features

Podplane Secrets:

- Adds a convention-based DX on top of the [secrets-store-csi-driver](https://secrets-store-csi-driver.sigs.k8s.io/).
    - Read path: enables `podplane secrets` CLI functionality.
    - Write path: simplifies template configuration with a "binding" CRD.
- A `SecretProviderBinding` CRD and controller that renders/manages Secrets Store CSI `SecretProviderClass` objects.
- An aggregated API extension to create, update, delete, restore, and destroy upstream provider secrets.
- Backend adapters for OpenBao/Vault KV-v2, AWS Secrets Manager, AWS Parameter Store, and GCP Secret Manager.

## Configuration

The operator is configured with a JSON file passed to `podplane-operator --config`.
The config declares the Podplane cluster identity and the named secrets
providers the operator can use. The `providers` object intentionally matches
the Podplane cluster config `cluster.secrets.providers` shape: provider names
are map keys, and provider entries contain non-secret provider metadata.

Example:

```json
{
  "clusterID": "dev-cluster",
  "providers": {
    "openbao-local": {
      "kind": "openbao",
      "address": "https://podplane-local.example/vault/dev-cluster/v1",
      "mount_path": "secret"
    },
    "aws-secrets-manager": {
      "kind": "aws",
      "object_type": "secretsmanager",
      "region": "us-east-1"
    }
  }
}
```

`clusterID` identifies the Podplane cluster. The backend path prefix defaults to
`clusterID`. Each provider has safe fields such as `kind`, `object_type`,
`region`, `project_id`, `location`, `address`, or `mount_path`. Secret material
must not be placed inline. When Vault/OpenBao needs a token, mount it at
`/var/run/podplane/providers/<provider-name>/token`.

`SecretProviderBinding.spec.syncToKubernetesSecrets` is disabled by default
because it causes provider secret values to be persisted into Kubernetes Secret
objects. To allow it, set `allowSyncToKubernetesSecrets: true` in the operator
config and annotate each permitted namespace with
`secrets.podplane.dev/allow-sync-to-kubernetes-secrets: "true"`.

## Helm Chart

The operator Helm chart lives in the Podplane components repository as the
[`platform-podplane` chart](https://github.com/podplane/components/tree/main/charts/platform-podplane).

## Learn More

Learn more about Podplane at the official project website: [podplane.dev](https://podplane.dev)

## License

Podplane is licensed under the Apache License, Version 2.0.
Copyright The Podplane Authors.

See the [LICENSE](./LICENSE) file for details.
