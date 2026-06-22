// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package controllers

// ProviderConfig contains the rendering settings for one CSI provider.
type ProviderConfig struct {
	Name string `json:"-"`    // Cluster-unique provider name from the providers map key.
	Kind string `json:"kind"` // Upstream Secrets Store CSI provider kind: aws, gcp, vault, openbao, or memory.

	// AWS options
	ObjectType string `json:"object_type,omitempty"` // object type for secrets-store-csi-provider-aws.
	// for ObjectType, "secretsmanager" is the default, "ssmparameter" is for AWS Parameter Store.
	Region string `json:"region,omitempty"` // AWS region for provider API calls.

	// GCP options
	ProjectID string `json:"project_id,omitempty"` // GCP project ID used in generated Secret Manager resource names.
	Location  string `json:"location,omitempty"`   // Optional GCP regional Secret Manager location.

	// Vault/OpenBao options
	Address   string `json:"address,omitempty"`    // Vault/OpenBao server address rendered into the SecretProviderClass.
	MountPath string `json:"mount_path,omitempty"` // Vault/OpenBao KV-v2 mount path. Defaults to secret.
}
