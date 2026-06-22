// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsbackend

import (
	"errors"
	"testing"

	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

func TestGCPDestroyVersionRequiresArchivedVersion(t *testing.T) {
	destroy, err := gcpDestroyVersion(secretmanagerpb.SecretVersion_ENABLED)
	if !errors.Is(err, ErrActive) {
		t.Fatalf("enabled version error = %v, want ErrActive", err)
	}
	if destroy {
		t.Fatal("enabled version must not be destroyed")
	}

	destroy, err = gcpDestroyVersion(secretmanagerpb.SecretVersion_DISABLED)
	if err != nil {
		t.Fatalf("disabled version error = %v", err)
	}
	if !destroy {
		t.Fatal("disabled version should be destroyed")
	}

	destroy, err = gcpDestroyVersion(secretmanagerpb.SecretVersion_DESTROYED)
	if err != nil {
		t.Fatalf("destroyed version error = %v", err)
	}
	if destroy {
		t.Fatal("already destroyed version should be skipped")
	}
}
