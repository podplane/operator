// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsbackend

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// GCPSecretManagerBackend stores keys in Google Secret Manager.
type GCPSecretManagerBackend struct {
	name, projectID, location string
	client                    *secretmanager.Client
}

// NewGCPSecretManagerBackend creates a Google Secret Manager backend.
func NewGCPSecretManagerBackend(ctx context.Context, name, projectID, location string) (*GCPSecretManagerBackend, error) {
	c, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return &GCPSecretManagerBackend{name: name, projectID: projectID, location: location, client: c}, nil
}

// ProviderName returns the configured provider name.
func (g *GCPSecretManagerBackend) ProviderName() string { return g.name }

// ProviderKind returns the CSI provider kind.
func (g *GCPSecretManagerBackend) ProviderKind() string { return "gcp" }

// parent returns the Google Secret Manager parent resource.
func (g *GCPSecretManagerBackend) parent() string {
	if g.location != "" {
		return fmt.Sprintf("projects/%s/locations/%s", g.projectID, g.location)
	}
	return fmt.Sprintf("projects/%s", g.projectID)
}

// secretName returns the Google Secret Manager secret resource name.
func (g *GCPSecretManagerBackend) secretName(id string) string { return g.parent() + "/secrets/" + id }

// versionName returns the latest version resource name for id.
func (g *GCPSecretManagerBackend) versionName(id string) string {
	return g.secretName(id) + "/versions/latest"
}

// Create creates a new secret and initial version.
func (g *GCPSecretManagerBackend) Create(ctx context.Context, ks Keyspace, key string, value []byte) (Entry, error) {
	id, err := ks.GCPSecretID(key)
	if err != nil {
		return Entry{}, err
	}
	_, err = g.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{Parent: g.parent(), SecretId: id, Secret: &secretmanagerpb.Secret{Replication: &secretmanagerpb.Replication{Replication: &secretmanagerpb.Replication_Automatic_{Automatic: &secretmanagerpb.Replication_Automatic{}}}, Labels: map[string]string{"podplane-cluster-prefix": ks.Prefix, "podplane-namespace": ks.Namespace, "podplane-binding": ks.BindingName}}})
	if err != nil && !strings.Contains(err.Error(), "AlreadyExists") {
		return Entry{}, err
	}
	if strings.Contains(fmt.Sprint(err), "AlreadyExists") {
		state, exists, statusErr := g.latestSecretVersionState(ctx, id)
		if statusErr == nil && state == secretmanagerpb.SecretVersion_DISABLED {
			return Entry{}, ArchivedError(key)
		}
		if statusErr != nil || exists && state == secretmanagerpb.SecretVersion_ENABLED {
			return Entry{}, ErrAlreadyExists
		}
	}
	_, err = g.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{Parent: g.secretName(id), Payload: &secretmanagerpb.SecretPayload{Data: value}})
	if err != nil {
		return Entry{}, err
	}
	return Entry{Key: key, Status: StatusActive, BackendPath: id}, nil
}

// Update adds a new secret version.
func (g *GCPSecretManagerBackend) Update(ctx context.Context, ks Keyspace, key string, value []byte) (Entry, error) {
	id, err := ks.GCPSecretID(key)
	if err != nil {
		return Entry{}, err
	}
	state, exists, err := g.latestSecretVersionState(ctx, id)
	if err != nil {
		return Entry{}, err
	}
	if !exists {
		return Entry{}, ErrNotFound
	}
	if state == secretmanagerpb.SecretVersion_DISABLED {
		return Entry{}, ArchivedError(key)
	}
	if state != secretmanagerpb.SecretVersion_ENABLED {
		return Entry{}, ErrNotFound
	}
	_, err = g.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{Parent: g.secretName(id), Payload: &secretmanagerpb.SecretPayload{Data: value}})
	if err != nil {
		return Entry{}, err
	}
	return Entry{Key: key, Status: StatusActive, BackendPath: id}, nil
}

// List lists Google Secret Manager secrets in a keyspace.
func (g *GCPSecretManagerBackend) List(ctx context.Context, ks Keyspace) ([]Entry, error) {
	prefix := strings.Join([]string{ks.Prefix, ks.Namespace, ks.BindingName}, "_") + "_"
	it := g.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{Parent: g.parent()})
	out := []Entry{}
	for {
		s, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		id := s.Name[strings.LastIndex(s.Name, "/")+1:]
		if strings.HasPrefix(id, prefix) {
			key := strings.TrimPrefix(id, prefix)
			st := StatusActive
			state, exists, err := g.latestSecretVersionState(ctx, id)
			if err != nil {
				st = StatusUnknown
			} else if !exists || state == secretmanagerpb.SecretVersion_DESTROYED {
				continue
			} else if state == secretmanagerpb.SecretVersion_DISABLED {
				st = StatusArchived
			}
			out = append(out, Entry{Key: key, Status: st, BackendPath: id})
		}
	}
	return out, nil
}

// Archive disables the latest secret version.
func (g *GCPSecretManagerBackend) Archive(ctx context.Context, ks Keyspace, key string) error {
	id, err := ks.GCPSecretID(key)
	if err != nil {
		return err
	}
	_, err = g.client.DisableSecretVersion(ctx, &secretmanagerpb.DisableSecretVersionRequest{Name: g.versionName(id)})
	return err
}

// ArchiveAll archives every key in a keyspace.
func (g *GCPSecretManagerBackend) ArchiveAll(ctx context.Context, ks Keyspace) error {
	es, err := g.List(ctx, ks)
	if err != nil {
		return err
	}
	for _, e := range es {
		if err := g.Archive(ctx, ks, e.Key); err != nil {
			return err
		}
	}
	return nil
}

// Restore enables the latest secret version.
func (g *GCPSecretManagerBackend) Restore(ctx context.Context, ks Keyspace, key string) (Entry, error) {
	id, err := ks.GCPSecretID(key)
	if err != nil {
		return Entry{}, err
	}
	_, err = g.client.EnableSecretVersion(ctx, &secretmanagerpb.EnableSecretVersionRequest{Name: g.versionName(id)})
	if err != nil {
		return Entry{}, err
	}
	return Entry{Key: key, Status: StatusActive, BackendPath: id}, nil
}

// Destroy permanently destroys retained versions of a Google Secret Manager secret.
func (g *GCPSecretManagerBackend) Destroy(ctx context.Context, ks Keyspace, key string) error {
	id, err := ks.GCPSecretID(key)
	if err != nil {
		return err
	}
	vit := g.client.ListSecretVersions(ctx, &secretmanagerpb.ListSecretVersionsRequest{Parent: g.secretName(id)})
	destroyed := false
	for {
		v, err := vit.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if grpcstatus.Code(err) == codes.NotFound {
				return ErrNotFound
			}
			return err
		}
		destroy, err := gcpDestroyVersion(v.State)
		if err != nil {
			return err
		}
		if !destroy {
			continue
		}
		if _, err := g.client.DestroySecretVersion(ctx, &secretmanagerpb.DestroySecretVersionRequest{Name: v.Name}); err != nil {
			return err
		}
		destroyed = true
	}
	if !destroyed {
		return ErrNotFound
	}
	return nil
}

// gcpDestroyVersion permits permanent destroy only for archived/disabled versions.
func gcpDestroyVersion(state secretmanagerpb.SecretVersion_State) (bool, error) {
	switch state {
	case secretmanagerpb.SecretVersion_ENABLED:
		return false, ErrActive
	case secretmanagerpb.SecretVersion_DISABLED:
		return true, nil
	default:
		return false, nil
	}
}

// DestroyAll deletes every key in a keyspace.
func (g *GCPSecretManagerBackend) DestroyAll(ctx context.Context, ks Keyspace) error {
	es, err := g.List(ctx, ks)
	if err != nil {
		return err
	}
	for _, e := range es {
		if err := g.Destroy(ctx, ks, e.Key); err != nil {
			return err
		}
	}
	return nil
}

// latestSecretVersionState returns the state of the version addressed by versions/latest.
func (g *GCPSecretManagerBackend) latestSecretVersionState(ctx context.Context, id string) (secretmanagerpb.SecretVersion_State, bool, error) {
	v, err := g.client.GetSecretVersion(ctx, &secretmanagerpb.GetSecretVersionRequest{Name: g.versionName(id)})
	if err != nil {
		if grpcstatus.Code(err) == codes.NotFound {
			return secretmanagerpb.SecretVersion_STATE_UNSPECIFIED, false, nil
		}
		return secretmanagerpb.SecretVersion_STATE_UNSPECIFIED, false, err
	}
	return v.State, true, nil
}
