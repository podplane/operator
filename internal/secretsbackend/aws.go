// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsbackend

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/smithy-go"
)

// AWSSecretsManagerBackend stores keys in AWS Secrets Manager.
type AWSSecretsManagerBackend struct {
	name               string
	client             *sm.Client
	recoveryWindowDays int64
}

// NewAWSSecretsManagerBackend creates an AWS Secrets Manager backend.
func NewAWSSecretsManagerBackend(ctx context.Context, name, region string, recoveryDays int64) (*AWSSecretsManagerBackend, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	if recoveryDays == 0 {
		recoveryDays = 30
	}
	return &AWSSecretsManagerBackend{name: name, client: sm.NewFromConfig(cfg), recoveryWindowDays: recoveryDays}, nil
}

// ProviderName returns the configured provider name.
func (a *AWSSecretsManagerBackend) ProviderName() string { return a.name }

// ProviderKind returns the CSI provider kind.
func (a *AWSSecretsManagerBackend) ProviderKind() string { return "aws" }

// Create creates a new Secrets Manager secret.
func (a *AWSSecretsManagerBackend) Create(ctx context.Context, ks Keyspace, key string, value []byte) (Entry, error) {
	p, err := ks.SlashPath(key)
	if err != nil {
		return Entry{}, err
	}
	_, err = a.client.CreateSecret(ctx, &sm.CreateSecretInput{Name: aws.String(p), SecretString: aws.String(string(value)), Tags: []smtypes.Tag{{Key: aws.String("podplane.dev/cluster-prefix"), Value: aws.String(ks.Prefix)}, {Key: aws.String("podplane.dev/namespace"), Value: aws.String(ks.Namespace)}, {Key: aws.String("podplane.dev/binding"), Value: aws.String(ks.BindingName)}}})
	if err != nil {
		switch awsErrorCode(err) {
		case "ResourceExistsException":
			return Entry{}, ErrAlreadyExists
		case "InvalidRequestException":
			if strings.Contains(strings.ToLower(err.Error()), "deletion") {
				return Entry{}, ArchivedError(key)
			}
		}
		return Entry{}, err
	}
	return Entry{Key: key, Status: StatusActive, BackendPath: p}, nil
}

// Update writes a new Secrets Manager secret version.
func (a *AWSSecretsManagerBackend) Update(ctx context.Context, ks Keyspace, key string, value []byte) (Entry, error) {
	p, err := ks.SlashPath(key)
	if err != nil {
		return Entry{}, err
	}
	_, err = a.client.PutSecretValue(ctx, &sm.PutSecretValueInput{SecretId: aws.String(p), SecretString: aws.String(string(value))})
	if err != nil {
		switch awsErrorCode(err) {
		case "ResourceNotFoundException":
			return Entry{}, ErrNotFound
		case "InvalidRequestException":
			if strings.Contains(strings.ToLower(err.Error()), "deletion") {
				return Entry{}, ArchivedError(key)
			}
		}
		return Entry{}, err
	}
	return Entry{Key: key, Status: StatusActive, BackendPath: p}, nil
}

// List lists Secrets Manager secrets in a keyspace.
func (a *AWSSecretsManagerBackend) List(ctx context.Context, ks Keyspace) ([]Entry, error) {
	prefix := "/" + strings.Join([]string{ks.Prefix, ks.Namespace, ks.BindingName}, "/") + "/"
	out := []Entry{}
	var token *string
	for {
		res, err := a.client.ListSecrets(ctx, &sm.ListSecretsInput{IncludePlannedDeletion: aws.Bool(true), NextToken: token})
		if err != nil {
			return nil, err
		}
		for _, s := range res.SecretList {
			if s.Name != nil && strings.HasPrefix(*s.Name, prefix) {
				st := StatusActive
				var until *time.Time
				if s.DeletedDate != nil {
					st = StatusArchived
					until = s.DeletedDate
				}
				out = append(out, Entry{Key: strings.TrimPrefix(*s.Name, prefix), Status: st, BackendPath: *s.Name, RestoreUntil: until})
			}
		}
		if res.NextToken == nil {
			break
		}
		token = res.NextToken
	}
	return out, nil
}

// Archive schedules recoverable deletion of a Secrets Manager secret.
func (a *AWSSecretsManagerBackend) Archive(ctx context.Context, ks Keyspace, key string) error {
	p, err := ks.SlashPath(key)
	if err != nil {
		return err
	}
	_, err = a.client.DeleteSecret(ctx, &sm.DeleteSecretInput{SecretId: aws.String(p), RecoveryWindowInDays: aws.Int64(a.recoveryWindowDays)})
	return err
}

// ArchiveAll archives every key in a keyspace.
func (a *AWSSecretsManagerBackend) ArchiveAll(ctx context.Context, ks Keyspace) error {
	es, err := a.List(ctx, ks)
	if err != nil {
		return err
	}
	for _, e := range es {
		if err := a.Archive(ctx, ks, e.Key); err != nil {
			return err
		}
	}
	return nil
}

// Restore restores a scheduled-for-deletion secret.
func (a *AWSSecretsManagerBackend) Restore(ctx context.Context, ks Keyspace, key string) (Entry, error) {
	p, err := ks.SlashPath(key)
	if err != nil {
		return Entry{}, err
	}
	_, err = a.client.RestoreSecret(ctx, &sm.RestoreSecretInput{SecretId: aws.String(p)})
	if err != nil {
		return Entry{}, err
	}
	return Entry{Key: key, Status: StatusActive, BackendPath: p}, nil
}

// Destroy permanently deletes a Secrets Manager secret.
func (a *AWSSecretsManagerBackend) Destroy(ctx context.Context, ks Keyspace, key string) error {
	p, err := ks.SlashPath(key)
	if err != nil {
		return err
	}
	_, err = a.client.DeleteSecret(ctx, &sm.DeleteSecretInput{SecretId: aws.String(p), ForceDeleteWithoutRecovery: aws.Bool(true)})
	return err
}

// DestroyAll permanently deletes every key in a keyspace.
func (a *AWSSecretsManagerBackend) DestroyAll(ctx context.Context, ks Keyspace) error {
	es, err := a.List(ctx, ks)
	if err != nil {
		return err
	}
	for _, e := range es {
		if err := a.Destroy(ctx, ks, e.Key); err != nil {
			return err
		}
	}
	return nil
}

// AWSParameterStoreBackend stores keys in AWS Systems Manager Parameter Store.
type AWSParameterStoreBackend struct {
	name   string
	client *ssm.Client
}

// NewAWSParameterStoreBackend creates an AWS Parameter Store backend.
func NewAWSParameterStoreBackend(ctx context.Context, name, region string) (*AWSParameterStoreBackend, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return &AWSParameterStoreBackend{name: name, client: ssm.NewFromConfig(cfg)}, nil
}

// ProviderName returns the configured provider name.
func (a *AWSParameterStoreBackend) ProviderName() string { return a.name }

// ProviderKind returns the CSI provider kind.
func (a *AWSParameterStoreBackend) ProviderKind() string { return "aws" }

// Create creates a new Parameter Store parameter.
func (a *AWSParameterStoreBackend) Create(ctx context.Context, ks Keyspace, key string, value []byte) (Entry, error) {
	p, err := ks.SlashPath(key)
	if err != nil {
		return Entry{}, err
	}
	_, err = a.client.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String(p), Value: aws.String(string(value)), Type: "SecureString", Overwrite: aws.Bool(false)})
	if err != nil {
		if awsErrorCode(err) == "ParameterAlreadyExists" {
			return Entry{}, ErrAlreadyExists
		}
		return Entry{}, err
	}
	return Entry{Key: key, Status: StatusActive, BackendPath: p}, nil
}

// Update overwrites an existing Parameter Store parameter.
func (a *AWSParameterStoreBackend) Update(ctx context.Context, ks Keyspace, key string, value []byte) (Entry, error) {
	p, err := ks.SlashPath(key)
	if err != nil {
		return Entry{}, err
	}
	if _, err := a.client.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(p), WithDecryption: aws.Bool(false)}); err != nil {
		if awsErrorCode(err) == "ParameterNotFound" {
			return Entry{}, ErrNotFound
		}
		return Entry{}, err
	}
	_, err = a.client.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String(p), Value: aws.String(string(value)), Type: "SecureString", Overwrite: aws.Bool(true)})
	if err != nil {
		return Entry{}, err
	}
	return Entry{Key: key, Status: StatusActive, BackendPath: p}, nil
}

// List lists Parameter Store parameters in a keyspace.
func (a *AWSParameterStoreBackend) List(ctx context.Context, ks Keyspace) ([]Entry, error) {
	pp := "/" + strings.Join([]string{ks.Prefix, ks.Namespace, ks.BindingName}, "/")
	out := []Entry{}
	var token *string
	for {
		res, err := a.client.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{Path: aws.String(pp), Recursive: aws.Bool(false), WithDecryption: aws.Bool(false), NextToken: token})
		if err != nil {
			return nil, err
		}
		for _, p := range res.Parameters {
			if p.Name != nil {
				out = append(out, Entry{Key: strings.TrimPrefix(*p.Name, pp+"/"), Status: StatusActive, BackendPath: *p.Name})
			}
		}
		if res.NextToken == nil {
			break
		}
		token = res.NextToken
	}
	return out, nil
}

// Archive reports that Parameter Store does not support recoverable delete.
func (a *AWSParameterStoreBackend) Archive(context.Context, Keyspace, string) error {
	return ErrArchiveUnsupported
}

// ArchiveAll reports that Parameter Store does not support recoverable delete.
func (a *AWSParameterStoreBackend) ArchiveAll(context.Context, Keyspace) error {
	return ErrArchiveUnsupported
}

// Restore reports that Parameter Store does not support restore.
func (a *AWSParameterStoreBackend) Restore(context.Context, Keyspace, string) (Entry, error) {
	return Entry{}, ErrRestoreUnsupported
}

// Destroy deletes a Parameter Store parameter.
func (a *AWSParameterStoreBackend) Destroy(ctx context.Context, ks Keyspace, key string) error {
	p, err := ks.SlashPath(key)
	if err != nil {
		return err
	}
	_, err = a.client.DeleteParameter(ctx, &ssm.DeleteParameterInput{Name: aws.String(p)})
	return err
}

// DestroyAll deletes every parameter in a keyspace.
func (a *AWSParameterStoreBackend) DestroyAll(ctx context.Context, ks Keyspace) error {
	es, err := a.List(ctx, ks)
	if err != nil {
		return err
	}
	for _, e := range es {
		if err := a.Destroy(ctx, ks, e.Key); err != nil {
			return err
		}
	}
	return nil
}

// awsErrorCode returns the modeled AWS API error code, if available.
func awsErrorCode(err error) string {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return ""
	}
	return apiErr.ErrorCode()
}
