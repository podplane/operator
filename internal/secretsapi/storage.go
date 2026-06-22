// Podplane <https://podplane.dev>
// Copyright The Podplane Authors
// SPDX-License-Identifier: Apache-2.0

package secretsapi

import (
	"context"
	"errors"
	"fmt"

	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	request "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	kubernetes "k8s.io/client-go/kubernetes"

	"github.com/podplane/operator/internal/secretsbackend"
)

// PublicKeyStorage serves the publickeys resource from the current in-memory keyring.
type PublicKeyStorage struct{ Keys *KeyRing }

// New returns an empty PublicKey object.
func (p *PublicKeyStorage) New() runtime.Object { return &PublicKey{} }

// Destroy releases storage resources.
func (p *PublicKeyStorage) Destroy() {}

// NamespaceScoped reports that publickeys are cluster scoped.
func (p *PublicKeyStorage) NamespaceScoped() bool { return false }

// GetSingularName returns the singular resource name.
func (p *PublicKeyStorage) GetSingularName() string { return "publickey" }

// Get returns publickeys/latest.
func (p *PublicKeyStorage) Get(_ context.Context, name string, _ *metav1.GetOptions) (runtime.Object, error) {
	if name != "latest" {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: SchemeGroupVersion.Group, Resource: "publickeys"}, name)
	}
	key := p.Keys.PublicKey()
	return key.DeepCopyObject(), nil
}

// KeyspaceStorage serves named SecretProviderKeyspace resources from provider backends.
type KeyspaceStorage struct {
	ClusterID string
	Prefix    string
	Keys      *KeyRing
	Backends  *secretsbackend.Registry
	Kube      kubernetes.Interface
}

// New returns an empty SecretProviderKeyspace object.
func (s *KeyspaceStorage) New() runtime.Object { return &SecretProviderKeyspace{} }

// Destroy releases storage resources.
func (s *KeyspaceStorage) Destroy() {}

// NamespaceScoped reports that keyspaces are namespace scoped.
func (s *KeyspaceStorage) NamespaceScoped() bool { return true }

// GetSingularName returns the singular resource name.
func (s *KeyspaceStorage) GetSingularName() string { return "secretproviderkeyspace" }

// Get returns one named keyspace status object.
func (s *KeyspaceStorage) Get(ctx context.Context, name string, _ *metav1.GetOptions) (runtime.Object, error) {
	namespace, ok := request.NamespaceFrom(ctx)
	if !ok || namespace == "" {
		return nil, apierrors.NewBadRequest("namespace is required")
	}
	ks, b, err := s.backend(namespace, name)
	if err != nil {
		return nil, err
	}
	entries, err := b.List(ctx, ks)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	return s.response(namespace, name, ks.ProviderName, entries), nil
}

// Update applies create, update, and restore operations from the submitted object.
func (s *KeyspaceStorage) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, _ rest.ValidateObjectFunc, updateValidation rest.ValidateObjectUpdateFunc, _ bool, _ *metav1.UpdateOptions) (runtime.Object, bool, error) {
	namespace, ok := request.NamespaceFrom(ctx)
	if !ok || namespace == "" {
		return nil, false, apierrors.NewBadRequest("namespace is required")
	}
	ks, b, err := s.backend(namespace, name)
	if err != nil {
		return nil, false, err
	}
	oldObj := &SecretProviderKeyspace{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	newObj, err := objInfo.UpdatedObject(ctx, oldObj)
	if err != nil {
		return nil, false, err
	}
	obj, ok := newObj.(*SecretProviderKeyspace)
	if !ok {
		return nil, false, apierrors.NewBadRequest(fmt.Sprintf("expected SecretProviderKeyspace, got %T", newObj))
	}
	if err := updateValidation(ctx, obj, oldObj); err != nil {
		return nil, false, err
	}
	ops := make([]keyspaceOperation, 0, len(obj.Spec.Entries))
	requiredVerbs := sets.New[string]()
	for _, e := range obj.Spec.Entries {
		if err := secretsbackend.ValidateSegment("key", e.Key); err != nil {
			return nil, false, apierrors.NewBadRequest(err.Error())
		}
		op := keyspaceOperation{entry: e}
		switch e.Operation {
		case "create", "update":
			if e.EncryptedValue == nil {
				return nil, false, apierrors.NewBadRequest("encryptedValue is required")
			}
			if e.Operation == "update" {
				requiredVerbs.Insert("overwrite")
			}
			value, err := s.Keys.Decrypt(*e.EncryptedValue, AssociatedData(e.EncryptedValue.Algorithm, s.ClusterID, namespace, name, e.Key))
			if err != nil {
				var stale StaleKeyError
				if errors.As(err, &stale) {
					return nil, false, apierrors.NewConflict(keyspaceResource(), name, fmt.Errorf("stale public key"))
				}
				return nil, false, apierrors.NewBadRequest(err.Error())
			}
			op.value = value
		case "restore":
			requiredVerbs.Insert("restore")
		default:
			return nil, false, apierrors.NewBadRequest(fmt.Sprintf("unsupported operation %q", e.Operation))
		}
		ops = append(ops, op)
	}
	for _, verb := range sets.List(requiredVerbs) {
		if err := s.check(ctx, namespace, name, verb); err != nil {
			return nil, false, err
		}
	}
	entries := []secretsbackend.Entry{}
	for _, op := range ops {
		e := op.entry
		switch e.Operation {
		case "create", "update":
			var out secretsbackend.Entry
			var err error
			if e.Operation == "create" {
				out, err = b.Create(ctx, ks, e.Key, op.value)
			} else {
				out, err = b.Update(ctx, ks, e.Key, op.value)
			}
			if err != nil {
				return nil, false, backendError(err, name)
			}
			entries = append(entries, out)
		case "restore":
			out, err := b.Restore(ctx, ks, e.Key)
			if err != nil {
				return nil, false, backendError(err, name)
			}
			entries = append(entries, out)
		}
	}
	return s.response(namespace, name, ks.ProviderName, entries), false, nil
}

type keyspaceOperation struct {
	entry SecretProviderKeyspaceEntry
	value []byte
}

// Delete archives or permanently destroys keys in one keyspace.
func (s *KeyspaceStorage) Delete(ctx context.Context, name string, deleteValidation rest.ValidateObjectFunc, _ *metav1.DeleteOptions) (runtime.Object, bool, error) {
	namespace, ok := request.NamespaceFrom(ctx)
	if !ok || namespace == "" {
		return nil, false, apierrors.NewBadRequest("namespace is required")
	}
	ks, b, err := s.backend(namespace, name)
	if err != nil {
		return nil, false, err
	}
	if err := deleteValidation(ctx, &SecretProviderKeyspace{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}); err != nil {
		return nil, false, err
	}
	q := deleteQueryFrom(ctx)
	if q.key != "" {
		if err := secretsbackend.ValidateSegment("key", q.key); err != nil {
			return nil, false, apierrors.NewBadRequest(err.Error())
		}
	}
	if q.destroy {
		if err := s.check(ctx, namespace, name, "destroy"); err != nil {
			return nil, false, err
		}
		if q.key == "" {
			err = b.DestroyAll(ctx, ks)
		} else {
			err = b.Destroy(ctx, ks, q.key)
		}
		if err != nil {
			return nil, false, backendError(err, name)
		}
		return status("destroyed"), true, nil
	}
	if q.key == "" {
		err = b.ArchiveAll(ctx, ks)
	} else {
		err = b.Archive(ctx, ks, q.key)
	}
	if err != nil {
		return nil, false, backendError(err, name)
	}
	return status("archived"), true, nil
}

// backend resolves the requested keyspace and its configured provider backend.
func (s *KeyspaceStorage) backend(namespace, name string) (secretsbackend.Keyspace, secretsbackend.Backend, error) {
	ks, err := secretsbackend.NewKeyspace(s.Prefix, namespace, name)
	if err != nil {
		return secretsbackend.Keyspace{}, nil, apierrors.NewBadRequest(err.Error())
	}
	b, err := s.Backends.Backend(ks.ProviderName)
	if err != nil {
		return secretsbackend.Keyspace{}, nil, apierrors.NewNotFound(keyspaceResource(), name)
	}
	return ks, b, nil
}

// check performs a SubjectAccessReview for an operator-enforced custom verb.
func (s *KeyspaceStorage) check(ctx context.Context, ns, name, verb string) error {
	u, ok := request.UserFrom(ctx)
	if !ok {
		return apierrors.NewUnauthorized("authenticated user is required")
	}
	if s.Kube == nil {
		return apierrors.NewInternalError(fmt.Errorf("authorization client is not configured"))
	}
	extra := map[string]authv1.ExtraValue{}
	for k, v := range u.GetExtra() {
		extra[k] = authv1.ExtraValue(v)
	}
	sar := &authv1.SubjectAccessReview{Spec: authv1.SubjectAccessReviewSpec{
		User:   u.GetName(),
		UID:    u.GetUID(),
		Groups: sets.List(sets.New(u.GetGroups()...)),
		Extra:  extra,
		ResourceAttributes: &authv1.ResourceAttributes{
			Namespace: ns,
			Group:     SchemeGroupVersion.Group,
			Version:   SchemeGroupVersion.Version,
			Resource:  "secretproviderkeyspaces",
			Name:      name,
			Verb:      verb,
		},
	}}
	res, err := s.Kube.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return apierrors.NewInternalError(err)
	}
	if !res.Status.Allowed {
		return apierrors.NewForbidden(keyspaceResource(), name, fmt.Errorf("%s access denied", verb))
	}
	return nil
}

// response builds a metadata-only SecretProviderKeyspace status object.
func (s *KeyspaceStorage) response(ns, name, provider string, entries []secretsbackend.Entry) *SecretProviderKeyspace {
	out := make([]SecretProviderKeyspaceStatusEntry, 0, len(entries))
	for _, e := range entries {
		var t *metav1.Time
		if e.RestoreUntil != nil {
			mt := metav1.NewTime(*e.RestoreUntil)
			t = &mt
		}
		out = append(out, SecretProviderKeyspaceStatusEntry{Key: e.Key, Status: e.Status, BackendPath: e.BackendPath, RestoreUntil: t})
	}
	return &SecretProviderKeyspace{TypeMeta: metav1.TypeMeta{APIVersion: GroupVersion, Kind: "SecretProviderKeyspace"}, ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Status: SecretProviderKeyspaceStatus{Provider: provider, Entries: out}}
}

// backendError maps backend adapter errors to Kubernetes API errors.
func backendError(err error, name string) error {
	switch {
	case errors.Is(err, secretsbackend.ErrNotFound):
		return apierrors.NewNotFound(keyspaceResource(), name)
	case errors.Is(err, secretsbackend.ErrAlreadyExists), errors.Is(err, secretsbackend.ErrArchived), errors.Is(err, secretsbackend.ErrActive):
		return apierrors.NewConflict(keyspaceResource(), name, err)
	case errors.Is(err, secretsbackend.ErrArchiveUnsupported), errors.Is(err, secretsbackend.ErrRestoreUnsupported), errors.Is(err, secretsbackend.ErrDestroyUnsupported):
		return apierrors.NewInvalid(SchemeGroupVersion.WithKind("SecretProviderKeyspace").GroupKind(), name, nil)
	default:
		return apierrors.NewInternalError(err)
	}
}

// keyspaceResource returns the GroupResource for SecretProviderKeyspace errors and SARs.
func keyspaceResource() schema.GroupResource {
	return schema.GroupResource{Group: SchemeGroupVersion.Group, Resource: "secretproviderkeyspaces"}
}

// status returns a Kubernetes success Status object with the supplied message.
func status(msg string) *metav1.Status {
	return &metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusSuccess, Reason: metav1.StatusReason("Success"), Message: msg, Code: 200}
}

type deleteQuery struct {
	key     string
	destroy bool
}

type deleteQueryKey struct{}

// WithDeleteQuery records legacy key/destroy delete query parameters for storage.
func WithDeleteQuery(ctx context.Context, key string, destroy bool) context.Context {
	return context.WithValue(ctx, deleteQueryKey{}, deleteQuery{key: key, destroy: destroy})
}

// deleteQueryFrom returns legacy key/destroy delete parameters stored on the context.
func deleteQueryFrom(ctx context.Context) deleteQuery {
	q, _ := ctx.Value(deleteQueryKey{}).(deleteQuery)
	return q
}
