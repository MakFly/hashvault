// Package registry stores what hashvault knows besides secret values:
// principals, policies, publication targets and publication records. It
// lives in the same OpenBao KV v2 mount as the secrets, under "_sys/", a
// prefix no environment can take (environments start with a letter). KV
// versioning keeps the history of every change.
//
// Nothing here is a secret value. Keys that are secret (the vault's signing
// keys) are stored as ordinary hashvault secrets, sealed in envelopes.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/MakFly/hashvault/internal/authn"
	"github.com/MakFly/hashvault/internal/iam"
	"github.com/MakFly/hashvault/internal/openbao"
	"github.com/MakFly/hashvault/internal/target"
)

const root = "_sys"

var (
	// ErrNotFound reports a missing object.
	ErrNotFound = errors.New("registry: not found")
	// ErrInvalid reports an object that fails validation.
	ErrInvalid = errors.New("registry: invalid")
	// ErrConflict reports a concurrent change.
	ErrConflict = errors.New("registry: changed concurrently, retry")

	principalPattern = regexp.MustCompile(`^(human|machine|ci|workload|breakglass)/[a-z0-9][a-z0-9._@-]{0,126}$`)
	namePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// Registry reads and writes the _sys tree.
type Registry struct {
	kv    *openbao.Client
	mount string
}

// New returns a registry on a KV v2 mount.
func New(kv *openbao.Client, mount string) *Registry {
	return &Registry{kv: kv, mount: mount}
}

// get decodes the current version of path into out and returns that version.
func (r *Registry) get(ctx context.Context, path string, out any) (int, error) {
	e, err := r.kv.KVGet(ctx, r.mount, root+"/"+path, 0)
	if errors.Is(err, openbao.ErrNotFound) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if e.Destroyed || e.Deleted {
		return 0, ErrNotFound
	}
	if err := json.Unmarshal([]byte(e.Data["doc"]), out); err != nil {
		return 0, fmt.Errorf("registry: %s is corrupted: %w", path, err)
	}
	return e.Version, nil
}

// put writes doc at path if its current version is still cas.
func (r *Registry) put(ctx context.Context, path string, doc any, cas int) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = r.kv.KVPut(ctx, r.mount, root+"/"+path, map[string]string{"doc": string(data)}, cas)
	if errors.Is(err, openbao.ErrCASMismatch) {
		return ErrConflict
	}
	return err
}

func (r *Registry) currentVersion(ctx context.Context, path string) (int, error) {
	md, err := r.kv.KVMetadata(ctx, r.mount, root+"/"+path)
	if errors.Is(err, openbao.ErrNotFound) {
		return 0, nil
	}
	return md.CurrentVersion, err
}

func (r *Registry) list(ctx context.Context, prefix string) ([]string, error) {
	keys, err := r.kv.KVList(ctx, r.mount, root+"/"+prefix)
	if err != nil {
		return nil, err
	}
	slices.Sort(keys)
	return keys, nil
}

// ---- Principals -----------------------------------------------------------

// Principal is an identity allowed to authenticate.
type Principal struct {
	Name     string            `json:"name"`
	SSHKey   string            `json:"ssh_key"`
	Tags     map[string]string `json:"tags,omitempty"`
	Policies []string          `json:"policies,omitempty"`
	// Boundary policies only restrict; HasBoundary with no policy denies all.
	Boundary    []string  `json:"boundary,omitempty"`
	HasBoundary bool      `json:"has_boundary,omitempty"`
	Disabled    bool      `json:"disabled,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Type is the principal type, the part before the slash.
func (p Principal) Type() string {
	t, _, _ := strings.Cut(p.Name, "/")
	return t
}

// Validate checks the name, the key and the attached policy names.
func (p Principal) Validate() error {
	if !principalPattern.MatchString(p.Name) {
		return fmt.Errorf("%w: principal name %q must match %s", ErrInvalid, p.Name, principalPattern)
	}
	key, err := authn.ParseKey(p.SSHKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if p.Type() == "human" && key.Type() != "sk-ssh-ed25519@openssh.com" {
		return fmt.Errorf("%w: a human principal needs a FIDO2 key (sk-ssh-ed25519)", ErrInvalid)
	}
	for _, n := range append(slices.Clone(p.Policies), p.Boundary...) {
		if !namePattern.MatchString(n) {
			return fmt.Errorf("%w: policy name %q", ErrInvalid, n)
		}
	}
	for k := range p.Tags {
		if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`).MatchString(k) {
			return fmt.Errorf("%w: tag %q", ErrInvalid, k)
		}
	}
	return nil
}

// Authn returns what the authenticator needs.
func (p Principal) Authn() (authn.Principal, error) {
	key, err := authn.ParseKey(p.SSHKey)
	if err != nil {
		return authn.Principal{}, err
	}
	return authn.Principal{Name: p.Name, Type: p.Type(), Key: key}, nil
}

// PutPrincipal creates a principal. It refuses to replace an existing one:
// changes go through Attach, Detach and Disable, which keep the key.
func (r *Registry) PutPrincipal(ctx context.Context, p Principal) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	err := r.put(ctx, "principals/"+p.Name, p, 0)
	if errors.Is(err, ErrConflict) {
		return fmt.Errorf("%w: principal %s already exists", ErrInvalid, p.Name)
	}
	return err
}

// GetPrincipal reads a principal.
func (r *Registry) GetPrincipal(ctx context.Context, name string) (Principal, error) {
	if !principalPattern.MatchString(name) {
		return Principal{}, ErrNotFound
	}
	var p Principal
	_, err := r.get(ctx, "principals/"+name, &p)
	return p, err
}

// ListPrincipals lists principal names.
func (r *Registry) ListPrincipals(ctx context.Context) ([]string, error) {
	types, err := r.list(ctx, "principals")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, t := range types {
		names, err := r.list(ctx, "principals/"+strings.TrimSuffix(t, "/"))
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			out = append(out, strings.TrimSuffix(t, "/")+"/"+n)
		}
	}
	return out, nil
}

// UpdatePrincipal applies change to a principal with check-and-set.
func (r *Registry) UpdatePrincipal(ctx context.Context, name string, change func(*Principal) error) error {
	var p Principal
	v, err := r.get(ctx, "principals/"+name, &p)
	if err != nil {
		return err
	}
	key := p.SSHKey
	if err := change(&p); err != nil {
		return err
	}
	if p.Name != name || p.SSHKey != key {
		return fmt.Errorf("%w: a principal's name and key never change; create a new principal", ErrInvalid)
	}
	if err := p.Validate(); err != nil {
		return err
	}
	return r.put(ctx, "principals/"+name, p, v)
}

// ---- Policies ---------------------------------------------------------------

type policyDoc struct {
	Document json.RawMessage `json:"document"`
}

// PutPolicy validates and stores a policy document under name.
func (r *Registry) PutPolicy(ctx context.Context, name string, document []byte) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("%w: policy name %q", ErrInvalid, name)
	}
	if _, err := iam.Parse(document); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	v, err := r.currentVersion(ctx, "policies/"+name)
	if err != nil {
		return err
	}
	return r.put(ctx, "policies/"+name, policyDoc{Document: document}, v)
}

// GetPolicy returns a parsed policy.
func (r *Registry) GetPolicy(ctx context.Context, name string) (iam.Policy, []byte, error) {
	if !namePattern.MatchString(name) {
		return iam.Policy{}, nil, ErrNotFound
	}
	var d policyDoc
	if _, err := r.get(ctx, "policies/"+name, &d); err != nil {
		return iam.Policy{}, nil, err
	}
	p, err := iam.Parse(d.Document)
	return p, d.Document, err
}

// ListPolicies lists policy names.
func (r *Registry) ListPolicies(ctx context.Context) ([]string, error) {
	return r.list(ctx, "policies")
}

// PolicySet loads everything attached to a principal. A missing policy is an
// error, not an empty policy: authorization fails closed.
func (r *Registry) PolicySet(ctx context.Context, p Principal) (iam.PolicySet, error) {
	set := iam.PolicySet{HasBoundary: p.HasBoundary || len(p.Boundary) > 0}
	for _, n := range p.Policies {
		pol, _, err := r.GetPolicy(ctx, n)
		if err != nil {
			return iam.PolicySet{}, fmt.Errorf("registry: policy %s attached to %s: %w", n, p.Name, err)
		}
		set.Identity = append(set.Identity, iam.NamedPolicy{Name: n, Policy: pol})
	}
	for _, n := range p.Boundary {
		pol, _, err := r.GetPolicy(ctx, n)
		if err != nil {
			return iam.PolicySet{}, fmt.Errorf("registry: boundary %s of %s: %w", n, p.Name, err)
		}
		set.Boundary = append(set.Boundary, iam.NamedPolicy{Name: "boundary:" + n, Policy: pol})
	}
	return set, nil
}

// ---- Targets ----------------------------------------------------------------

// Target is a registered publication target. Config is kind-specific JSON,
// interpreted by the daemon when it builds the adapter.
type Target struct {
	Name   string          `json:"name"`
	Kind   target.Kind     `json:"kind"`
	Env    string          `json:"env"`
	Config json.RawMessage `json:"config"`
}

// PutTarget registers or updates a target.
func (r *Registry) PutTarget(ctx context.Context, t Target) error {
	if !namePattern.MatchString(t.Name) {
		return fmt.Errorf("%w: target name %q", ErrInvalid, t.Name)
	}
	if !slices.Contains(target.Kinds, t.Kind) {
		return fmt.Errorf("%w: target kind %q", ErrInvalid, t.Kind)
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(t.Env) {
		return fmt.Errorf("%w: target env %q", ErrInvalid, t.Env)
	}
	if !json.Valid(t.Config) {
		return fmt.Errorf("%w: target config is not JSON", ErrInvalid)
	}
	v, err := r.currentVersion(ctx, "targets/"+t.Name)
	if err != nil {
		return err
	}
	return r.put(ctx, "targets/"+t.Name, t, v)
}

// GetTarget reads a target.
func (r *Registry) GetTarget(ctx context.Context, name string) (Target, error) {
	if !namePattern.MatchString(name) {
		return Target{}, ErrNotFound
	}
	var t Target
	_, err := r.get(ctx, "targets/"+name, &t)
	return t, err
}

// ListTargets lists target names.
func (r *Registry) ListTargets(ctx context.Context) ([]string, error) {
	return r.list(ctx, "targets")
}

// ---- Publications ------------------------------------------------------------

// Publication is the last state hashvault published for an app on a target.
// For host targets it is the inventory, and the source of a rollback.
type Publication struct {
	Target   string            `json:"target"`
	App      string            `json:"app"`
	Versions map[string]uint64 `json:"versions"`
	By       string            `json:"by"`
	At       time.Time         `json:"at"`
}

// RecordPublication stores the outcome of a successful publication. Its KV
// history is the publication history.
func (r *Registry) RecordPublication(ctx context.Context, p Publication) error {
	path := "publications/" + p.Target + "/" + p.App
	v, err := r.currentVersion(ctx, path)
	if err != nil {
		return err
	}
	return r.put(ctx, path, p, v)
}

// GetPublication returns the last publication of an app on a target.
func (r *Registry) GetPublication(ctx context.Context, targetName, app string) (Publication, error) {
	var p Publication
	_, err := r.get(ctx, "publications/"+targetName+"/"+app, &p)
	return p, err
}
