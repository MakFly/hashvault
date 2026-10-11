// Package secrets stores versioned secrets as hv1 envelopes in OpenBao KV v2.
//
// Layout: every secret version is its own KV entry,
//
//	<mount>/data/<env>/<app>/<KEY>/<N>
//
// so the version N bound into the envelope never changes. The KV versions of
// that entry only move when the record is rewrapped after a KEK rotation;
// older KV versions are destroyed right after, so a retired wrapped key does
// not linger. A destroyed secret version keeps its metadata, which keeps its
// number from ever being reused.
package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/MakFly/hashvault/internal/envelope"
	"github.com/MakFly/hashvault/internal/openbao"
)

var (
	// ErrNotFound reports a secret or a version that does not exist.
	ErrNotFound = errors.New("secrets: not found")
	// ErrDestroyed reports a version whose data was destroyed.
	ErrDestroyed = errors.New("secrets: version destroyed")
	// ErrInvalidRef reports coordinates that cannot name a secret.
	ErrInvalidRef = errors.New("secrets: invalid reference")
)

var (
	envPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	appPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	keyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
)

// maxPutAttempts bounds the retries when concurrent writers race for the next
// version number.
const maxPutAttempts = 8

// Ref names a secret.
type Ref struct {
	Env string
	App string
	Key string
}

// Validate checks the three coordinates.
func (r Ref) Validate() error {
	switch {
	case !envPattern.MatchString(r.Env):
		return fmt.Errorf("%w: env %q must match %s", ErrInvalidRef, r.Env, envPattern)
	case !appPattern.MatchString(r.App):
		return fmt.Errorf("%w: app %q must match %s", ErrInvalidRef, r.App, appPattern)
	case !keyPattern.MatchString(r.Key):
		return fmt.Errorf("%w: key %q must match %s", ErrInvalidRef, r.Key, keyPattern)
	}
	return nil
}

// Resource is the IAM resource of the secret.
func (r Ref) Resource() string {
	return "hv:" + r.Env + ":secret/" + r.App + "/" + r.Key
}

func (r Ref) base() string { return r.Env + "/" + r.App + "/" + r.Key }

func (r Ref) versionPath(n uint64) string { return r.base() + "/" + strconv.FormatUint(n, 10) }

func (r Ref) binding(n uint64) envelope.Binding {
	return envelope.Binding{Resource: r.Resource(), Env: r.Env, Version: n}
}

// Store reads and writes secrets.
type Store struct {
	kv      *openbao.Client
	mount   string
	wrapper interface {
		envelope.KeyWrapper
		envelope.Rewrapper
	}
}

// New returns a store on the KV v2 mount, sealing with wrapper.
func New(kv *openbao.Client, mount string, wrapper interface {
	envelope.KeyWrapper
	envelope.Rewrapper
}) *Store {
	return &Store{kv: kv, mount: mount, wrapper: wrapper}
}

// Versions lists the version numbers of a secret, destroyed ones included,
// in ascending order.
func (s *Store) Versions(ctx context.Context, ref Ref) ([]uint64, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	keys, err := s.kv.KVList(ctx, s.mount, ref.base())
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, k := range keys {
		n, err := strconv.ParseUint(k, 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != k {
			return nil, fmt.Errorf("secrets: unexpected entry %q under %s", k, ref.base())
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return out, nil
}

// Put stores value as the next version and returns its number.
func (s *Store) Put(ctx context.Context, ref Ref, value []byte) (uint64, error) {
	if err := ref.Validate(); err != nil {
		return 0, err
	}
	for range maxPutAttempts {
		versions, err := s.Versions(ctx, ref)
		if err != nil {
			return 0, err
		}
		next := uint64(1)
		if len(versions) > 0 {
			next = versions[len(versions)-1] + 1
		}
		rec, err := envelope.Seal(ctx, s.wrapper, ref.binding(next), value)
		if err != nil {
			return 0, err
		}
		data, err := envelope.MarshalRecord(rec)
		if err != nil {
			return 0, err
		}
		// cas=0: the version entry must not exist. A concurrent writer that
		// took the same number makes this fail, and we try the next one.
		_, err = s.kv.KVPut(ctx, s.mount, ref.versionPath(next), map[string]string{"record": base64.StdEncoding.EncodeToString(data)}, 0)
		if errors.Is(err, openbao.ErrCASMismatch) {
			continue
		}
		if err != nil {
			return 0, err
		}
		return next, nil
	}
	return 0, fmt.Errorf("secrets: %s: too many concurrent writers", ref.base())
}

// Latest returns the highest version number, destroyed or not.
func (s *Store) Latest(ctx context.Context, ref Ref) (uint64, error) {
	versions, err := s.Versions(ctx, ref)
	if err != nil {
		return 0, err
	}
	if len(versions) == 0 {
		return 0, ErrNotFound
	}
	return versions[len(versions)-1], nil
}

// Get returns a version of the secret (0: the latest). The caller clears the
// value.
func (s *Store) Get(ctx context.Context, ref Ref, version uint64) ([]byte, uint64, error) {
	if err := ref.Validate(); err != nil {
		return nil, 0, err
	}
	if version == 0 {
		v, err := s.Latest(ctx, ref)
		if err != nil {
			return nil, 0, err
		}
		version = v
	}
	rec, err := s.record(ctx, ref, version)
	if err != nil {
		return nil, 0, err
	}
	value, err := envelope.Open(ctx, s.wrapper, ref.binding(version), rec)
	if err != nil {
		return nil, 0, err
	}
	return value, version, nil
}

func (s *Store) record(ctx context.Context, ref Ref, version uint64) (envelope.Record, error) {
	entry, err := s.kv.KVGet(ctx, s.mount, ref.versionPath(version), 0)
	if errors.Is(err, openbao.ErrNotFound) {
		return envelope.Record{}, ErrNotFound
	}
	if err != nil {
		return envelope.Record{}, err
	}
	if entry.Destroyed || entry.Deleted {
		return envelope.Record{}, ErrDestroyed
	}
	raw, err := base64.StdEncoding.DecodeString(entry.Data["record"])
	if err != nil {
		return envelope.Record{}, fmt.Errorf("secrets: %s: stored record is not base64", ref.versionPath(version))
	}
	return envelope.ParseRecord(raw)
}

// Destroy permanently removes the data of a secret version, which holds the
// only copy of its wrapped data key. The version number stays reserved.
func (s *Store) Destroy(ctx context.Context, ref Ref, version uint64) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	md, err := s.kv.KVMetadata(ctx, s.mount, ref.versionPath(version))
	if errors.Is(err, openbao.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return s.kv.KVDestroy(ctx, s.mount, ref.versionPath(version), md.Live)
}

// Rewrap moves every live version of a secret to the latest KEK version, then
// destroys the KV versions that held the previous wrapped keys. It returns
// how many versions were rewrapped.
func (s *Store) Rewrap(ctx context.Context, ref Ref) (int, error) {
	versions, err := s.Versions(ctx, ref)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, v := range versions {
		path := ref.versionPath(v)
		md, err := s.kv.KVMetadata(ctx, s.mount, path)
		if err != nil {
			return done, err
		}
		if len(md.Live) == 0 {
			continue // destroyed version
		}
		rec, err := s.record(ctx, ref, v)
		if err != nil {
			return done, err
		}
		next, err := envelope.Rewrap(ctx, s.wrapper, rec)
		if err != nil {
			return done, err
		}
		if next.KEKVersion == rec.KEKVersion {
			continue // already on the latest KEK version
		}
		data, err := envelope.MarshalRecord(next)
		if err != nil {
			return done, err
		}
		if _, err := s.kv.KVPut(ctx, s.mount, path, map[string]string{"record": base64.StdEncoding.EncodeToString(data)}, md.CurrentVersion); err != nil {
			return done, err
		}
		if err := s.kv.KVDestroy(ctx, s.mount, path, md.Live); err != nil {
			return done, err
		}
		done++
	}
	return done, nil
}

// Keys lists the secret keys of an app in an environment.
func (s *Store) Keys(ctx context.Context, env, app string) ([]string, error) {
	if err := (Ref{Env: env, App: app, Key: "X"}).Validate(); err != nil {
		return nil, err
	}
	keys, err := s.kv.KVList(ctx, s.mount, env+"/"+app)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, k := range keys {
		name := k
		if len(name) > 0 && name[len(name)-1] == '/' {
			name = name[:len(name)-1]
		}
		if keyPattern.MatchString(name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out, nil
}
