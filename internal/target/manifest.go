package target

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// ManifestVersion is the only accepted manifest version.
const ManifestVersion = "hv-manifest-1"

const maxManifestSize = 256 << 10

var (
	keyPattern     = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	targetPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	servicePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
	idPattern      = regexp.MustCompile(`^[0-9]{1,10}$`)
)

// Exposure says how a workload receives a value.
type Exposure string

const (
	// File: a read-only file, /run/secrets/<target> (or the credential
	// directory for systemd).
	File Exposure = "file"
	// Env: an environment variable named after the key. On swarm and docker
	// the value is still mounted as a file; the image's entrypoint exports
	// it. On ssh it goes into the .env or the exec environment.
	Env Exposure = "env"
)

// ItemSpec is the contract of one key: where and how it is exposed.
type ItemSpec struct {
	Expose Exposure `json:"expose"`
	// Target is the file name under /run/secrets. Defaults to the key in
	// lower case: a target that differs from the key is a deliberate choice,
	// never an accident.
	Target   string   `json:"target,omitempty"`
	Services []string `json:"services"`
	UID      string   `json:"uid,omitempty"`
	GID      string   `json:"gid,omitempty"`
	// Mode is octal text, "0400" by default. Group or world write is refused.
	Mode string `json:"mode,omitempty"`
}

// FileMode returns the numeric mode.
func (s ItemSpec) FileMode() uint32 {
	m, _ := strconv.ParseUint(s.Mode, 8, 32)
	return uint32(m)
}

func (s *ItemSpec) defaults(key string) {
	if s.Target == "" {
		s.Target = strings.ToLower(key)
	}
	if s.UID == "" {
		s.UID = "0"
	}
	if s.GID == "" {
		s.GID = "0"
	}
	if s.Mode == "" {
		s.Mode = "0400"
	}
}

func (s ItemSpec) validate(key string) error {
	if !keyPattern.MatchString(key) {
		return fmt.Errorf("%w: key %q must match %s", ErrContract, key, keyPattern)
	}
	if s.Expose != File && s.Expose != Env {
		return fmt.Errorf("%w: %s: expose must be %q or %q", ErrContract, key, File, Env)
	}
	if !targetPattern.MatchString(s.Target) {
		return fmt.Errorf("%w: %s: target %q must match %s", ErrContract, key, s.Target, targetPattern)
	}
	if s.Expose == Env && s.Target != strings.ToLower(key) {
		return fmt.Errorf("%w: %s: an env item exports the key itself, its target must be %q", ErrContract, key, strings.ToLower(key))
	}
	if len(s.Services) == 0 {
		return fmt.Errorf("%w: %s: no service consumes it", ErrContract, key)
	}
	for _, svc := range s.Services {
		if !servicePattern.MatchString(svc) {
			return fmt.Errorf("%w: %s: service %q", ErrContract, key, svc)
		}
	}
	if !idPattern.MatchString(s.UID) || !idPattern.MatchString(s.GID) {
		return fmt.Errorf("%w: %s: uid and gid must be numeric", ErrContract, key)
	}
	m, err := strconv.ParseUint(s.Mode, 8, 32)
	if err != nil || len(s.Mode) != 4 || s.Mode[0] != '0' {
		return fmt.Errorf("%w: %s: mode %q must be four octal digits", ErrContract, key, s.Mode)
	}
	if m&0o022 != 0 || m&0o111 != 0 {
		return fmt.Errorf("%w: %s: mode %s grants write to others or execute", ErrContract, key, s.Mode)
	}
	return nil
}

// Manifest is the env contract an app declares in hashvault.json.
type Manifest struct {
	Version string              `json:"version"`
	App     string              `json:"app"`
	Items   map[string]ItemSpec `json:"items"`
}

// Keys returns the declared keys, sorted.
func (m Manifest) Keys() []string {
	keys := make([]string, 0, len(m.Items))
	for k := range m.Items {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// ParseManifest decodes, fills defaults and validates a manifest. Unknown
// fields are refused: a misspelled "taget" must not silently fall back to the
// default.
func ParseManifest(data []byte) (Manifest, error) {
	if len(data) > maxManifestSize {
		return Manifest{}, fmt.Errorf("%w: manifest larger than %d bytes", ErrContract, maxManifestSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrContract, err)
	}
	if dec.More() {
		return Manifest{}, fmt.Errorf("%w: trailing data", ErrContract)
	}
	if m.Version != ManifestVersion {
		return Manifest{}, fmt.Errorf("%w: version must be %q", ErrContract, ManifestVersion)
	}
	if !appPattern.MatchString(m.App) {
		return Manifest{}, fmt.Errorf("%w: app %q must match %s", ErrContract, m.App, appPattern)
	}
	if len(m.Items) == 0 {
		return Manifest{}, fmt.Errorf("%w: no item", ErrContract)
	}
	for key, spec := range m.Items {
		spec.defaults(key)
		m.Items[key] = spec
	}
	// Validate through Desired so the per-service uniqueness rule is the
	// same at parse time and at publish time.
	d := Desired{App: m.App}
	for _, key := range m.Keys() {
		d.Items = append(d.Items, Item{Key: key, Version: 1, Spec: m.Items[key]})
	}
	if err := d.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
