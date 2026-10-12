// Package hostagent is what hashvault-agent does on a host it publishes to:
// a plain Docker host (kind docker) or a server deployed to over SSH (kind
// ssh). It runs as root, receives one signed and encrypted batch at a time,
// and never talks to the vault on its own.
//
// For each item it:
//
//  1. seals the value into the host credential store
//     (<CredstoreDir>/<app>.<KEY>, systemd-creds, the format
//     LoadCredentialEncrypted= reads), keeping the previous one as .prev;
//  2. materialises every item of the app on tmpfs, one directory per
//     consuming service: <RuntimeDir>/<app>/<service>/<target>, plus a .env
//     with the env-exposed items;
//  3. restarts the consumers (compose services, or reload commands);
//  4. on any failure, puts the previous values back and reports it.
//
// The credential store survives reboots, the tmpfs copy does not: at boot,
// `hashvault-agent materialize --all` rebuilds it from the store alone,
// without the vault.
package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/MakFly/hashvault/internal/batch"
	"github.com/MakFly/hashvault/internal/target"
)

// Config locates the agent's files and tools.
type Config struct {
	// CredstoreDir holds the sealed values. /etc/credstore.encrypted.
	CredstoreDir string
	// RuntimeDir holds the materialised values. /run/hashvault, on tmpfs.
	RuntimeDir string
	// StateDir holds the replay state and the app metadata. /var/lib/hashvault-agent.
	StateDir string
	// AllowNonTmpfs lets tests materialise outside tmpfs. Never in production.
	AllowNonTmpfs bool
	Sealer        Sealer
	Consumers     Consumers
	// Chown sets ownership; nil means os.Lchown. Tests running unprivileged
	// replace it.
	Chown func(path string, uid, gid int) error
	Now   func() time.Time
}

// Agent applies batches.
type Agent struct {
	cfg    Config
	replay *batch.Replay
}

// New prepares the agent directories and loads the replay state.
func New(cfg Config) (*Agent, error) {
	if cfg.Sealer == nil {
		return nil, errors.New("hostagent: a sealer is required")
	}
	for _, d := range []string{cfg.CredstoreDir, cfg.StateDir, filepath.Join(cfg.StateDir, "apps")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	if cfg.Chown == nil {
		cfg.Chown = os.Lchown
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	r, err := batch.LoadReplay(filepath.Join(cfg.StateDir, "replay.json"))
	if err != nil {
		return nil, err
	}
	return &Agent{cfg: cfg, replay: r}, nil
}

// Status of a receipt.
const (
	Applied    = "applied"
	RolledBack = "rolled_back"
	Refused    = "refused"
)

// Receipt is what the agent answers. It names versions, never values.
type Receipt struct {
	BatchID string            `json:"batch_id"`
	App     string            `json:"app"`
	Status  string            `json:"status"`
	Items   map[string]uint64 `json:"items"`
	Error   string            `json:"error,omitempty"`
	At      time.Time         `json:"at"`
}

// meta is the non-secret description of an app on this host.
type meta struct {
	App   string               `json:"app"`
	Env   string               `json:"env"`
	Kind  target.Kind          `json:"kind"`
	Items map[string]metaItem  `json:"items"`
	Prev  map[string]*metaItem `json:"prev,omitempty"` // key -> previous (nil: none)
}

type metaItem struct {
	Version  uint64          `json:"version"`
	Resource string          `json:"resource"`
	Spec     target.ItemSpec `json:"spec"`
}

func (a *Agent) metaPath(app string) string {
	return filepath.Join(a.cfg.StateDir, "apps", app+".json")
}

func (a *Agent) loadMeta(app string) (*meta, error) {
	data, err := os.ReadFile(a.metaPath(app))
	if os.IsNotExist(err) {
		return &meta{App: app, Items: map[string]metaItem{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var m meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("hostagent: metadata of %s is corrupted: %w", app, err)
	}
	if m.Items == nil {
		m.Items = map[string]metaItem{}
	}
	return &m, nil
}

func (a *Agent) saveMeta(m *meta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(a.metaPath(m.App), data, 0o600, -1, -1, nil)
}

func (a *Agent) credPath(app, key string) string {
	return filepath.Join(a.cfg.CredstoreDir, app+"."+key)
}

// Receive opens a sealed batch and applies it. A batch that fails to open is
// refused without touching anything.
func (a *Agent) Receive(ctx context.Context, data []byte, open func([]byte) (batch.Batch, error)) Receipt {
	b, err := open(data)
	if err != nil {
		return Receipt{Status: Refused, Error: err.Error(), At: a.cfg.Now().UTC()}
	}
	defer b.Clear()
	return a.Apply(ctx, b)
}

// Apply writes, materialises and restarts. On failure it restores the
// previous state and reports RolledBack.
func (a *Agent) Apply(ctx context.Context, b batch.Batch) Receipt {
	rcpt := Receipt{BatchID: b.ID, App: b.App, Items: map[string]uint64{}, At: a.cfg.Now().UTC()}
	for _, it := range b.Items {
		rcpt.Items[it.Key] = it.Version
	}
	if err := a.replay.Check(b); err != nil {
		rcpt.Status, rcpt.Error = Refused, err.Error()
		return rcpt
	}
	if err := checkEnvOwners(b); err != nil {
		rcpt.Status, rcpt.Error = Refused, err.Error()
		return rcpt
	}
	m, err := a.loadMeta(b.App)
	if err != nil {
		rcpt.Status, rcpt.Error = Refused, err.Error()
		return rcpt
	}
	before := cloneMeta(m)

	err = a.write(ctx, b, m)
	if err == nil {
		err = a.Materialize(ctx, b.App)
	}
	if err == nil {
		err = a.cfg.Consumers.Run(ctx, b)
	}
	if err != nil {
		rbErr := a.restore(ctx, b, before)
		rcpt.Status, rcpt.Error = RolledBack, errors.Join(err, rbErr).Error()
		return rcpt
	}
	if err := a.replay.Record(b, a.cfg.Now()); err != nil {
		rcpt.Status, rcpt.Error = Applied, "applied, but the replay state could not be saved: "+err.Error()
		return rcpt
	}
	rcpt.Status = Applied
	return rcpt
}

// write seals the new values. The previous sealed file of each key becomes
// <file>.prev, the only copy Rollback needs.
func (a *Agent) write(ctx context.Context, b batch.Batch, m *meta) error {
	m.Env, m.Kind = b.Env, b.Kind
	m.Prev = map[string]*metaItem{}
	for _, it := range b.Items {
		name := b.App + "." + it.Key
		sealed, err := a.cfg.Sealer.Seal(ctx, name, it.Value)
		if err != nil {
			return err
		}
		path := a.credPath(b.App, it.Key)
		if old, ok := m.Items[it.Key]; ok {
			if err := os.Rename(path, path+".prev"); err != nil && !os.IsNotExist(err) {
				return err
			}
			m.Prev[it.Key] = &old
		} else {
			m.Prev[it.Key] = nil
		}
		if err := writeAtomic(path, sealed, 0o600, -1, -1, nil); err != nil {
			return err
		}
		m.Items[it.Key] = metaItem{Version: it.Version, Resource: it.Resource, Spec: it.Spec}
	}
	return a.saveMeta(m)
}

// restore puts back the sealed files and metadata of before, then
// materialises and restarts again.
func (a *Agent) restore(ctx context.Context, b batch.Batch, before *meta) error {
	var errs []error
	for _, it := range b.Items {
		path := a.credPath(b.App, it.Key)
		if _, had := before.Items[it.Key]; had {
			if err := os.Rename(path+".prev", path); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
		} else if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	before.Prev = nil
	if err := a.saveMeta(before); err != nil {
		errs = append(errs, err)
	}
	if err := a.Materialize(ctx, b.App); err != nil {
		errs = append(errs, err)
	}
	if err := a.cfg.Consumers.Run(ctx, b); err != nil {
		errs = append(errs, fmt.Errorf("restart after restore: %w", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("restore incomplete: %w", errors.Join(errs...))
	}
	return nil
}

func cloneMeta(m *meta) *meta {
	c := &meta{App: m.App, Env: m.Env, Kind: m.Kind, Items: map[string]metaItem{}}
	for k, v := range m.Items {
		c.Items[k] = v
	}
	return c
}

// checkEnvOwners refuses env items of one service with different owners:
// they share one .env file.
func checkEnvOwners(b batch.Batch) error {
	owner := map[string]string{}
	for _, it := range b.Items {
		if it.Spec.Expose != target.Env {
			continue
		}
		for _, svc := range it.Spec.Services {
			o := it.Spec.UID + ":" + it.Spec.GID
			if prev, ok := owner[svc]; ok && prev != o {
				return fmt.Errorf("%w: env items of service %q have different owners (%s, %s)", target.ErrContract, svc, prev, o)
			}
			owner[svc] = o
		}
	}
	return nil
}

// Apps lists the apps this agent manages.
func (a *Agent) Apps() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(a.cfg.StateDir, "apps"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".json"); ok && !e.IsDir() {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out, nil
}
