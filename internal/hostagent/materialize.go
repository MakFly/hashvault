package hostagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/MakFly/hashvault/internal/target"
)

// tmpfsMagic is TMPFS_MAGIC from linux/magic.h.
const tmpfsMagic = 0x01021994

// ErrNotTmpfs reports a runtime directory that would put values on disk.
var ErrNotTmpfs = errors.New("hostagent: runtime directory is not on tmpfs")

func (a *Agent) checkTmpfs() error {
	if a.cfg.AllowNonTmpfs {
		return nil
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(a.cfg.RuntimeDir, &st); err != nil {
		return err
	}
	if uint64(st.Type) != tmpfsMagic { // #nosec G115 -- filesystem magic, compared bit for bit
		return fmt.Errorf("%w: %s", ErrNotTmpfs, a.cfg.RuntimeDir)
	}
	return nil
}

// Materialize rebuilds <RuntimeDir>/<app> from the credential store: one
// directory per service with one file per item and a .env of the env items.
// Files of items that are gone are removed. It needs no vault: it is what
// runs at boot.
func (a *Agent) Materialize(ctx context.Context, app string) error {
	// 0711: app users must traverse to reach their own 0400 files; nothing is
	// listable by them.
	if err := os.MkdirAll(a.cfg.RuntimeDir, 0o711); err != nil { // #nosec G301
		return err
	}
	if err := a.checkTmpfs(); err != nil {
		return err
	}
	m, err := a.loadMeta(app)
	if err != nil {
		return err
	}
	appDir := filepath.Join(a.cfg.RuntimeDir, app)
	if err := os.MkdirAll(appDir, 0o711); err != nil { // #nosec G301 -- see RuntimeDir
		return err
	}
	// The directories are root-owned and traversable; each file is readable
	// by its owner only.
	type file struct {
		value      []byte
		uid, gid   int
		mode       os.FileMode
		envKey     string
		expose     target.Exposure
		targetName string
	}
	perService := map[string][]file{}
	defer func() {
		for _, files := range perService {
			for _, f := range files {
				clear(f.value)
			}
		}
	}()
	keys := make([]string, 0, len(m.Items))
	for k := range m.Items {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, key := range keys {
		it := m.Items[key]
		sealed, err := os.ReadFile(a.credPath(app, key))
		if err != nil {
			return fmt.Errorf("hostagent: %s.%s: %w", app, key, err)
		}
		value, err := a.cfg.Sealer.Open(ctx, app+"."+key, sealed)
		if err != nil {
			return fmt.Errorf("hostagent: open %s.%s: %w", app, key, err)
		}
		uid, _ := strconv.Atoi(it.Spec.UID)
		gid, _ := strconv.Atoi(it.Spec.GID)
		for i, svc := range it.Spec.Services {
			v := value
			if i > 0 {
				v = append([]byte(nil), value...)
			}
			perService[svc] = append(perService[svc], file{
				value: v, uid: uid, gid: gid, mode: os.FileMode(it.Spec.FileMode()),
				envKey: key, expose: it.Spec.Expose, targetName: it.Spec.Target,
			})
		}
		if len(it.Spec.Services) == 0 {
			clear(value)
		}
	}

	services := make([]string, 0, len(perService))
	for svc := range perService {
		services = append(services, svc)
	}
	slices.Sort(services)
	for _, svc := range services {
		dir := filepath.Join(appDir, svc)
		if err := os.MkdirAll(dir, 0o711); err != nil { // #nosec G301 -- see RuntimeDir
			return err
		}
		want := map[string]bool{}
		var env []envLine
		envUID, envGID := -1, -1
		for _, f := range perService[svc] {
			if err := writeAtomic(filepath.Join(dir, f.targetName), f.value, f.mode, f.uid, f.gid, a.cfg.Chown); err != nil {
				return err
			}
			want[f.targetName] = true
			if f.expose == target.Env {
				env = append(env, envLine{key: f.envKey, value: f.value})
				envUID, envGID = f.uid, f.gid
			}
		}
		if len(env) > 0 {
			data, err := encodeDotenv(env)
			if err != nil {
				return fmt.Errorf("hostagent: %s/%s: %w", app, svc, err)
			}
			err = writeAtomic(filepath.Join(dir, ".env"), data, 0o400, envUID, envGID, a.cfg.Chown)
			clear(data)
			if err != nil {
				return err
			}
			want[".env"] = true
		}
		if err := prune(dir, want); err != nil {
			return err
		}
	}
	// Service directories nobody consumes any more.
	entries, err := os.ReadDir(appDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() && !slices.Contains(services, e.Name()) {
			if err := os.RemoveAll(filepath.Join(appDir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// MaterializeAll rebuilds every app; used at boot.
func (a *Agent) MaterializeAll(ctx context.Context) error {
	apps, err := a.Apps()
	if err != nil {
		return err
	}
	var errs []error
	for _, app := range apps {
		if err := a.Materialize(ctx, app); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func prune(dir string, want map[string]bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !want[e.Name()] && !strings.HasPrefix(e.Name(), ".hv-tmp-") {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeAtomic writes data to a temporary file in the same directory, sets
// mode and owner, syncs, then renames it over path: a reader sees the old
// or the new content, never a partial one. uid or gid -1 keeps the owner.
func writeAtomic(path string, data []byte, mode os.FileMode, uid, gid int, chown func(string, int, int) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".hv-tmp-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if uid >= 0 && chown != nil {
		if err := chown(name, uid, gid); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

type envLine struct {
	key   string
	value []byte
}

// ErrDotenv reports a value no dotenv dialect can carry literally.
var ErrDotenv = errors.New("value cannot be written literally in a .env; expose it as a file")

// encodeDotenv writes KEY='value' lines. Single quotes are literal in the
// common parsers (Symfony, phpdotenv, Node dotenv, Ruby dotenv): no escape,
// no variable expansion, so a "$" in a password stays a "$". A value holding
// a single quote, a newline or a NUL cannot be written that way and is
// refused rather than mangled.
func encodeDotenv(lines []envLine) ([]byte, error) {
	slices.SortFunc(lines, func(x, y envLine) int { return strings.Compare(x.key, y.key) })
	var out []byte
	for _, l := range lines {
		for _, c := range l.value {
			if c == '\'' || c == '\n' || c == '\r' || c == 0 {
				clear(out)
				return nil, fmt.Errorf("%s: %w", l.key, ErrDotenv)
			}
		}
		out = append(out, l.key...)
		out = append(out, '=', '\'')
		out = append(out, l.value...)
		out = append(out, '\'', '\n')
	}
	return out, nil
}

// Env returns KEY=value pairs of the env items of one service, for
// `hashvault-agent exec`. The caller clears them.
func (a *Agent) Env(ctx context.Context, app, service string) ([][]byte, error) {
	m, err := a.loadMeta(app)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for key, it := range m.Items {
		if it.Spec.Expose != target.Env || !slices.Contains(it.Spec.Services, service) {
			continue
		}
		sealed, err := os.ReadFile(a.credPath(app, key))
		if err != nil {
			return nil, err
		}
		value, err := a.cfg.Sealer.Open(ctx, app+"."+key, sealed)
		if err != nil {
			return nil, err
		}
		pair := append([]byte(key+"="), value...)
		clear(value)
		out = append(out, pair)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("hostagent: %s/%s has no env item", app, service)
	}
	return out, nil
}
