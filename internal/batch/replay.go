package batch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Replay is the agent's memory of what it accepted: batch ids until they
// expire, and the last version applied per app and key. It lives in one
// JSON file written atomically.
type Replay struct {
	mu   sync.Mutex
	path string
	st   replayState
}

type replayState struct {
	Seen     map[string]time.Time         `json:"seen"`     // batch id -> expiry
	Versions map[string]map[string]uint64 `json:"versions"` // app -> key -> version
}

// LoadReplay reads the state file, or starts empty if it does not exist.
func LoadReplay(path string) (*Replay, error) {
	r := &Replay{path: path, st: replayState{Seen: map[string]time.Time{}, Versions: map[string]map[string]uint64{}}}
	data, err := os.ReadFile(path) // #nosec G304 -- path from the agent configuration
	if os.IsNotExist(err) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &r.st); err != nil {
		return nil, fmt.Errorf("batch: replay state %s is corrupted: %w", path, err)
	}
	if r.st.Seen == nil {
		r.st.Seen = map[string]time.Time{}
	}
	if r.st.Versions == nil {
		r.st.Versions = map[string]map[string]uint64{}
	}
	return r, nil
}

// Check refuses a replayed batch, or one that would move a key back to an
// older version without the signed rollback flag.
func (r *Replay) Check(b Batch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.st.Seen[b.ID]; ok {
		return fmt.Errorf("%w: batch %s already applied", ErrInvalid, b.ID)
	}
	if b.Rollback {
		return nil
	}
	for _, it := range b.Items {
		if last := r.st.Versions[b.App][it.Key]; it.Version < last {
			return fmt.Errorf("%w: %s v%d is older than the applied v%d", ErrInvalid, it.Key, it.Version, last)
		}
	}
	return nil
}

// Record remembers an applied batch and persists the state.
func (r *Replay) Record(b Batch, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, exp := range r.st.Seen {
		if now.After(exp.Add(ClockSkew)) {
			delete(r.st.Seen, id)
		}
	}
	r.st.Seen[b.ID] = b.ExpiresAt
	if r.st.Versions[b.App] == nil {
		r.st.Versions[b.App] = map[string]uint64{}
	}
	for _, it := range b.Items {
		r.st.Versions[b.App][it.Key] = it.Version
	}
	return r.save()
}

// Applied returns the last version applied for app/key (0 if none).
func (r *Replay) Applied(app, key string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.st.Versions[app][key]
}

func (r *Replay) save() error {
	data, err := json.Marshal(r.st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- path from the agent configuration
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}
