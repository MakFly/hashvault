package hostagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/MakFly/hashvault/internal/batch"
	"github.com/MakFly/hashvault/internal/target"
)

// generation isolates all encrypted files and tmpfs copies. Legacy publish
// continues to use its existing paths; a prepared generation never replaces
// one of those files. Retained generations also survive a vault outage.
func (a *Agent) generation(id string) (*Agent, error) {
	if !target.ValidPreparationID(id) {
		return nil, target.ErrContract
	}
	cfg := a.cfg
	cfg.CredstoreDir = filepath.Join(cfg.CredstoreDir, ".generations", id)
	cfg.RuntimeDir = filepath.Join(cfg.RuntimeDir, ".generations", id)
	cfg.StateDir = filepath.Join(cfg.StateDir, ".generations", id)
	return New(cfg)
}

func (a *Agent) prepare(ctx context.Context, b batch.Batch) Receipt {
	r := Receipt{BatchID: b.ID, App: b.App, At: a.cfg.Now().UTC(), Items: map[string]uint64{}}
	refuse := func(err error) Receipt { r.Status, r.Error = Refused, err.Error(); return r }
	if !target.ValidPreparationID(b.Preparation) || len(b.Consumers.Docker) > 0 || len(b.Consumers.Reload) > 0 {
		return refuse(target.ErrContract)
	}
	d := target.Desired{App: b.App, Env: b.Env}
	for _, it := range b.Items {
		d.Items = append(d.Items, target.Item{Key: it.Key, Version: it.Version, Spec: it.Spec})
	}
	if err := d.Validate(); err != nil {
		return refuse(err)
	}
	if err := checkEnvOwners(b); err != nil {
		return refuse(err)
	}
	// Exclusive directory creation protects immutable generations across
	// concurrent receive processes, including replays of a signed batch.
	parent := filepath.Join(a.cfg.StateDir, ".generations")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return refuse(err)
	}
	if err := os.Mkdir(filepath.Join(parent, b.Preparation), 0o700); err != nil {
		return refuse(fmt.Errorf("hostagent: generation cannot be claimed: %w", err))
	}
	g, err := a.generation(b.Preparation)
	if err != nil {
		return refuse(err)
	}
	completed := false
	defer func() {
		if !completed {
			_ = os.RemoveAll(g.cfg.RuntimeDir)
			_ = os.RemoveAll(g.cfg.CredstoreDir)
			_ = os.RemoveAll(g.cfg.StateDir)
		}
	}()
	m := &meta{App: b.App, Env: b.Env, Kind: b.Kind, Items: map[string]metaItem{}}
	for _, it := range b.Items {
		name := b.App + "." + it.Key
		sealed, err := g.cfg.Sealer.Seal(ctx, name, it.Value)
		if err != nil {
			return refuse(err)
		}
		if err := writeAtomic(g.credPath(b.App, it.Key), sealed, 0o600, -1, -1, nil); err != nil {
			return refuse(err)
		}
		m.Items[it.Key] = metaItem{Version: it.Version, Resource: it.Resource, Spec: it.Spec}
		r.Items[it.Key] = it.Version
	}
	if err := g.saveMeta(m); err != nil {
		return refuse(err)
	}
	if err := g.Materialize(ctx, b.App); err != nil {
		return refuse(err)
	}
	resources := target.PreparedResources{Items: map[string]target.PreparedItem{}, Services: map[string]target.ServiceFiles{}}
	for _, it := range b.Items {
		resources.Items[it.Key] = target.PreparedItem{Version: it.Version, Spec: it.Spec}
		for _, svc := range it.Spec.Services {
			files := resources.Services[svc]
			files.Directory = filepath.Join(g.cfg.RuntimeDir, b.App, svc)
			if it.Spec.Expose == target.Env {
				files.Dotenv = filepath.Join(files.Directory, ".env")
			}
			if files.Credentials == nil {
				files.Credentials = map[string]string{}
			}
			files.Credentials[it.Key] = g.credPath(b.App, it.Key)
			resources.Services[svc] = files
		}
	}
	r.Status, r.Resources = Applied, &resources
	completed = true
	return r
}

// MaterializeGenerations rebuilds retained snapshots at boot without touching
// consumers. The service runs before workloads, just like legacy materialize.
func (a *Agent) MaterializeGenerations(ctx context.Context) error {
	entries, err := os.ReadDir(filepath.Join(a.cfg.StateDir, ".generations"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if !e.IsDir() || !target.ValidPreparationID(e.Name()) {
			continue
		}
		g, err := a.generation(e.Name())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		apps, err := g.Apps()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		slices.Sort(apps)
		for _, app := range apps {
			if err := g.Materialize(ctx, app); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
