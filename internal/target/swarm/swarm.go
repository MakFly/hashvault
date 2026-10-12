// Package swarm publishes secrets to Docker Swarm.
//
// Each secret version becomes one immutable swarm secret named
// hv_<app>_<target>_v<N>, labelled with its hashvault coordinates. Publishing
// a new version creates the new object and swaps the reference in every
// consuming service; Swarm then rolls those services. The name comes from the
// version number, never from a hash of the value: anyone allowed to list
// swarm secrets must not get an offline guessing oracle on a short secret.
//
// hashvault only edits the secret references of a service spec. Every other
// field round-trips untouched.
package swarm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/MakFly/hashvault/internal/dockerapi"
	"github.com/MakFly/hashvault/internal/target"
)

// MaxValueSize is the swarm limit for a secret value (500 KiB).
const MaxValueSize = 500 * 1024

const maxObjectName = 64

// clockSkew tolerates a manager clock slightly behind ours.
const clockSkew = 2 * time.Second

// Labels set on every object hashvault creates.
const (
	LabelManaged  = "hv.managed"
	LabelTarget   = "hv.target"
	LabelApp      = "hv.app"
	LabelEnv      = "hv.env"
	LabelKey      = "hv.key"
	LabelVersion  = "hv.version"
	LabelResource = "hv.resource"
)

// Config describes one swarm target.
type Config struct {
	// Name is the registered target name, stored in the hv.target label.
	Name string
	// Stack prefixes service names: service "api" of stack "acme" is the
	// swarm service "acme_api". Empty means manifest names are absolute.
	Stack string
	// VerifyTimeout bounds Verify. Zero means 5 minutes.
	VerifyTimeout time.Duration
	// PollInterval is the Verify polling period. Zero means 2 seconds.
	PollInterval time.Duration
}

// Adapter is the swarm target.
type Adapter struct {
	docker *dockerapi.Client
	cfg    Config
}

var _ target.Target = (*Adapter)(nil)

// New returns a swarm adapter.
func New(docker *dockerapi.Client, cfg Config) (*Adapter, error) {
	if cfg.Name == "" {
		return nil, errors.New("swarm: target name required")
	}
	if cfg.VerifyTimeout == 0 {
		cfg.VerifyTimeout = 5 * time.Minute
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 2 * time.Second
	}
	return &Adapter{docker: docker, cfg: cfg}, nil
}

// Kind implements target.Target.
func (a *Adapter) Kind() target.Kind { return target.Swarm }

// ObjectName is the swarm secret name of a version.
func ObjectName(app, fileTarget string, version uint64) string {
	return "hv_" + app + "_" + fileTarget + "_v" + strconv.FormatUint(version, 10)
}

func (a *Adapter) serviceName(svc string) string {
	if a.cfg.Stack == "" {
		return svc
	}
	return a.cfg.Stack + "_" + svc
}

// Check refuses a node that is not a swarm manager.
func (a *Adapter) Check(ctx context.Context) (target.Posture, error) {
	st, err := a.docker.Swarm(ctx)
	if err != nil {
		return target.Posture{}, err
	}
	p := target.Posture{Kind: target.Swarm, Details: map[string]string{
		"node_state": st.LocalNodeState,
		"manager":    strconv.FormatBool(st.ControlAvailable),
	}}
	if st.LocalNodeState != "active" || !st.ControlAvailable {
		return p, fmt.Errorf("%w: this node is not an active swarm manager (state %q)", target.ErrPosture, st.LocalNodeState)
	}
	return p, nil
}

// ref is one secret mount of a service, in the Engine API shape.
type ref struct {
	SecretID   string  `json:"SecretID"`
	SecretName string  `json:"SecretName"`
	File       refFile `json:"File"`
}

type refFile struct {
	Name string `json:"Name"`
	UID  string `json:"UID"`
	GID  string `json:"GID"`
	Mode uint32 `json:"Mode"`
}

type wanted struct {
	item target.Item
	name string
}

func (a *Adapter) wanted(d target.Desired) ([]wanted, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	var out []wanted
	for _, it := range d.Items {
		if len(it.Value) > MaxValueSize {
			return nil, fmt.Errorf("%w: %s is larger than the swarm limit of %d bytes", target.ErrContract, it.Key, MaxValueSize)
		}
		name := ObjectName(d.App, it.Spec.Target, it.Version)
		if len(name) > maxObjectName {
			return nil, fmt.Errorf("%w: swarm secret name %q exceeds %d characters", target.ErrContract, name, maxObjectName)
		}
		out = append(out, wanted{item: it, name: name})
	}
	return out, nil
}

func (a *Adapter) labels(d target.Desired, it target.Item) map[string]string {
	return map[string]string{
		LabelManaged:  "true",
		LabelTarget:   a.cfg.Name,
		LabelApp:      d.App,
		LabelEnv:      d.Env,
		LabelKey:      it.Key,
		LabelVersion:  strconv.FormatUint(it.Version, 10),
		LabelResource: it.Resource,
	}
}

// existing returns this app's managed secrets by name, and refuses an object
// whose labels disagree with what its name claims.
func (a *Adapter) existing(ctx context.Context, d target.Desired, ws []wanted) (map[string]dockerapi.Secret, error) {
	list, err := a.docker.SecretList(ctx, LabelManaged+"=true", LabelApp+"="+d.App)
	if err != nil {
		return nil, err
	}
	byName := map[string]dockerapi.Secret{}
	for _, s := range list {
		byName[s.Spec.Name] = s
	}
	for _, w := range ws {
		s, ok := byName[w.name]
		if !ok {
			continue
		}
		if s.Spec.Labels[LabelResource] != w.item.Resource || s.Spec.Labels[LabelVersion] != strconv.FormatUint(w.item.Version, 10) {
			return nil, fmt.Errorf("%w: swarm secret %q exists with other coordinates", target.ErrContract, w.name)
		}
	}
	return byName, nil
}

// desiredRefs computes the new secret list of one service: the managed
// mounts it should have, plus every foreign mount whose file name hashvault
// does not manage. A foreign mount on a managed file name (an old *_v1
// secret) is replaced: that is the migration path.
func (a *Adapter) desiredRefs(app, svc string, current []ref, ws []wanted, ids map[string]string) []ref {
	managedFiles := map[string]bool{}
	var out []ref
	for _, w := range ws {
		if !slices.Contains(w.item.Spec.Services, svc) {
			continue
		}
		managedFiles[w.item.Spec.Target] = true
		out = append(out, ref{
			SecretID:   ids[w.name],
			SecretName: w.name,
			File: refFile{
				Name: w.item.Spec.Target,
				UID:  w.item.Spec.UID,
				GID:  w.item.Spec.GID,
				Mode: w.item.Spec.FileMode(),
			},
		})
	}
	ownPrefix := "hv_" + app + "_"
	for _, r := range current {
		if managedFiles[r.File.Name] || strings.HasPrefix(r.SecretName, ownPrefix) {
			continue
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(x, y ref) int { return strings.Compare(x.File.Name, y.File.Name) })
	return out
}

func names(refs []ref) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.SecretName+":"+r.File.Name)
	}
	slices.Sort(out)
	return out
}

func services(ws []wanted) []string {
	var out []string
	for _, w := range ws {
		for _, s := range w.item.Spec.Services {
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	slices.Sort(out)
	return out
}

// Plan implements target.Target.
func (a *Adapter) Plan(ctx context.Context, d target.Desired) (target.Plan, error) {
	ws, err := a.wanted(d)
	if err != nil {
		return target.Plan{}, err
	}
	have, err := a.existing(ctx, d, ws)
	if err != nil {
		return target.Plan{}, err
	}
	plan := target.Plan{App: d.App}
	ids := map[string]string{}
	for _, w := range ws {
		if s, ok := have[w.name]; ok {
			plan.Reuse = append(plan.Reuse, w.name)
			ids[w.name] = s.ID
		} else {
			plan.Create = append(plan.Create, w.name)
		}
	}
	for _, svc := range services(ws) {
		service, err := a.docker.ServiceInspect(ctx, a.serviceName(svc))
		if err != nil {
			return target.Plan{}, fmt.Errorf("swarm: service %q: %w", a.serviceName(svc), err)
		}
		current, err := secretsOf(service.Spec)
		if err != nil {
			return target.Plan{}, err
		}
		next := a.desiredRefs(d.App, svc, current, ws, ids)
		if !slices.Equal(names(current), names(next)) {
			plan.Changes = append(plan.Changes, target.Change{Consumer: a.serviceName(svc), Before: names(current), After: names(next)})
		}
	}
	return plan, nil
}

// Apply implements target.Target. If a service update fails, the services
// already updated are rolled back before the error is returned.
func (a *Adapter) Apply(ctx context.Context, d target.Desired) (target.Receipt, error) {
	ws, err := a.wanted(d)
	if err != nil {
		return target.Receipt{}, err
	}
	have, err := a.existing(ctx, d, ws)
	if err != nil {
		return target.Receipt{}, err
	}
	rcpt := target.Receipt{Kind: target.Swarm, App: d.App, Previous: map[string][]byte{}, At: time.Now().UTC()}
	ids := map[string]string{}
	for _, w := range ws {
		if s, ok := have[w.name]; ok {
			ids[w.name] = s.ID
			continue
		}
		id, err := a.docker.SecretCreate(ctx, w.name, a.labels(d, w.item), w.item.Value)
		if errors.Is(err, dockerapi.ErrConflict) {
			// A concurrent publisher created it: accept it if its labels match.
			again, lerr := a.existing(ctx, d, ws)
			if lerr != nil {
				return rcpt, lerr
			}
			s, ok := again[w.name]
			if !ok {
				return rcpt, err
			}
			id, err = s.ID, nil
		}
		if err != nil {
			return rcpt, fmt.Errorf("swarm: create %s: %w", w.name, err)
		}
		ids[w.name] = id
		rcpt.Created = append(rcpt.Created, w.name)
	}
	for _, svc := range services(ws) {
		name := a.serviceName(svc)
		changed, prev, err := a.updateService(ctx, name, func(current []ref) []ref {
			return a.desiredRefs(d.App, svc, current, ws, ids)
		})
		if err != nil {
			rbErr := a.Rollback(ctx, rcpt)
			return rcpt, errors.Join(fmt.Errorf("swarm: update %s: %w", name, err), rbErr)
		}
		if changed {
			rcpt.Consumers = append(rcpt.Consumers, name)
			rcpt.Previous[name] = prev
		}
	}
	return rcpt, nil
}

// updateService applies edit to a service's secret list, retrying when the
// service moved under us. It returns whether the list changed and the
// previous list as JSON.
func (a *Adapter) updateService(ctx context.Context, name string, edit func([]ref) []ref) (bool, []byte, error) {
	for range 3 {
		service, err := a.docker.ServiceInspect(ctx, name)
		if err != nil {
			return false, nil, err
		}
		current, err := secretsOf(service.Spec)
		if err != nil {
			return false, nil, err
		}
		next := edit(current)
		if slices.Equal(names(current), names(next)) {
			return false, nil, nil
		}
		prev, err := json.Marshal(current)
		if err != nil {
			return false, nil, err
		}
		if err := setSecrets(service.Spec, next); err != nil {
			return false, nil, err
		}
		err = a.docker.ServiceUpdate(ctx, service.ID, service.Version.Index, service.Spec)
		if errors.Is(err, dockerapi.ErrOutOfSequence) {
			continue
		}
		if err != nil {
			return false, nil, err
		}
		return true, prev, nil
	}
	return false, nil, fmt.Errorf("swarm: service %s kept changing during the update", name)
}

// Verify implements target.Target: every updated service must finish its
// rolling update. A paused update or a swarm rollback is a failure.
func (a *Adapter) Verify(ctx context.Context, r target.Receipt) error {
	deadline := time.Now().Add(a.cfg.VerifyTimeout)
	for _, name := range r.Consumers {
		for {
			service, err := a.docker.ServiceInspect(ctx, name)
			if err != nil {
				return err
			}
			state, msg := "", ""
			// A status left over from an earlier update does not count: the
			// update we made started at or after the receipt.
			if us := service.UpdateStatus; us != nil && !us.StartedAt.Before(r.At.Add(-clockSkew)) {
				state, msg = us.State, us.Message
			}
			switch state {
			case "completed":
			case "paused", "rollback_started", "rollback_paused", "rollback_completed":
				return fmt.Errorf("%w: service %s: update %s: %s%s", target.ErrVerify, name, state, msg, a.taskError(ctx, service.ID))
			default:
				if time.Now().After(deadline) {
					return fmt.Errorf("%w: service %s: still %q after %s", target.ErrVerify, name, state, a.cfg.VerifyTimeout)
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(a.cfg.PollInterval):
				}
				continue
			}
			break
		}
	}
	return nil
}

// taskError returns the most recent task failure of a service, to explain a
// failed update. Task errors are runtime messages, never secret values.
func (a *Adapter) taskError(ctx context.Context, serviceID string) string {
	tasks, err := a.docker.TaskList(ctx, serviceID)
	if err != nil {
		return ""
	}
	for _, t := range tasks {
		if t.Status.Err != "" {
			return " (task: " + t.Status.Err + ")"
		}
	}
	return ""
}

// Rollback implements target.Target: it restores each touched service's
// previous secret list, most recent first.
func (a *Adapter) Rollback(ctx context.Context, r target.Receipt) error {
	var errs []error
	for i := len(r.Consumers) - 1; i >= 0; i-- {
		name := r.Consumers[i]
		var prev []ref
		if err := json.Unmarshal(r.Previous[name], &prev); err != nil {
			errs = append(errs, fmt.Errorf("swarm: rollback %s: %w", name, err))
			continue
		}
		if _, _, err := a.updateService(ctx, name, func([]ref) []ref { return prev }); err != nil {
			errs = append(errs, fmt.Errorf("swarm: rollback %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// Inventory implements target.Target.
func (a *Adapter) Inventory(ctx context.Context) ([]target.Published, error) {
	list, err := a.docker.SecretList(ctx, LabelManaged+"=true", LabelTarget+"="+a.cfg.Name)
	if err != nil {
		return nil, err
	}
	inUse, err := a.inUse(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]target.Published, 0, len(list))
	for _, s := range list {
		v, _ := strconv.ParseUint(s.Spec.Labels[LabelVersion], 10, 64)
		out = append(out, target.Published{
			App:        s.Spec.Labels[LabelApp],
			Key:        s.Spec.Labels[LabelKey],
			Version:    v,
			ObjectName: s.Spec.Name,
			ObjectID:   s.ID,
			CreatedAt:  s.CreatedAt,
			InUse:      inUse[s.ID],
		})
	}
	slices.SortFunc(out, func(x, y target.Published) int { return strings.Compare(x.ObjectName, y.ObjectName) })
	return out, nil
}

func (a *Adapter) inUse(ctx context.Context) (map[string]bool, error) {
	svcs, err := a.docker.ServiceList(ctx)
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for _, s := range svcs {
		refs, err := secretsOf(s.Spec)
		if err != nil {
			return nil, err
		}
		for _, r := range refs {
			used[r.SecretID] = true
		}
	}
	return used, nil
}

// GC removes the managed secrets of this target that no service mounts and
// that are older than retention (the rollback window). It returns the names
// removed.
func (a *Adapter) GC(ctx context.Context, retention time.Duration, now time.Time) ([]string, error) {
	inv, err := a.Inventory(ctx)
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, p := range inv {
		if p.InUse || now.Sub(p.CreatedAt) < retention {
			continue
		}
		if err := a.docker.SecretRemove(ctx, p.ObjectID); err != nil {
			if errors.Is(err, dockerapi.ErrConflict) || errors.Is(err, dockerapi.ErrNotFound) {
				continue // mounted since the listing, or already gone
			}
			return removed, err
		}
		removed = append(removed, p.ObjectName)
	}
	return removed, nil
}

// secretsOf reads TaskTemplate.ContainerSpec.Secrets from a generic spec.
func secretsOf(spec map[string]any) ([]ref, error) {
	cs, err := containerSpec(spec)
	if err != nil {
		return nil, err
	}
	raw, ok := cs["Secrets"]
	if !ok || raw == nil {
		return nil, nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var out []ref
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("swarm: unexpected secret references: %w", err)
	}
	return out, nil
}

func setSecrets(spec map[string]any, refs []ref) error {
	cs, err := containerSpec(spec)
	if err != nil {
		return err
	}
	data, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	var generic []any
	if err := json.Unmarshal(data, &generic); err != nil {
		return err
	}
	cs["Secrets"] = generic
	return nil
}

func containerSpec(spec map[string]any) (map[string]any, error) {
	tt, ok := spec["TaskTemplate"].(map[string]any)
	if !ok {
		return nil, errors.New("swarm: service spec has no TaskTemplate")
	}
	cs, ok := tt["ContainerSpec"].(map[string]any)
	if !ok {
		return nil, errors.New("swarm: service is not a container service")
	}
	return cs, nil
}
