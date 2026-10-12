// Package host is the vault side of the docker and ssh targets: it turns a
// desired state into a batch for one hashvault-agent, signs it, encrypts it
// to that agent, delivers it through a Transport and reads the receipt.
//
// The agent does the host work (see internal/hostagent) and restores the
// previous values itself when a restart fails, so Verify has nothing left to
// wait for once Apply returns.
package host

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"filippo.io/age"

	"github.com/MakFly/hashvault/internal/batch"
	"github.com/MakFly/hashvault/internal/hostagent"
	"github.com/MakFly/hashvault/internal/target"
)

// ErrUnsupported reports an operation a host target cannot do.
var ErrUnsupported = errors.New("host: not supported by host targets")

// Config describes one docker or ssh target.
type Config struct {
	Name string
	Kind target.Kind
	// Agent is the agent name the batch is addressed to.
	Agent string
	// Recipient is the agent's age hybrid recipient (age1pq1...).
	Recipient string
	// Signer is the vault's Ed25519 key; the agent pins its public half.
	Signer    ed25519.PrivateKey
	Transport Transport
	// ComposeProject overrides the compose project name (docker); by
	// default it is the app name.
	ComposeProject string
	// Reload lists, per app, the commands the agent runs after writing the
	// values (ssh), for example {"acme-api": {{"/usr/bin/systemctl", "reload", "php8.4-fpm"}}}.
	Reload map[string][][]string
	// Validity of a batch; at most batch.MaxValidity. Default 5 minutes.
	Validity time.Duration
	Now      func() time.Time
}

// Adapter is a docker or ssh target.
type Adapter struct {
	cfg       Config
	recipient age.Recipient
}

var _ target.Target = (*Adapter)(nil)

// New validates the configuration.
func New(cfg Config) (*Adapter, error) {
	if cfg.Kind != target.Docker && cfg.Kind != target.SSH {
		return nil, fmt.Errorf("host: kind %q is not a host target", cfg.Kind)
	}
	if cfg.Name == "" || cfg.Agent == "" || cfg.Transport == nil {
		return nil, errors.New("host: name, agent and transport are required")
	}
	if len(cfg.Signer) != ed25519.PrivateKeySize {
		return nil, errors.New("host: an Ed25519 signing key is required")
	}
	r, err := age.ParseHybridRecipient(cfg.Recipient)
	if err != nil {
		return nil, fmt.Errorf("host: agent recipient: %w", err)
	}
	if cfg.Validity == 0 {
		cfg.Validity = 5 * time.Minute
	}
	if cfg.Validity > batch.MaxValidity {
		return nil, fmt.Errorf("host: validity above %s", batch.MaxValidity)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Kind == target.Docker && len(cfg.Reload) > 0 {
		return nil, errors.New("host: reload commands belong to ssh targets")
	}
	for app, cmds := range cfg.Reload {
		for _, argv := range cmds {
			if len(argv) == 0 || len(argv[0]) == 0 || argv[0][0] != '/' {
				return nil, fmt.Errorf("host: reload command of %s needs an absolute program path", app)
			}
		}
	}
	return &Adapter{cfg: cfg, recipient: r}, nil
}

// Kind implements target.Target.
func (a *Adapter) Kind() target.Kind { return a.cfg.Kind }

// Check implements target.Target. A host agent accepts nothing but batches,
// so the check covers the configuration; reachability shows at the first
// publication.
func (a *Adapter) Check(context.Context) (target.Posture, error) {
	return target.Posture{Kind: a.cfg.Kind, Details: map[string]string{
		"agent":     a.cfg.Agent,
		"transport": a.cfg.Transport.Describe(),
		"recipient": "hybrid ML-KEM-768 + X25519",
	}}, nil
}

// ObjectName names a published version in plans and receipts.
func ObjectName(app, key string, version uint64) string {
	return app + "." + key + "@v" + strconv.FormatUint(version, 10)
}

func (a *Adapter) consumers(d target.Desired) batch.Consumers {
	var c batch.Consumers
	switch a.cfg.Kind {
	case target.Docker:
		for _, it := range d.Items {
			for _, svc := range it.Spec.Services {
				if !slices.Contains(c.Docker, svc) {
					c.Docker = append(c.Docker, svc)
				}
			}
		}
		slices.Sort(c.Docker)
		c.ComposeProject = a.cfg.ComposeProject
	case target.SSH:
		c.Reload = a.cfg.Reload[d.App]
	}
	return c
}

// Plan implements target.Target. The agent's state is not readable from
// here, so the plan lists what will be pushed and what will be restarted.
func (a *Adapter) Plan(_ context.Context, d target.Desired) (target.Plan, error) {
	if err := d.Validate(); err != nil {
		return target.Plan{}, err
	}
	p := target.Plan{App: d.App}
	for _, it := range d.Items {
		p.Create = append(p.Create, ObjectName(d.App, it.Key, it.Version))
	}
	c := a.consumers(d)
	for _, svc := range c.Docker {
		p.Changes = append(p.Changes, target.Change{Consumer: "compose:" + svc})
	}
	for _, argv := range c.Reload {
		p.Changes = append(p.Changes, target.Change{Consumer: "reload:" + argv[0]})
	}
	return p, nil
}

func (a *Adapter) batch(d target.Desired) batch.Batch {
	now := a.cfg.Now().UTC()
	b := batch.Batch{
		Version: batch.Version, ID: batch.NewID(), Agent: a.cfg.Agent, Target: a.cfg.Name, Kind: a.cfg.Kind,
		App: d.App, Env: d.Env, IssuedAt: now, ExpiresAt: now.Add(a.cfg.Validity), Rollback: d.Rollback,
		Consumers: a.consumers(d),
	}
	for _, it := range d.Items {
		b.Items = append(b.Items, batch.Item{Key: it.Key, Version: it.Version, Resource: it.Resource, Value: it.Value, Spec: it.Spec})
	}
	return b
}

// Apply implements target.Target. A rolled back or refused receipt is an
// error that carries the agent's reason.
func (a *Adapter) Apply(ctx context.Context, d target.Desired) (target.Receipt, error) {
	if err := d.Validate(); err != nil {
		return target.Receipt{}, err
	}
	b := a.batch(d)
	sealed, err := batch.Seal(b, a.cfg.Signer, a.recipient)
	if err != nil {
		return target.Receipt{}, err
	}
	r, err := a.cfg.Transport.Deliver(ctx, sealed)
	if err != nil {
		return target.Receipt{}, err
	}
	rcpt := target.Receipt{Kind: a.cfg.Kind, App: d.App, At: b.IssuedAt}
	for _, it := range d.Items {
		rcpt.Created = append(rcpt.Created, ObjectName(d.App, it.Key, it.Version))
	}
	for _, svc := range b.Consumers.Docker {
		rcpt.Consumers = append(rcpt.Consumers, "compose:"+svc)
	}
	if r.BatchID != b.ID && r.Status != hostagent.Refused {
		return rcpt, fmt.Errorf("host: receipt for batch %q, sent %q", r.BatchID, b.ID)
	}
	switch r.Status {
	case hostagent.Applied:
		return rcpt, nil
	case hostagent.RolledBack:
		return rcpt, fmt.Errorf("%w: agent %s restored the previous values: %s", target.ErrVerify, a.cfg.Agent, r.Error)
	default:
		return rcpt, fmt.Errorf("host: agent %s refused the batch: %s", a.cfg.Agent, r.Error)
	}
}

// Verify implements target.Target: the agent answered only after its
// consumers were up, so there is nothing left to wait for.
func (a *Adapter) Verify(context.Context, target.Receipt) error { return nil }

// Rollback implements target.Target. A failed publication is already undone
// by the agent; going back after a successful one is a new publication of
// the previous versions with Desired.Rollback set, which needs their values.
func (a *Adapter) Rollback(context.Context, target.Receipt) error {
	return fmt.Errorf("%w: republish the previous versions with Rollback set", ErrUnsupported)
}

// Inventory implements target.Target. The agent exposes no listing; the
// vault's own publication records are the inventory of host targets.
func (a *Adapter) Inventory(context.Context) ([]target.Published, error) {
	return nil, fmt.Errorf("%w: inventory comes from the vault's publication records", ErrUnsupported)
}
