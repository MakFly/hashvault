// Package target defines how hashvault publishes secrets to where workloads
// run. Each kind of target (docker, ssh, swarm, k3s, k8s) has an adapter
// implementing Target; this package holds what they share: the kinds, the
// app manifest (the env contract) and the shapes of a plan and a receipt.
package target

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Kind is a target kind. The values match the IAM key hv:TargetKind.
type Kind string

const (
	Docker Kind = "docker"
	SSH    Kind = "ssh"
	Swarm  Kind = "swarm"
	K3s    Kind = "k3s"
	K8s    Kind = "k8s"
)

// Kinds lists every kind, in the order the README presents them.
var Kinds = []Kind{Docker, SSH, Swarm, K3s, K8s}

var (
	// ErrContract reports a manifest or a desired state that breaks the env
	// contract (unknown key, invalid target name, duplicate mount...).
	ErrContract = errors.New("target: env contract violation")
	// ErrPosture reports a target whose security posture is refused (for
	// example a cluster without encryption at rest).
	ErrPosture = errors.New("target: posture refused")
	// ErrVerify reports a publication that did not converge.
	ErrVerify = errors.New("target: publication did not converge")
)

// Item is one secret version to publish, with its contract.
type Item struct {
	Key      string
	Version  uint64
	Resource string
	// Value is cleared by the caller once Apply returns.
	Value []byte
	Spec  ItemSpec
}

// Desired is everything one app should have on one target.
type Desired struct {
	App   string
	Env   string
	Items []Item
	// Rollback publishes versions older than the ones in place. Host agents
	// refuse a downgrade without it; swarm needs no flag.
	Rollback bool
}

// Validate checks the items against the manifest rules.
func (d Desired) Validate() error {
	if !appPattern.MatchString(d.App) {
		return fmt.Errorf("%w: app %q", ErrContract, d.App)
	}
	seen := map[string]string{}
	for _, it := range d.Items {
		if err := it.Spec.validate(it.Key); err != nil {
			return err
		}
		if it.Version == 0 {
			return fmt.Errorf("%w: %s has no version", ErrContract, it.Key)
		}
		for _, svc := range it.Spec.Services {
			slot := svc + "/" + it.Spec.Target
			if other, ok := seen[slot]; ok {
				return fmt.Errorf("%w: %s and %s both mount %q in service %q", ErrContract, other, it.Key, it.Spec.Target, svc)
			}
			seen[slot] = it.Key
		}
	}
	return nil
}

// Published is one secret version as it exists on a target.
type Published struct {
	App        string
	Key        string
	Version    uint64
	ObjectName string
	ObjectID   string
	CreatedAt  time.Time
	InUse      bool
}

// Posture is what Check found out about a target.
type Posture struct {
	Kind    Kind
	Details map[string]string
}

// Change is one consumer (service, unit, deployment) whose secret mounts
// change.
type Change struct {
	Consumer string
	Before   []string // object names mounted before
	After    []string // object names mounted after
}

// Plan is what Apply will do. It carries no secret value.
type Plan struct {
	App     string
	Create  []string // object names to create
	Reuse   []string // object names already present
	Changes []Change
}

// Empty reports a plan with nothing to do.
func (p Plan) Empty() bool { return len(p.Create) == 0 && len(p.Changes) == 0 }

// Receipt records what Apply did, so Verify and Rollback can act on it.
type Receipt struct {
	Kind    Kind
	App     string
	Created []string
	// Previous holds, per consumer, the opaque state Rollback restores.
	Previous map[string][]byte
	// Consumers lists the consumers Apply touched, in order.
	Consumers []string
	At        time.Time
}

// Target is implemented by every adapter.
type Target interface {
	Kind() Kind
	// Check inspects the target and refuses an unsafe posture.
	Check(ctx context.Context) (Posture, error)
	// Plan computes the changes without touching anything.
	Plan(ctx context.Context, d Desired) (Plan, error)
	// Apply publishes the desired state. Values are only held in memory.
	Apply(ctx context.Context, d Desired) (Receipt, error)
	// Verify waits until the consumers run the new state, or fails.
	Verify(ctx context.Context, r Receipt) error
	// Rollback restores the consumers to their state before Apply.
	Rollback(ctx context.Context, r Receipt) error
	// Inventory lists what hashvault published there. Never a value.
	Inventory(ctx context.Context) ([]Published, error)
}

var appPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
