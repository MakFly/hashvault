package host

import (
	"context"
	"fmt"

	"github.com/MakFly/hashvault/internal/batch"
	"github.com/MakFly/hashvault/internal/hostagent"
	"github.com/MakFly/hashvault/internal/target"
)

func (a *Adapter) Prepare(ctx context.Context, d target.Desired, id string) (target.PreparedResources, error) {
	if err := d.Validate(); err != nil {
		return target.PreparedResources{}, err
	}
	if !target.ValidPreparationID(id) {
		return target.PreparedResources{}, target.ErrContract
	}
	b := a.batch(d)
	b.Preparation, b.Consumers = id, batch.Consumers{}
	sealed, err := batch.Seal(b, a.cfg.Signer, a.recipient)
	if err != nil {
		return target.PreparedResources{}, err
	}
	r, err := a.cfg.Transport.Deliver(ctx, sealed)
	if err != nil {
		return target.PreparedResources{}, err
	}
	if r.BatchID != b.ID || r.Status != hostagent.Applied || r.Resources == nil {
		return target.PreparedResources{}, fmt.Errorf("host: preparation refused by agent %s: %s", a.cfg.Agent, r.Error)
	}
	return *r.Resources, nil
}
