package swarm

import (
	"context"
	"errors"
	"fmt"

	"github.com/MakFly/hashvault/internal/dockerapi"
	"github.com/MakFly/hashvault/internal/target"
)

// Prepare creates immutable secret objects even when no service exists yet.
// Stack deploy owns service specs when this integration mode is used.
func (a *Adapter) Prepare(ctx context.Context, d target.Desired, id string) (target.PreparedResources, error) {
	if !target.ValidPreparationID(id) {
		return target.PreparedResources{}, target.ErrContract
	}
	ws, err := a.wanted(d)
	if err != nil {
		return target.PreparedResources{}, err
	}
	have, err := a.existing(ctx, d, ws)
	if err != nil {
		return target.PreparedResources{}, err
	}
	resources := target.PreparedResources{Items: map[string]target.PreparedItem{}}
	for _, w := range ws {
		s := have[w.name]
		if s.ID == "" {
			labels := a.labels(d, w.item)
			labels[LabelPrepared] = "true"
			id, err := a.docker.SecretCreate(ctx, w.name, labels, w.item.Value)
			if errors.Is(err, dockerapi.ErrConflict) {
				again, lookupErr := a.existing(ctx, d, ws)
				if lookupErr != nil {
					return resources, lookupErr
				}
				if s, ok := again[w.name]; ok {
					id, err = s.ID, nil
				}
			}
			if err != nil {
				return resources, fmt.Errorf("swarm: prepare %s: %w", w.name, err)
			}
			s.ID = id
		}
		// Retained stack files may still reference this version even when no
		// current service mounts it. GC must preserve prepared rollback inputs.
		if err := a.retainPrepared(ctx, s.ID); err != nil {
			return resources, err
		}
		resources.Items[w.item.Key] = target.PreparedItem{Version: w.item.Version, Spec: w.item.Spec, ObjectName: w.name, ObjectID: s.ID}
	}
	return resources, nil
}

func (a *Adapter) retainPrepared(ctx context.Context, id string) error {
	for range 3 {
		s, err := a.docker.SecretInspect(ctx, id)
		if err != nil {
			return err
		}
		if s.Spec.Labels[LabelPrepared] == "true" {
			return nil
		}
		if s.Spec.Labels == nil {
			s.Spec.Labels = map[string]string{}
		}
		s.Spec.Labels[LabelPrepared] = "true"
		err = a.docker.SecretUpdateLabels(ctx, s, s.Spec.Labels)
		if errors.Is(err, dockerapi.ErrOutOfSequence) {
			continue
		}
		return err
	}
	return fmt.Errorf("swarm: prepared secret kept changing")
}
