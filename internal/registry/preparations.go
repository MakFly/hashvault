package registry

import (
	"context"
	"errors"

	"github.com/MakFly/hashvault/internal/target"
)

// RecordPreparation uses create-only CAS: snapshots cannot be overwritten.
func (r *Registry) RecordPreparation(ctx context.Context, p target.Preparation) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if !namePattern.MatchString(p.Target) {
		return ErrInvalid
	}
	return r.put(ctx, "preparations/"+p.ID, p, 0)
}

func (r *Registry) GetPreparation(ctx context.Context, id string) (target.Preparation, error) {
	if !target.ValidPreparationID(id) {
		return target.Preparation{}, ErrNotFound
	}
	var p target.Preparation
	_, err := r.get(ctx, "preparations/"+id, &p)
	if err == nil {
		err = p.Validate()
	}
	return p, err
}

func (r *Registry) ListPreparations(ctx context.Context) ([]string, error) {
	return r.list(ctx, "preparations")
}

// ConfirmPublication checks the expected active snapshot and uses CAS to
// prevent two deployers from silently claiming the same predecessor. A retry
// of the same snapshot and release is idempotent.
func (r *Registry) ConfirmPublication(ctx context.Context, p Publication, previous string) error {
	if !target.ValidPreparationID(p.PreparationID) || !namePattern.MatchString(p.Target) || !namePattern.MatchString(p.App) || p.Release == "" {
		return ErrInvalid
	}
	path := "publications/" + p.Target + "/" + p.App
	var current Publication
	v, err := r.get(ctx, path, &current)
	if errors.Is(err, ErrNotFound) {
		v, err = 0, nil
	}
	if err != nil {
		return err
	}
	if current.PreparationID == p.PreparationID && current.Release == p.Release {
		return nil
	}
	if current.PreparationID != previous {
		return ErrConflict
	}
	return r.put(ctx, path, p, v)
}
