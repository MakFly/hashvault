package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/MakFly/hashvault/internal/registry"
	"github.com/MakFly/hashvault/internal/secrets"
	"github.com/MakFly/hashvault/internal/target"
	"github.com/MakFly/hashvault/internal/target/host"
)

type publishRequest struct {
	Target   string          `json:"target"`
	Manifest json.RawMessage `json:"manifest"`
	// Versions pins keys to versions; the others take their latest.
	Versions map[string]uint64 `json:"versions,omitempty"`
	// Rollback allows versions older than the published ones (host targets).
	Rollback bool `json:"rollback,omitempty"`
	// DryRun returns the plan without publishing.
	DryRun bool `json:"dry_run,omitempty"`
}

type publishResponse struct {
	Status  string            `json:"status"` // planned, published, rolled_back
	Plan    target.Plan       `json:"plan"`
	Applied map[string]uint64 `json:"versions,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// publish authorizes every key and the target, reads the values, then
// plans, applies and verifies through the target's adapter. A failed
// verification is rolled back and reported.
func (s *Server) publish(w http.ResponseWriter, r *http.Request, c caller) {
	ctx := r.Context()
	var req publishRequest
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	t, err := s.cfg.Registry.GetTarget(ctx, req.Target)
	if err != nil {
		fail(w, err)
		return
	}
	m, err := target.ParseManifest(req.Manifest)
	if err != nil {
		fail(w, err)
		return
	}
	cond := map[string]string{"hv:TargetKind": string(t.Kind), "hv:TargetName": t.Name, "hv:PublishMode": "push", "hv:Env": t.Env}
	targetResource := "hv:" + t.Env + ":target/" + t.Name
	if err := s.authorize(ctx, c, "secret:Publish", targetResource, cond); err != nil {
		fail(w, err)
		return
	}
	for key := range req.Versions {
		if _, ok := m.Items[key]; !ok {
			fail(w, badRequest("pinned key %s is not in the manifest", key))
			return
		}
	}
	d := target.Desired{App: m.App, Env: t.Env, Rollback: req.Rollback}
	defer func() {
		for _, it := range d.Items {
			clear(it.Value)
		}
	}()
	for _, key := range m.Keys() {
		rf := secrets.Ref{Env: t.Env, App: m.App, Key: key}
		if err := s.authorize(ctx, c, "secret:Publish", rf.Resource(), cond); err != nil {
			fail(w, err)
			return
		}
		value, version, err := s.cfg.Store.Get(ctx, rf, req.Versions[key])
		if err != nil {
			fail(w, err)
			return
		}
		d.Items = append(d.Items, target.Item{Key: key, Version: version, Resource: rf.Resource(), Value: value, Spec: m.Items[key]})
	}

	adapter, err := s.cfg.Targets(ctx, t)
	if err != nil {
		fail(w, err)
		return
	}
	if _, err := adapter.Check(ctx); err != nil {
		fail(w, err)
		return
	}
	plan, err := adapter.Plan(ctx, d)
	if err != nil {
		fail(w, err)
		return
	}
	resp := publishResponse{Status: "planned", Plan: plan, Applied: map[string]uint64{}}
	for _, it := range d.Items {
		resp.Applied[it.Key] = it.Version
	}
	if req.DryRun {
		reply(w, http.StatusOK, resp)
		return
	}

	detail := map[string]string{"target": t.Name, "app": m.App}
	for k, v := range resp.Applied {
		detail["v."+k] = strconv.FormatUint(v, 10)
	}
	rcpt, err := adapter.Apply(ctx, d)
	if err == nil {
		err = adapter.Verify(ctx, rcpt)
		if err != nil {
			if rbErr := adapter.Rollback(ctx, rcpt); rbErr != nil && !errors.Is(rbErr, host.ErrUnsupported) {
				err = errors.Join(err, rbErr)
			}
		}
	}
	if err != nil {
		s.record(c, "secret:Publish", targetResource, "rolled_back", detail)
		resp.Status, resp.Error = "rolled_back", err.Error()
		reply(w, http.StatusBadGateway, resp)
		return
	}
	if err := s.cfg.Registry.RecordPublication(ctx, registry.Publication{
		Target: t.Name, App: m.App, Versions: resp.Applied, By: c.session.Principal, At: s.cfg.Now().UTC(),
	}); err != nil {
		s.record(c, "secret:Publish", targetResource, "published_unrecorded", detail)
		resp.Status, resp.Error = "published", "published, but the publication record failed: "+err.Error()
		reply(w, http.StatusOK, resp)
		return
	}
	s.record(c, "secret:Publish", targetResource, "published", detail)
	resp.Status = "published"
	reply(w, http.StatusOK, resp)
}
