package server

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/MakFly/hashvault/internal/registry"
	"github.com/MakFly/hashvault/internal/secrets"
	"github.com/MakFly/hashvault/internal/target"
)

func (s *Server) preparationAccess(r *http.Request, c caller, p target.Preparation) error {
	cond := map[string]string{"hv:TargetKind": string(p.Kind), "hv:TargetName": p.Target, "hv:PublishMode": "push", "hv:Env": p.Env}
	if err := s.authorize(r.Context(), c, "secret:Publish", "hv:"+p.Env+":target/"+p.Target, cond); err != nil {
		return err
	}
	keys := make([]string, 0, len(p.Items))
	for key := range p.Items {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		ref := secrets.Ref{Env: p.Env, App: p.App, Key: key}
		if err := ref.Validate(); err != nil {
			return err
		}
		if err := s.authorize(r.Context(), c, "secret:Publish", ref.Resource(), cond); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) prepare(w http.ResponseWriter, r *http.Request, c caller) {
	var req publishRequest
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	if req.DryRun {
		fail(w, badRequest("prepare installs resources; use publish --dry-run for an existing deployment"))
		return
	}
	t, err := s.cfg.Registry.GetTarget(r.Context(), req.Target)
	if err != nil {
		fail(w, err)
		return
	}
	m, err := target.ParseManifest(req.Manifest)
	if err != nil {
		fail(w, err)
		return
	}
	p := target.Preparation{Version: target.PreparationVersion, ID: target.NewPreparationID(), Target: t.Name, Kind: t.Kind, Env: t.Env, App: m.App, By: c.session.Principal, At: s.cfg.Now().UTC(), PreparedResources: target.PreparedResources{Items: map[string]target.PreparedItem{}}}
	for _, key := range m.Keys() {
		p.Items[key] = target.PreparedItem{Spec: m.Items[key]}
	}
	for key, version := range req.Versions {
		if _, ok := m.Items[key]; !ok || version == 0 {
			fail(w, badRequest("invalid version pin for %s", key))
			return
		}
	}
	if err := s.preparationAccess(r, c, p); err != nil {
		fail(w, err)
		return
	}
	d := target.Desired{App: m.App, Env: t.Env, Rollback: req.Rollback}
	defer func() {
		for _, it := range d.Items {
			clear(it.Value)
		}
	}()
	// Resolve the full version vector before decrypting. It stays fixed even
	// if writers rotate individual keys while resources are being prepared.
	for _, key := range m.Keys() {
		version := req.Versions[key]
		if version == 0 {
			version, err = s.cfg.Store.Latest(r.Context(), secrets.Ref{Env: t.Env, App: m.App, Key: key})
			if err != nil {
				fail(w, err)
				return
			}
		}
		it := p.Items[key]
		it.Version = version
		p.Items[key] = it
	}
	for _, key := range m.Keys() {
		ref := secrets.Ref{Env: t.Env, App: m.App, Key: key}
		value, version, err := s.cfg.Store.Get(r.Context(), ref, p.Items[key].Version)
		if err != nil {
			fail(w, err)
			return
		}
		d.Items = append(d.Items, target.Item{Key: key, Version: version, Resource: ref.Resource(), Value: value, Spec: m.Items[key]})
	}
	a, err := s.cfg.Targets(r.Context(), t)
	if err != nil {
		fail(w, err)
		return
	}
	if _, err := a.Check(r.Context()); err != nil {
		fail(w, err)
		return
	}
	preparer, ok := a.(target.Preparer)
	if !ok {
		fail(w, badRequest("target does not support deployment preparations"))
		return
	}
	p.PreparedResources, err = preparer.Prepare(r.Context(), d, p.ID)
	if err != nil {
		fail(w, err)
		return
	}
	if err := s.cfg.Registry.RecordPreparation(r.Context(), p); err != nil {
		fail(w, err)
		return
	}
	s.record(c, "secret:Publish", "hv:"+t.Env+":target/"+t.Name, "prepared", map[string]string{"app": p.App, "preparation": p.ID})
	reply(w, http.StatusCreated, p)
}

func (s *Server) getPreparation(w http.ResponseWriter, r *http.Request, c caller) {
	p, err := s.cfg.Registry.GetPreparation(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	if err := s.preparationAccess(r, c, p); err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusOK, p)
}

func (s *Server) listPreparations(w http.ResponseWriter, r *http.Request, c caller) {
	// Lists are scoped explicitly. A caller cannot enumerate snapshots across
	// applications by probing a global preparation index.
	t, err := s.cfg.Registry.GetTarget(r.Context(), r.URL.Query().Get("target"))
	if err != nil {
		fail(w, err)
		return
	}
	app := r.URL.Query().Get("app")
	if err := (secrets.Ref{Env: t.Env, App: app, Key: "KEY"}).Validate(); err != nil {
		fail(w, err)
		return
	}
	cond := map[string]string{"hv:TargetKind": string(t.Kind), "hv:TargetName": t.Name, "hv:PublishMode": "push", "hv:Env": t.Env}
	if err := s.authorize(r.Context(), c, "secret:Publish", "hv:"+t.Env+":target/"+t.Name, cond); err != nil {
		fail(w, err)
		return
	}
	if err := s.authorize(r.Context(), c, "secret:List", "hv:"+t.Env+":secret/"+app, cond); err != nil {
		fail(w, err)
		return
	}
	ids, err := s.cfg.Registry.ListPreparations(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	out := []target.Preparation{}
	for _, id := range ids {
		p, err := s.cfg.Registry.GetPreparation(r.Context(), id)
		if err != nil {
			fail(w, err)
			return
		}
		if p.Target == t.Name && p.App == app {
			if err := s.preparationAccess(r, c, p); err != nil {
				fail(w, err)
				return
			}
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b target.Preparation) int { return b.At.Compare(a.At) })
	reply(w, http.StatusOK, map[string]any{"preparations": out})
}

func (s *Server) confirmPreparation(w http.ResponseWriter, r *http.Request, c caller) {
	var req struct {
		Release  string `json:"release"`
		Previous string `json:"previous"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	if strings.TrimSpace(req.Release) != req.Release || req.Release == "" || len(req.Release) > 128 || strings.ContainsAny(req.Release, "\r\n\x00") || (req.Previous != "" && !target.ValidPreparationID(req.Previous)) {
		fail(w, badRequest("invalid release or previous preparation"))
		return
	}
	p, err := s.cfg.Registry.GetPreparation(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	if err := s.preparationAccess(r, c, p); err != nil {
		fail(w, err)
		return
	}
	pub := registry.Publication{Target: p.Target, App: p.App, PreparationID: p.ID, Release: req.Release, Versions: map[string]uint64{}, By: c.session.Principal, At: s.cfg.Now().UTC()}
	for key, it := range p.Items {
		pub.Versions[key] = it.Version
	}
	if err := s.cfg.Registry.ConfirmPublication(r.Context(), pub, req.Previous); err != nil {
		fail(w, err)
		return
	}
	s.record(c, "secret:Publish", "hv:"+p.Env+":target/"+p.Target, "confirmed", map[string]string{"app": p.App, "preparation": p.ID, "release": req.Release})
	reply(w, http.StatusOK, pub)
}

func (s *Server) getPublication(w http.ResponseWriter, r *http.Request, c caller) {
	t, err := s.cfg.Registry.GetTarget(r.Context(), r.PathValue("target"))
	if err != nil {
		fail(w, err)
		return
	}
	app := r.PathValue("app")
	if err := (secrets.Ref{Env: t.Env, App: app, Key: "KEY"}).Validate(); err != nil {
		fail(w, err)
		return
	}
	if err := s.authorize(r.Context(), c, "secret:Publish", "hv:"+t.Env+":target/"+t.Name, map[string]string{"hv:TargetKind": string(t.Kind), "hv:TargetName": t.Name, "hv:PublishMode": "push", "hv:Env": t.Env}); err != nil {
		fail(w, err)
		return
	}
	p, err := s.cfg.Registry.GetPublication(r.Context(), t.Name, app)
	if errors.Is(err, registry.ErrNotFound) {
		reply(w, http.StatusOK, map[string]any{"publication": nil})
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	for key := range p.Versions {
		if err := s.authorize(r.Context(), c, "secret:Publish", (secrets.Ref{Env: t.Env, App: app, Key: key}).Resource(), map[string]string{"hv:TargetKind": string(t.Kind), "hv:TargetName": t.Name, "hv:PublishMode": "push", "hv:Env": t.Env}); err != nil {
			fail(w, err)
			return
		}
	}
	reply(w, http.StatusOK, map[string]any{"publication": p})
}
