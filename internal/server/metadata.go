package server

import "net/http"

// Version listing never decrypts a secret and needs only secret:List.
func (s *Server) secretVersions(w http.ResponseWriter, r *http.Request, c caller) {
	rf := ref(r)
	if err := rf.Validate(); err != nil {
		fail(w, err)
		return
	}
	if err := s.authorize(r.Context(), c, "secret:List", rf.Resource(), map[string]string{"hv:Env": rf.Env}); err != nil {
		fail(w, err)
		return
	}
	versions, err := s.cfg.Store.Versions(r.Context(), rf)
	if err != nil {
		fail(w, err)
		return
	}
	out := []map[string]any{}
	for _, version := range versions {
		live, err := s.cfg.Store.VersionLive(r.Context(), rf, version)
		if err != nil {
			fail(w, err)
			return
		}
		out = append(out, map[string]any{"version": version, "destroyed": !live})
	}
	reply(w, http.StatusOK, map[string]any{"versions": out})
}

func (s *Server) getTarget(w http.ResponseWriter, r *http.Request, c caller) {
	t, err := s.cfg.Registry.GetTarget(r.Context(), r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	if err := s.authorize(r.Context(), c, "target:List", "hv:"+t.Env+":target/"+t.Name, map[string]string{"hv:Env": t.Env, "hv:TargetKind": string(t.Kind), "hv:TargetName": t.Name}); err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusOK, t)
}

func (s *Server) listPrincipals(w http.ResponseWriter, r *http.Request, c caller) {
	if err := s.authorize(r.Context(), c, "principal:Read", "hv:sys:principals", nil); err != nil {
		fail(w, err)
		return
	}
	names, err := s.cfg.Registry.ListPrincipals(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{"principals": names})
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request, c caller) {
	if err := s.authorize(r.Context(), c, "policy:Get", "hv:sys:policies", nil); err != nil {
		fail(w, err)
		return
	}
	names, err := s.cfg.Registry.ListPolicies(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{"policies": names})
}
