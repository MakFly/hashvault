// Package server is the HTTP API of hashvaultd, served on a unix socket.
//
// Every request but status and login is authenticated by a session token
// and authorized by the IAM engine against the principal's policies, with a
// context built from the session (MFA age, principal type and tags), the
// kernel-reported peer of the socket (source channel) and the request
// itself. Every authorization decision is written to the audit log before
// the operation runs; if the audit log cannot be written, nothing runs.
package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/MakFly/hashvault/internal/audit"
	"github.com/MakFly/hashvault/internal/authn"
	"github.com/MakFly/hashvault/internal/envelope"
	"github.com/MakFly/hashvault/internal/iam"
	"github.com/MakFly/hashvault/internal/openbao"
	"github.com/MakFly/hashvault/internal/registry"
	"github.com/MakFly/hashvault/internal/secrets"
	"github.com/MakFly/hashvault/internal/target"
)

// Version is set at build time.
var Version = "dev"

const maxBody = 2 << 20

// Config wires the server.
type Config struct {
	VaultID  string
	Bao      *openbao.Client
	Store    *secrets.Store
	Registry *registry.Registry
	Sessions *authn.Sessions
	Audit    *audit.Log
	// AuditPath and AuditKey let audit:Read verify the log.
	AuditPath string
	AuditKey  ed25519.PublicKey
	// TunnelUIDs are the peer uids of operator SSH sessions: a request from
	// one of them has hv:SourceChannel=tunnel; any other peer is "socket".
	TunnelUIDs []int
	// Targets builds the adapter of a registered target.
	Targets TargetFactory
	// Seal seals the vault; called after sys:Seal is authorized.
	Seal func(ctx context.Context) error
	Now  func() time.Time
}

// TargetFactory turns a registered target into an adapter.
type TargetFactory func(ctx context.Context, t registry.Target) (target.Target, error)

// Server is the API.
type Server struct {
	cfg Config
	mux *http.ServeMux
}

// New returns the API handler. Serve it with ConnContext set on the
// http.Server, so the source channel is known.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.routes()
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /v1/sys/status", s.status)
	s.mux.HandleFunc("POST /v1/auth/challenge", s.challenge)
	s.mux.HandleFunc("POST /v1/auth/login", s.login)
	s.mux.HandleFunc("POST /v1/auth/logout", s.authed(s.logout))
	s.mux.HandleFunc("GET /v1/auth/session", s.authed(func(w http.ResponseWriter, r *http.Request, c caller) {
		reply(w, http.StatusOK, map[string]any{"principal": c.session.Principal, "expires_at": c.session.ExpiresAt, "mfa": !c.session.TouchedAt.IsZero()})
	}))
	s.mux.HandleFunc("PUT /v1/secrets/{env}/{app}/{key}", s.authed(s.putSecret))
	s.mux.HandleFunc("GET /v1/secrets/{env}/{app}/{key}", s.authed(s.getSecret))
	s.mux.HandleFunc("GET /v1/secrets/{env}/{app}/{key}/versions", s.authed(s.secretVersions))
	s.mux.HandleFunc("GET /v1/secrets/{env}/{app}", s.authed(s.listSecrets))
	s.mux.HandleFunc("DELETE /v1/secrets/{env}/{app}/{key}/versions/{version}", s.authed(s.destroySecret))
	s.mux.HandleFunc("POST /v1/secrets/{env}/{app}/{key}/rewrap", s.authed(s.rewrapSecret))
	s.mux.HandleFunc("PUT /v1/policies/{name}", s.authed(s.putPolicy))
	s.mux.HandleFunc("GET /v1/policies/{name}", s.authed(s.getPolicy))
	s.mux.HandleFunc("POST /v1/principals", s.authed(s.createPrincipal))
	s.mux.HandleFunc("GET /v1/principals", s.authed(s.listPrincipals))
	s.mux.HandleFunc("GET /v1/policies", s.authed(s.listPolicies))
	s.mux.HandleFunc("GET /v1/principals/{type}/{name}", s.authed(s.getPrincipal))
	s.mux.HandleFunc("POST /v1/principals/{type}/{name}/attach", s.authed(s.attachPolicy))
	s.mux.HandleFunc("POST /v1/principals/{type}/{name}/disable", s.authed(s.disablePrincipal))
	s.mux.HandleFunc("POST /v1/iam/simulate", s.authed(s.simulate))
	s.mux.HandleFunc("PUT /v1/targets/{name}", s.authed(s.putTarget))
	s.mux.HandleFunc("GET /v1/targets", s.authed(s.listTargets))
	s.mux.HandleFunc("GET /v1/targets/{name}", s.authed(s.getTarget))
	s.mux.HandleFunc("POST /v1/publish", s.authed(s.publish))
	s.mux.HandleFunc("POST /v1/preparations", s.authed(s.prepare))
	s.mux.HandleFunc("GET /v1/preparations", s.authed(s.listPreparations))
	s.mux.HandleFunc("GET /v1/preparations/{id}", s.authed(s.getPreparation))
	s.mux.HandleFunc("POST /v1/preparations/{id}/confirm", s.authed(s.confirmPreparation))
	s.mux.HandleFunc("GET /v1/publications/{target}/{app}", s.authed(s.getPublication))
	s.mux.HandleFunc("GET /v1/audit/verify", s.authed(s.verifyAudit))
	s.mux.HandleFunc("POST /v1/sys/seal", s.authed(s.seal))
}

func (s *Server) seal(w http.ResponseWriter, r *http.Request, c caller) {
	if err := s.authorize(r.Context(), c, "sys:Seal", "hv:sys:seal", nil); err != nil {
		fail(w, err)
		return
	}
	if s.cfg.Seal == nil {
		fail(w, badRequest("sealing is not available"))
		return
	}
	s.record(c, "sys:Seal", "hv:sys:seal", "sealing", nil)
	if err := s.cfg.Seal(context.WithoutCancel(r.Context())); err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]bool{"sealed": true})
}

// ---- Responses ----------------------------------------------------------------

type apiError struct {
	status int
	msg    string
}

func (e apiError) Error() string { return e.msg }

var (
	errUnauthenticated = apiError{http.StatusUnauthorized, "unauthenticated"}
	errForbidden       = apiError{http.StatusForbidden, "forbidden"}
)

func badRequest(format string, args ...any) error {
	return apiError{http.StatusBadRequest, fmt.Sprintf(format, args...)}
}

func reply(w http.ResponseWriter, status int, body any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// fail maps an error to a status. Internal errors are not echoed: the
// client gets a generic message, the operator the audit log.
func fail(w http.ResponseWriter, err error) {
	var api apiError
	switch {
	case errors.As(err, &api):
		reply(w, api.status, map[string]string{"error": api.msg})
	case errors.Is(err, secrets.ErrNotFound), errors.Is(err, registry.ErrNotFound):
		reply(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, secrets.ErrDestroyed):
		reply(w, http.StatusGone, map[string]string{"error": "version destroyed"})
	case errors.Is(err, secrets.ErrInvalidRef), errors.Is(err, registry.ErrInvalid), errors.Is(err, target.ErrContract), errors.Is(err, iam.ErrInvalidPolicy):
		reply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, registry.ErrConflict):
		reply(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, target.ErrVerify), errors.Is(err, target.ErrPosture):
		reply(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
	case errors.Is(err, envelope.ErrAuthentication):
		reply(w, http.StatusInternalServerError, map[string]string{"error": "stored record failed authentication"})
	default:
		reply(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
	}
}

func decode(r *http.Request, out any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return badRequest("invalid JSON body: %v", err)
	}
	if dec.More() {
		return badRequest("trailing data")
	}
	return nil
}

// ---- Authentication and authorization ------------------------------------------

type sessionKey struct{}

type caller struct {
	token   string
	session authn.Session
}

func (s *Server) authed(h func(http.ResponseWriter, *http.Request, caller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			fail(w, errUnauthenticated)
			return
		}
		sess, err := s.cfg.Sessions.Lookup(token)
		if err != nil {
			fail(w, errUnauthenticated)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)), caller{token: token, session: sess})
	}
}

func (s *Server) channel(ctx context.Context) string {
	p := peerOf(ctx)
	if p.known && slices.Contains(s.cfg.TunnelUIDs, p.uid) {
		return "tunnel"
	}
	return "socket"
}

// authorize evaluates action on resource for the caller, audits the
// decision and returns errForbidden unless it is Allow. extra adds request
// condition keys (target kind, env...).
func (s *Server) authorize(ctx context.Context, c caller, action, resource string, extra map[string]string) error {
	now := s.cfg.Now()
	reqCtx := c.session.Context(now)
	reqCtx["hv:SourceChannel"] = []string{s.channel(ctx)}
	// No approval workflow yet: a policy that requires one denies.
	reqCtx["hv:Approved"] = []string{"false"}
	reqCtx["hv:ApprovalCount"] = []string{"0"}
	for k, v := range extra {
		reqCtx[k] = []string{v}
	}
	decision, reason := iam.ImplicitDeny, "principal unavailable"
	p, err := s.cfg.Registry.GetPrincipal(ctx, c.session.Principal)
	if err == nil && p.Disabled {
		reason = "principal disabled"
	}
	if err == nil && !p.Disabled {
		for k, v := range p.Tags {
			reqCtx["hv:PrincipalTag/"+k] = []string{v}
		}
		set, serr := s.cfg.Registry.PolicySet(ctx, p)
		if serr != nil {
			reason = "policy set unavailable"
		} else {
			res := iam.Evaluate(set, iam.Request{Principal: p.Name, Action: action, Resource: resource, Context: reqCtx})
			decision, reason = res.Decision, res.Reason
		}
	}
	if _, aerr := s.cfg.Audit.Append(audit.Entry{
		Principal: c.session.Principal, Action: action, Resource: resource,
		Decision: string(decision), Outcome: "authorize", Detail: map[string]string{"reason": reason, "channel": s.channel(ctx)},
	}); aerr != nil {
		return fmt.Errorf("audit unavailable: %w", aerr)
	}
	if decision != iam.Allowed {
		return errForbidden
	}
	return nil
}

// record writes the outcome of an operation that was authorized.
func (s *Server) record(c caller, action, resource, outcome string, detail map[string]string) {
	_, _ = s.cfg.Audit.Append(audit.Entry{Principal: c.session.Principal, Action: action, Resource: resource, Decision: string(iam.Allowed), Outcome: outcome, Detail: detail})
}

// ---- Status and login -------------------------------------------------------------

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	st, err := s.cfg.Bao.SealStatus(r.Context())
	sealed := err != nil || st.Sealed
	reply(w, http.StatusOK, map[string]any{"vault": s.cfg.VaultID, "version": Version, "sealed": sealed})
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Principal string `json:"principal"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	// The same answer whether the principal exists or not.
	id, msg, err := s.cfg.Sessions.Challenge(req.Principal)
	if err != nil {
		reply(w, http.StatusTooManyRequests, map[string]string{"error": "too many pending challenges"})
		return
	}
	reply(w, http.StatusOK, map[string]string{"id": id, "message": string(msg)})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID        string `json:"id"`
		Principal string `json:"principal"`
		Signature string `json:"signature"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	outcome := "denied"
	defer func() {
		_, _ = s.cfg.Audit.Append(audit.Entry{Principal: req.Principal, Action: "auth:Login", Resource: "hv:sys:auth", Decision: outcome, Outcome: "login", Detail: map[string]string{"channel": s.channel(r.Context())}})
	}()
	p, err := s.cfg.Registry.GetPrincipal(r.Context(), req.Principal)
	if err != nil || p.Disabled {
		fail(w, errUnauthenticated)
		return
	}
	ap, err := p.Authn()
	if err != nil {
		fail(w, errUnauthenticated)
		return
	}
	token, sess, err := s.cfg.Sessions.Login(req.ID, ap, []byte(req.Signature))
	if err != nil {
		fail(w, errUnauthenticated)
		return
	}
	outcome = string(iam.Allowed)
	reply(w, http.StatusOK, map[string]any{"token": token, "expires_at": sess.ExpiresAt, "mfa": !sess.TouchedAt.IsZero()})
}

func (s *Server) logout(w http.ResponseWriter, _ *http.Request, c caller) {
	s.cfg.Sessions.Revoke(c.token)
	reply(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- Secrets ------------------------------------------------------------------------

func ref(r *http.Request) secrets.Ref {
	return secrets.Ref{Env: r.PathValue("env"), App: r.PathValue("app"), Key: r.PathValue("key")}
}

func (s *Server) putSecret(w http.ResponseWriter, r *http.Request, c caller) {
	rf := ref(r)
	if err := rf.Validate(); err != nil {
		fail(w, err)
		return
	}
	var req struct {
		Value string `json:"value"` // base64
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	value, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		fail(w, badRequest("value must be base64"))
		return
	}
	defer clear(value)
	if err := s.authorize(r.Context(), c, "secret:Write", rf.Resource(), map[string]string{"hv:Env": rf.Env}); err != nil {
		fail(w, err)
		return
	}
	v, err := s.cfg.Store.Put(r.Context(), rf, value)
	if err != nil {
		s.record(c, "secret:Write", rf.Resource(), "error", nil)
		fail(w, err)
		return
	}
	s.record(c, "secret:Write", rf.Resource(), "ok", map[string]string{"version": strconv.FormatUint(v, 10)})
	reply(w, http.StatusOK, map[string]uint64{"version": v})
}

func (s *Server) getSecret(w http.ResponseWriter, r *http.Request, c caller) {
	rf := ref(r)
	if err := rf.Validate(); err != nil {
		fail(w, err)
		return
	}
	var version uint64
	if q := r.URL.Query().Get("version"); q != "" {
		v, err := strconv.ParseUint(q, 10, 64)
		if err != nil {
			fail(w, badRequest("invalid version"))
			return
		}
		version = v
	}
	if err := s.authorize(r.Context(), c, "secret:Read", rf.Resource(), map[string]string{"hv:Env": rf.Env}); err != nil {
		fail(w, err)
		return
	}
	value, v, err := s.cfg.Store.Get(r.Context(), rf, version)
	if err != nil {
		fail(w, err)
		return
	}
	defer clear(value)
	s.record(c, "secret:Read", rf.Resource(), "ok", map[string]string{"version": strconv.FormatUint(v, 10)})
	reply(w, http.StatusOK, map[string]any{"version": v, "value": base64.StdEncoding.EncodeToString(value)})
}

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request, c caller) {
	env, app := r.PathValue("env"), r.PathValue("app")
	resource := "hv:" + env + ":secret/" + app
	if err := (secrets.Ref{Env: env, App: app, Key: "X"}).Validate(); err != nil {
		fail(w, err)
		return
	}
	if err := s.authorize(r.Context(), c, "secret:List", resource, map[string]string{"hv:Env": env}); err != nil {
		fail(w, err)
		return
	}
	keys, err := s.cfg.Store.Keys(r.Context(), env, app)
	if err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *Server) destroySecret(w http.ResponseWriter, r *http.Request, c caller) {
	rf := ref(r)
	v, err := strconv.ParseUint(r.PathValue("version"), 10, 64)
	if err != nil || v == 0 {
		fail(w, badRequest("invalid version"))
		return
	}
	if err := rf.Validate(); err != nil {
		fail(w, err)
		return
	}
	if err := s.authorize(r.Context(), c, "secret:Delete", rf.Resource(), map[string]string{"hv:Env": rf.Env}); err != nil {
		fail(w, err)
		return
	}
	if err := s.cfg.Store.Destroy(r.Context(), rf, v); err != nil {
		fail(w, err)
		return
	}
	s.record(c, "secret:Delete", rf.Resource(), "ok", map[string]string{"version": strconv.FormatUint(v, 10)})
	reply(w, http.StatusOK, map[string]bool{"destroyed": true})
}

func (s *Server) rewrapSecret(w http.ResponseWriter, r *http.Request, c caller) {
	rf := ref(r)
	if err := rf.Validate(); err != nil {
		fail(w, err)
		return
	}
	if err := s.authorize(r.Context(), c, "secret:Rotate", rf.Resource(), map[string]string{"hv:Env": rf.Env}); err != nil {
		fail(w, err)
		return
	}
	n, err := s.cfg.Store.Rewrap(r.Context(), rf)
	if err != nil {
		fail(w, err)
		return
	}
	s.record(c, "secret:Rotate", rf.Resource(), "ok", map[string]string{"rewrapped": strconv.Itoa(n)})
	reply(w, http.StatusOK, map[string]int{"rewrapped": n})
}

// ---- Policies, principals, simulator ------------------------------------------------

func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request, c caller) {
	name := r.PathValue("name")
	doc, err := io.ReadAll(r.Body)
	if err != nil {
		fail(w, badRequest("body too large"))
		return
	}
	if err := s.authorize(r.Context(), c, "policy:Put", "hv:policy/"+name, nil); err != nil {
		fail(w, err)
		return
	}
	if err := s.cfg.Registry.PutPolicy(r.Context(), name, doc); err != nil {
		fail(w, err)
		return
	}
	s.record(c, "policy:Put", "hv:policy/"+name, "ok", nil)
	reply(w, http.StatusOK, map[string]bool{"stored": true})
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request, c caller) {
	name := r.PathValue("name")
	if err := s.authorize(r.Context(), c, "policy:Get", "hv:policy/"+name, nil); err != nil {
		fail(w, err)
		return
	}
	_, doc, err := s.cfg.Registry.GetPolicy(r.Context(), name)
	if err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]json.RawMessage{"document": doc})
}

func principalName(r *http.Request) string { return r.PathValue("type") + "/" + r.PathValue("name") }

func (s *Server) createPrincipal(w http.ResponseWriter, r *http.Request, c caller) {
	var p registry.Principal
	if err := decode(r, &p); err != nil {
		fail(w, err)
		return
	}
	resource := "hv:principal/" + p.Name
	if err := s.authorize(r.Context(), c, "principal:Create", resource, nil); err != nil {
		fail(w, err)
		return
	}
	// Policies are attached separately, under policy:Attach.
	p.Policies, p.Boundary, p.Disabled, p.CreatedAt = nil, nil, false, s.cfg.Now().UTC()
	if err := s.cfg.Registry.PutPrincipal(r.Context(), p); err != nil {
		fail(w, err)
		return
	}
	s.record(c, "principal:Create", resource, "ok", nil)
	reply(w, http.StatusOK, map[string]bool{"created": true})
}

func (s *Server) getPrincipal(w http.ResponseWriter, r *http.Request, c caller) {
	name := principalName(r)
	if err := s.authorize(r.Context(), c, "principal:Read", "hv:principal/"+name, nil); err != nil {
		fail(w, err)
		return
	}
	p, err := s.cfg.Registry.GetPrincipal(r.Context(), name)
	if err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusOK, p)
}

func (s *Server) attachPolicy(w http.ResponseWriter, r *http.Request, c caller) {
	name := principalName(r)
	var req struct {
		Policy   string `json:"policy"`
		Boundary bool   `json:"boundary"`
		Detach   bool   `json:"detach"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	resource := "hv:principal/" + name
	if err := s.authorize(r.Context(), c, "policy:Attach", resource, map[string]string{}); err != nil {
		fail(w, err)
		return
	}
	if _, _, err := s.cfg.Registry.GetPolicy(r.Context(), req.Policy); err != nil && !req.Detach {
		fail(w, err)
		return
	}
	err := s.cfg.Registry.UpdatePrincipal(r.Context(), name, func(p *registry.Principal) error {
		list := &p.Policies
		if req.Boundary {
			list = &p.Boundary
			p.HasBoundary = true
		}
		*list = slices.DeleteFunc(*list, func(n string) bool { return n == req.Policy })
		if !req.Detach {
			*list = append(*list, req.Policy)
			slices.Sort(*list)
		}
		return nil
	})
	if err != nil {
		fail(w, err)
		return
	}
	// New rights apply at the next login; removed rights apply now.
	if req.Detach {
		s.cfg.Sessions.RevokePrincipal(name)
	}
	s.record(c, "policy:Attach", resource, "ok", map[string]string{"policy": req.Policy, "boundary": strconv.FormatBool(req.Boundary), "detach": strconv.FormatBool(req.Detach)})
	reply(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) disablePrincipal(w http.ResponseWriter, r *http.Request, c caller) {
	name := principalName(r)
	resource := "hv:principal/" + name
	if err := s.authorize(r.Context(), c, "principal:Disable", resource, nil); err != nil {
		fail(w, err)
		return
	}
	if err := s.cfg.Registry.UpdatePrincipal(r.Context(), name, func(p *registry.Principal) error { p.Disabled = true; return nil }); err != nil {
		fail(w, err)
		return
	}
	n := s.cfg.Sessions.RevokePrincipal(name)
	s.record(c, "principal:Disable", resource, "ok", map[string]string{"sessions_revoked": strconv.Itoa(n)})
	reply(w, http.StatusOK, map[string]int{"sessions_revoked": n})
}

func (s *Server) simulate(w http.ResponseWriter, r *http.Request, c caller) {
	var req struct {
		Principal string              `json:"principal"`
		Action    string              `json:"action"`
		Resource  string              `json:"resource"`
		Context   map[string][]string `json:"context"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, err)
		return
	}
	if err := s.authorize(r.Context(), c, "policy:Simulate", "hv:principal/"+req.Principal, nil); err != nil {
		fail(w, err)
		return
	}
	p, err := s.cfg.Registry.GetPrincipal(r.Context(), req.Principal)
	if err != nil {
		fail(w, err)
		return
	}
	set, err := s.cfg.Registry.PolicySet(r.Context(), p)
	if err != nil {
		fail(w, err)
		return
	}
	reqCtx := map[string][]string{}
	for k, v := range p.Tags {
		reqCtx["hv:PrincipalTag/"+k] = []string{v}
	}
	for k, v := range req.Context {
		reqCtx[k] = v
	}
	reply(w, http.StatusOK, iam.Simulate(set, iam.Request{Principal: p.Name, Action: req.Action, Resource: req.Resource, Context: reqCtx}))
}

// ---- Targets and audit ------------------------------------------------------------------

func (s *Server) putTarget(w http.ResponseWriter, r *http.Request, c caller) {
	var t registry.Target
	if err := decode(r, &t); err != nil {
		fail(w, err)
		return
	}
	if t.Name != r.PathValue("name") {
		fail(w, badRequest("name in the path and the body differ"))
		return
	}
	resource := "hv:" + t.Env + ":target/" + t.Name
	if err := s.authorize(r.Context(), c, "target:Register", resource, map[string]string{"hv:TargetKind": string(t.Kind), "hv:TargetName": t.Name, "hv:Env": t.Env}); err != nil {
		fail(w, err)
		return
	}
	if s.cfg.Targets != nil {
		if _, err := s.cfg.Targets(r.Context(), t); err != nil {
			fail(w, badRequest("target configuration: %v", err))
			return
		}
	}
	if err := s.cfg.Registry.PutTarget(r.Context(), t); err != nil {
		fail(w, err)
		return
	}
	s.record(c, "target:Register", resource, "ok", map[string]string{"kind": string(t.Kind)})
	reply(w, http.StatusOK, map[string]bool{"stored": true})
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request, c caller) {
	if err := s.authorize(r.Context(), c, "target:List", "hv:sys:targets", nil); err != nil {
		fail(w, err)
		return
	}
	names, err := s.cfg.Registry.ListTargets(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{"targets": names})
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request, c caller) {
	if err := s.authorize(r.Context(), c, "audit:Read", "hv:audit", nil); err != nil {
		fail(w, err)
		return
	}
	rep, err := audit.Verify(s.cfg.AuditPath, s.cfg.AuditKey, nil)
	if err != nil {
		reply(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "entries": rep.Entries})
		return
	}
	reply(w, http.StatusOK, map[string]any{"ok": true, "entries": rep.Entries, "head": rep.Head, "checkpoints": rep.Checkpoints})
}
