// Package daemon runs hashvaultd: it starts sealed, unseals through an
// operator ceremony, serves the API while unsealed, and seals itself again
// after a period without activity.
//
// Sealed, the daemon holds no OpenBao token and no key: it answers status
// and accepts an unseal request from the SSH tunnel only. Workloads keep
// running meanwhile, since targets were published while unsealed.
package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/MakFly/hashvault/internal/audit"
	"github.com/MakFly/hashvault/internal/authn"
	"github.com/MakFly/hashvault/internal/openbao"
	"github.com/MakFly/hashvault/internal/registry"
	"github.com/MakFly/hashvault/internal/secrets"
	"github.com/MakFly/hashvault/internal/server"
)

// Config is the daemon configuration (/etc/hashvault/hashvaultd.json).
type Config struct {
	VaultID      string `json:"vault_id"`
	Listen       string `json:"listen"`
	OpenBao      string `json:"openbao"`
	KVMount      string `json:"kv_mount"`
	TransitMount string `json:"transit_mount"`
	KEK          string `json:"kek"`
	AppRoleMount string `json:"approle_mount"`
	Role         string `json:"role"`
	RoleID       string `json:"role_id"`
	AuditPath    string `json:"audit_path"`
	TunnelUIDs   []int  `json:"tunnel_uids"`
	SSHDir       string `json:"ssh_dir"`
	// IdleSealMinutes seals after that long without an authenticated
	// request. 0 means 60; a negative value disables it.
	IdleSealMinutes int `json:"idle_seal_minutes"`
}

// Defaults fills the conventional values.
func (c *Config) Defaults() {
	set := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	set(&c.Listen, "/run/hashvault/api.sock")
	set(&c.OpenBao, "unix:///run/openbao/api.sock")
	set(&c.KVMount, "hv")
	set(&c.TransitMount, "transit")
	set(&c.KEK, "hv-kek-prod")
	set(&c.AppRoleMount, "approle")
	set(&c.Role, "hashvaultd")
	set(&c.AuditPath, "/var/lib/hashvault/audit.jsonl")
	set(&c.SSHDir, "/etc/hashvault/ssh")
	if c.IdleSealMinutes == 0 {
		c.IdleSealMinutes = 60
	}
}

const maxUnsealFailures = 5

// Daemon is the sealed/unsealed state machine and its HTTP entry point.
type Daemon struct {
	cfg Config
	now func() time.Time

	mu           sync.Mutex
	bao          *openbao.Client
	open         *unsealed
	lastActivity time.Time
	failures     int
	lockedUntil  time.Time
}

type unsealed struct {
	api       *server.Server
	log       *audit.Log
	auditKey  []byte
	batchKey  ed25519.PrivateKey
	stopRenew context.CancelFunc
}

// New returns a sealed daemon.
func New(cfg Config, now func() time.Time) (*Daemon, error) {
	cfg.Defaults()
	if cfg.RoleID == "" || cfg.VaultID == "" {
		return nil, errors.New("daemon: vault_id and role_id are required (run the bootstrap first)")
	}
	bao, err := openbao.New(openbao.Config{Address: cfg.OpenBao})
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Daemon{cfg: cfg, bao: bao, now: now}, nil
}

// Sealed reports the state.
func (d *Daemon) Sealed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.open == nil
}

// ServeHTTP routes to the sealed handlers or to the API.
func (d *Daemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/v1/sys/unseal" {
		d.unsealHandler(w, r)
		return
	}
	d.mu.Lock()
	open := d.open
	if open != nil && r.Header.Get("Authorization") != "" {
		d.lastActivity = d.now()
	}
	d.mu.Unlock()
	if open != nil {
		open.api.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet && r.URL.Path == "/v1/sys/status" {
		_ = json.NewEncoder(w).Encode(map[string]any{"vault": d.cfg.VaultID, "version": server.Version, "sealed": true})
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "sealed"})
}

func (d *Daemon) reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// unsealHandler accepts the decrypted bundle from an operator's SSH tunnel.
func (d *Daemon) unsealHandler(w http.ResponseWriter, r *http.Request) {
	uid, known := server.PeerUID(r.Context())
	if !known || !slices.Contains(d.cfg.TunnelUIDs, uid) {
		d.reply(w, http.StatusForbidden, map[string]string{"error": "unseal is only accepted from an operator SSH session"})
		return
	}
	d.mu.Lock()
	if d.now().Before(d.lockedUntil) {
		d.mu.Unlock()
		d.reply(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed unseal attempts, retry later"})
		return
	}
	d.mu.Unlock()
	var b Bundle
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || b.UnsealKey == "" || b.SecretID == "" {
		d.reply(w, http.StatusBadRequest, map[string]string{"error": "expected {unseal_key, secret_id}"})
		return
	}
	if err := d.Unseal(r.Context(), b); err != nil {
		d.mu.Lock()
		d.failures++
		if d.failures >= maxUnsealFailures {
			d.lockedUntil, d.failures = d.now().Add(time.Minute), 0
		}
		d.mu.Unlock()
		d.reply(w, http.StatusUnauthorized, map[string]string{"error": "unseal failed"})
		return
	}
	d.reply(w, http.StatusOK, map[string]bool{"sealed": false})
}

// Unseal unseals OpenBao if needed, logs in with the AppRole, loads the
// daemon's keys, opens the audit log and starts serving.
func (d *Daemon) Unseal(ctx context.Context, b Bundle) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.open != nil {
		return nil
	}
	st, err := d.bao.SealStatus(ctx)
	if err != nil {
		return err
	}
	if st.Sealed {
		if st, err = d.bao.Unseal(ctx, b.UnsealKey); err != nil {
			return err
		}
		if st.Sealed {
			return errors.New("daemon: OpenBao is still sealed")
		}
	}
	if err := d.bao.WaitActive(ctx, 30*time.Second); err != nil {
		return err
	}
	ttl, err := d.bao.AppRoleLogin(ctx, d.cfg.AppRoleMount, d.cfg.RoleID, b.SecretID)
	if err != nil {
		return err
	}
	store := secrets.New(d.bao, d.cfg.KVMount, openbao.NewTransitWrapper(d.bao, d.cfg.TransitMount, d.cfg.KEK))
	auditKey, _, err := store.Get(ctx, AuditKeyRef, 0)
	if err != nil {
		d.bao.SetToken("")
		return fmt.Errorf("daemon: audit key: %w", err)
	}
	batchKey, _, err := store.Get(ctx, BatchKeyRef, 0)
	if err != nil {
		clear(auditKey)
		d.bao.SetToken("")
		return fmt.Errorf("daemon: batch key: %w", err)
	}
	log, err := audit.Open(d.cfg.AuditPath, ed25519.PrivateKey(auditKey), d.now)
	if err != nil {
		clear(auditKey)
		clear(batchKey)
		d.bao.SetToken("")
		return err
	}
	if _, err := log.Append(audit.Entry{Principal: "operator", Action: "sys:Unseal", Resource: "hv:sys:unseal", Decision: "Allow", Outcome: "unsealed"}); err != nil {
		_ = log.Close()
		d.bao.SetToken("")
		return err
	}
	api := server.New(server.Config{
		VaultID: d.cfg.VaultID, Bao: d.bao, Store: store, Registry: registry.New(d.bao, d.cfg.KVMount),
		Sessions: authn.NewSessions(d.cfg.VaultID, d.now), Audit: log,
		AuditPath: d.cfg.AuditPath, AuditKey: ed25519.PrivateKey(auditKey).Public().(ed25519.PublicKey),
		TunnelUIDs: d.cfg.TunnelUIDs,
		Targets:    server.NewFactory(server.FactoryConfig{BatchSigner: ed25519.PrivateKey(batchKey), SSHDir: d.cfg.SSHDir}),
		Seal:       func(ctx context.Context) error { return d.Seal(ctx, "sealed by an operator") },
		Now:        d.now,
	})
	renewCtx, stop := context.WithCancel(context.Background())
	go d.renew(renewCtx, ttl)
	d.open = &unsealed{api: api, log: log, auditKey: auditKey, batchKey: ed25519.PrivateKey(batchKey), stopRenew: stop}
	d.lastActivity = d.now()
	d.failures = 0
	return nil
}

// renew keeps the periodic AppRole token alive while unsealed.
func (d *Daemon) renew(ctx context.Context, ttl time.Duration) {
	if ttl <= 0 {
		ttl = time.Hour
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(ttl / 2):
		}
		if next, err := d.bao.RenewSelf(ctx); err == nil && next > 0 {
			ttl = next
		}
	}
}

// Seal seals OpenBao, forgets the token and the keys, ends every session and
// closes the audit log.
func (d *Daemon) Seal(ctx context.Context, reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.open == nil {
		return nil
	}
	_, _ = d.open.log.Append(audit.Entry{Principal: "hashvaultd", Action: "sys:Seal", Resource: "hv:sys:seal", Decision: "Allow", Outcome: reason})
	sealErr := d.bao.Seal(ctx)
	d.open.stopRenew()
	_ = d.open.log.Close()
	clear(d.open.batchKey)
	clear(d.open.auditKey)
	d.bao.SetToken("")
	d.open = nil
	return sealErr
}

// RunIdleSeal seals the daemon after IdleSealMinutes without activity. It
// returns when ctx ends.
func (d *Daemon) RunIdleSeal(ctx context.Context, tick time.Duration) {
	if d.cfg.IdleSealMinutes < 0 {
		return
	}
	idle := time.Duration(d.cfg.IdleSealMinutes) * time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(tick):
		}
		d.mu.Lock()
		expired := d.open != nil && d.now().Sub(d.lastActivity) > idle
		d.mu.Unlock()
		if expired {
			_ = d.Seal(ctx, "idle")
		}
	}
}
