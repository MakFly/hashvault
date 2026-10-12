package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MakFly/hashvault/internal/agentcli"
	"github.com/MakFly/hashvault/internal/audit"
	"github.com/MakFly/hashvault/internal/authn"
	"github.com/MakFly/hashvault/internal/authn/authntest"
	"github.com/MakFly/hashvault/internal/batch"
	"github.com/MakFly/hashvault/internal/hostagent"
	"github.com/MakFly/hashvault/internal/openbao"
	"github.com/MakFly/hashvault/internal/openbao/baotest"
	"github.com/MakFly/hashvault/internal/registry"
	"github.com/MakFly/hashvault/internal/secrets"
	"github.com/MakFly/hashvault/internal/target"
	"github.com/MakFly/hashvault/internal/target/host"
)

var bg = context.Background()

const allowAll = `{"Version":"hv-1","Statement":[{"Effect":"Allow","Action":"*","Resource":"hv:*",
  "Condition":{"NumericLessThanEquals":{"hv:MfaAgeSeconds":900},"StringEquals":{"hv:SourceChannel":"tunnel"}}}]}`

const publisher = `{"Version":"hv-1","Statement":[
  {"Sid":"Publish","Effect":"Allow","Action":"secret:Publish","Resource":["hv:prod:secret/acme-api/*","hv:prod:target/*"],
   "Condition":{"StringEquals":{"hv:TargetKind":"ssh"}}},
  {"Sid":"NeverRead","Effect":"Deny","Action":["secret:Read","secret:Write"],"Resource":"*"}]}`

// ---- Fixture -------------------------------------------------------------------

type consumers struct {
	mu   sync.Mutex
	fail bool
	runs int
}

func (c *consumers) Run(context.Context, batch.Batch) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runs++
	if c.fail {
		return errors.New("service did not come back")
	}
	return nil
}

type agentTransport struct {
	cfgPath string
	cons    *consumers
}

func (t agentTransport) Deliver(_ context.Context, sealed []byte) (hostagent.Receipt, error) {
	var out bytes.Buffer
	agentcli.Main([]string{"receive", "--config", t.cfgPath}, agentcli.IO{
		Stdin: bytes.NewReader(sealed), Stdout: &out, Stderr: io.Discard,
		Agent: func(c *hostagent.Config) {
			c.AllowNonTmpfs = true
			c.Chown = func(string, int, int) error { return nil }
			c.Consumers = t.cons
		},
	})
	var r hostagent.Receipt
	err := json.Unmarshal(out.Bytes(), &r)
	return r, err
}

func (agentTransport) Describe() string { return "in-process" }

type fixture struct {
	t         *testing.T
	bao       *baotest.Server
	sock      string
	sessions  *authn.Sessions
	reg       *registry.Registry
	store     *secrets.Store
	auditPath string
	agentDir  string
	recipient string
	cons      *consumers
	tunnel    bool
	admin     authntest.Key
}

func newFixture(t *testing.T, tunnel bool) *fixture {
	t.Helper()
	bao := baotest.Start(t)
	f := &fixture{t: t, tunnel: tunnel, cons: &consumers{}, bao: bao}
	f.store = secrets.New(bao.Client, baotest.KVMount, openbao.NewTransitWrapper(bao.Client, baotest.TransitMount, baotest.KEK))
	f.reg = registry.New(bao.Client, baotest.KVMount)
	f.sessions = authn.NewSessions("vault-test", nil)
	dir := t.TempDir()
	f.auditPath = filepath.Join(dir, "audit.jsonl")
	auditPub, auditPriv, _ := ed25519.GenerateKey(rand.Reader)
	log, err := audit.Open(f.auditPath, auditPriv, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })

	// A host agent, enrolled with the vault's batch key.
	batchPub, batchPriv, _ := ed25519.GenerateKey(rand.Reader)
	f.agentDir = filepath.Join(dir, "agent")
	cfgPath := filepath.Join(f.agentDir, "config.json")
	var out bytes.Buffer
	if agentcli.Main([]string{"init", "--config", cfgPath, "--agent", "web-01", "--trusted-signer", base64.StdEncoding.EncodeToString(batchPub)},
		agentcli.IO{Stdout: &out, Stderr: io.Discard}) != 0 {
		t.Fatal("agent init")
	}
	f.recipient = strings.TrimSpace(out.String())
	creds := filepath.Join(f.agentDir, "bin", "systemd-creds")
	_ = os.MkdirAll(filepath.Dir(creds), 0o700)
	_ = os.WriteFile(creds, []byte("#!/bin/sh\nexec cat\n"), 0o700) // #nosec G306 -- test script
	var ac agentcli.Config
	raw, _ := os.ReadFile(cfgPath)
	_ = json.Unmarshal(raw, &ac)
	ac.CredstoreDir, ac.RuntimeDir, ac.StateDir, ac.SealerCommand = filepath.Join(f.agentDir, "cred"), filepath.Join(f.agentDir, "run"), filepath.Join(f.agentDir, "state"), []string{creds}
	raw, _ = json.Marshal(ac)
	_ = os.WriteFile(cfgPath, raw, 0o600)

	tunnelUIDs := []int{}
	if tunnel {
		tunnelUIDs = []int{os.Getuid()}
	}
	srv := New(Config{
		VaultID: "vault-test", Bao: bao.Client, Store: f.store, Registry: f.reg, Sessions: f.sessions,
		Audit: log, AuditPath: f.auditPath, AuditKey: auditPub, TunnelUIDs: tunnelUIDs,
		Targets: NewFactory(FactoryConfig{
			BatchSigner: batchPriv, SSHDir: dir,
			Transport: func(registry.Target) host.Transport { return agentTransport{cfgPath: cfgPath, cons: f.cons} },
		}),
	})
	f.sock = filepath.Join(dir, "api.sock")
	l, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv, ConnContext: ConnContext, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(l) }()
	t.Cleanup(func() { _ = hs.Close() })

	// Bootstrap: an admin principal and its policy, written directly.
	f.admin = authntest.SK(authn.FlagUserPresent)
	if err := f.reg.PutPolicy(bg, "admin", []byte(allowAll)); err != nil {
		t.Fatal(err)
	}
	if err := f.reg.PutPrincipal(bg, registry.Principal{Name: "human/admin", SSHKey: f.admin.Line, Policies: []string{"admin"}}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) client() *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", f.sock)
	}}}
}

func (f *fixture) do(token, method, path string, body any) (int, map[string]any) {
	f.t.Helper()
	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		reader = bytes.NewReader(b)
	default:
		data, _ := json.Marshal(b)
		reader = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, "http://hashvault"+path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (f *fixture) login(name string, key authntest.Key) string {
	f.t.Helper()
	code, ch := f.do("", "POST", "/v1/auth/challenge", map[string]string{"principal": name})
	if code != 200 {
		f.t.Fatalf("challenge: %d %v", code, ch)
	}
	sig := key.Sign([]byte(ch["message"].(string)), authn.Namespace)
	code, out := f.do("", "POST", "/v1/auth/login", map[string]string{"id": ch["id"].(string), "principal": name, "signature": string(sig)})
	if code != 200 {
		f.t.Fatalf("login %s: %d %v", name, code, out)
	}
	return out["token"].(string)
}

func b64(s string) map[string]string {
	return map[string]string{"value": base64.StdEncoding.EncodeToString([]byte(s))}
}

// ---- Tests ---------------------------------------------------------------------

func TestStatusAndLogin(t *testing.T) {
	f := newFixture(t, true)
	code, st := f.do("", "GET", "/v1/sys/status", nil)
	if code != 200 || st["sealed"] != false || st["vault"] != "vault-test" {
		t.Fatalf("%d %v", code, st)
	}
	if code, _ := f.do("", "GET", "/v1/secrets/prod/acme-api", nil); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := f.do("hvs.bogus", "GET", "/v1/secrets/prod/acme-api", nil); code != 401 {
		t.Fatalf("bad token: %d", code)
	}
	// A signature by another key does not log in, and spends the challenge.
	_, ch := f.do("", "POST", "/v1/auth/challenge", map[string]string{"principal": "human/admin"})
	other := authntest.SK(authn.FlagUserPresent)
	code, _ = f.do("", "POST", "/v1/auth/login", map[string]string{"id": ch["id"].(string), "principal": "human/admin", "signature": string(other.Sign([]byte(ch["message"].(string)), authn.Namespace))})
	if code != 401 {
		t.Fatalf("foreign signature: %d", code)
	}
	code, _ = f.do("", "POST", "/v1/auth/login", map[string]string{"id": "x", "principal": "human/nobody", "signature": "x"})
	if code != 401 {
		t.Fatalf("unknown principal: %d", code)
	}
	token := f.login("human/admin", f.admin)
	if code, _ := f.do(token, "POST", "/v1/auth/logout", nil); code != 200 {
		t.Fatal("logout")
	}
	if code, _ := f.do(token, "GET", "/v1/secrets/prod/acme-api", nil); code != 401 {
		t.Fatal("token valid after logout")
	}
}

func TestSecretsLifecycleThroughTheTunnel(t *testing.T) {
	f := newFixture(t, true)
	token := f.login("human/admin", f.admin)
	code, out := f.do(token, "PUT", "/v1/secrets/prod/acme-api/DATABASE_URL", b64("postgres://v1"))
	if code != 200 || out["version"] != float64(1) {
		t.Fatalf("%d %v", code, out)
	}
	f.do(token, "PUT", "/v1/secrets/prod/acme-api/DATABASE_URL", b64("postgres://v2"))
	code, out = f.do(token, "GET", "/v1/secrets/prod/acme-api/DATABASE_URL?version=1", nil)
	if code != 200 || out["value"] != base64.StdEncoding.EncodeToString([]byte("postgres://v1")) {
		t.Fatalf("%d %v", code, out)
	}
	code, out = f.do(token, "GET", "/v1/secrets/prod/acme-api", nil)
	if code != 200 || fmt.Sprint(out["keys"]) != "[DATABASE_URL]" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := f.do(token, "POST", "/v1/secrets/prod/acme-api/DATABASE_URL/rewrap", nil); code != 200 {
		t.Fatalf("rewrap %d", code)
	}
	if code, _ := f.do(token, "DELETE", "/v1/secrets/prod/acme-api/DATABASE_URL/versions/1", nil); code != 200 {
		t.Fatalf("destroy %d", code)
	}
	if code, _ := f.do(token, "GET", "/v1/secrets/prod/acme-api/DATABASE_URL?version=1", nil); code != 410 {
		t.Fatalf("destroyed version: %d", code)
	}
	for name, req := range map[string][2]string{
		"bad key":       {"PUT", "/v1/secrets/prod/acme-api/bad-key"},
		"bad version":   {"GET", "/v1/secrets/prod/acme-api/DATABASE_URL?version=x"},
		"zero version":  {"DELETE", "/v1/secrets/prod/acme-api/DATABASE_URL/versions/0"},
		"missing":       {"GET", "/v1/secrets/prod/acme-api/NOPE"},
		"bad list path": {"GET", "/v1/secrets/Prod/acme-api"},
	} {
		code, _ := f.do(token, req[0], req[1], b64("x"))
		if code < 400 || code >= 500 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _ := f.do(token, "PUT", "/v1/secrets/prod/acme-api/K", map[string]string{"value": "%%%"}); code != 400 {
		t.Fatalf("non-base64 value: %d", code)
	}
	if code, _ := f.do(token, "PUT", "/v1/secrets/prod/acme-api/K", map[string]any{"value": "", "extra": 1}); code != 400 {
		t.Fatalf("unknown field: %d", code)
	}
}

// The same admin, through the socket instead of the tunnel, is denied: the
// channel comes from the kernel, not from the client.
func TestTheSourceChannelComesFromTheKernel(t *testing.T) {
	f := newFixture(t, false)
	token := f.login("human/admin", f.admin)
	if code, _ := f.do(token, "PUT", "/v1/secrets/prod/acme-api/K", b64("v")); code != 403 {
		t.Fatalf("want 403 outside the tunnel, got %d", code)
	}
	rep, err := audit.Verify(f.auditPath, nil, nil)
	if err != nil || rep.Entries < 2 {
		t.Fatalf("decisions must be audited: %+v %v", rep, err)
	}
	data, _ := os.ReadFile(f.auditPath)
	if !bytes.Contains(data, []byte(`"decision":"ImplicitDeny"`)) || !bytes.Contains(data, []byte(`"channel":"socket"`)) {
		t.Fatalf("audit log lacks the denial: %s", data)
	}
}

func TestAdministrationAndSimulation(t *testing.T) {
	f := newFixture(t, true)
	token := f.login("human/admin", f.admin)
	if code, out := f.do(token, "PUT", "/v1/policies/publisher", []byte(publisher)); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := f.do(token, "PUT", "/v1/policies/typo", []byte(`{"Version":"hv-1","Statement":[{"Effect":"Allow","Action":"secret:Publsh","Resource":"*"}]}`)); code != 400 {
		t.Fatalf("typo policy: %d", code)
	}
	if code, out := f.do(token, "GET", "/v1/policies/publisher", nil); code != 200 || out["document"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	bot := authntest.Ed25519()
	code, out := f.do(token, "POST", "/v1/principals", map[string]any{"name": "machine/deployer", "ssh_key": bot.Line, "policies": []string{"admin"}})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := f.do(token, "GET", "/v1/principals/machine/deployer", nil); code != 200 || out["policies"] != nil {
		t.Fatalf("policies must not be attached at creation: %d %v", code, out)
	}
	if code, _ := f.do(token, "POST", "/v1/principals/machine/deployer/attach", map[string]any{"policy": "publisher"}); code != 200 {
		t.Fatal("attach")
	}
	if code, _ := f.do(token, "POST", "/v1/principals/machine/deployer/attach", map[string]any{"policy": "missing"}); code != 404 {
		t.Fatal("attaching a missing policy")
	}
	code, sim := f.do(token, "POST", "/v1/iam/simulate", map[string]any{
		"principal": "machine/deployer", "action": "secret:Read", "resource": "hv:prod:secret/acme-api/DB",
	})
	if code != 200 || sim["Decision"] != "ExplicitDeny" || sim["Trace"] == nil {
		t.Fatalf("%d %v", code, sim)
	}
	botToken := f.login("machine/deployer", bot)
	if code, _ := f.do(botToken, "GET", "/v1/secrets/prod/acme-api/DB", nil); code != 403 {
		t.Fatalf("the deployer read a secret: %d", code)
	}
	if code, _ := f.do(token, "POST", "/v1/principals/machine/deployer/attach", map[string]any{"policy": "publisher", "detach": true}); code != 200 {
		t.Fatal("detach")
	}
	if code, _ := f.do(botToken, "GET", "/v1/targets", nil); code != 401 {
		t.Fatalf("a detach must end the sessions: %d", code)
	}
	if code, out := f.do(token, "POST", "/v1/principals/machine/deployer/disable", nil); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	code, ch := f.do("", "POST", "/v1/auth/challenge", map[string]string{"principal": "machine/deployer"})
	if code != 200 {
		t.Fatal(code)
	}
	code, _ = f.do("", "POST", "/v1/auth/login", map[string]string{"id": ch["id"].(string), "principal": "machine/deployer", "signature": string(bot.Sign([]byte(ch["message"].(string)), authn.Namespace))})
	if code != 401 {
		t.Fatalf("a disabled principal logged in: %d", code)
	}
	if code, out := f.do(token, "GET", "/v1/audit/verify", nil); code != 200 || out["ok"] != true {
		t.Fatalf("%d %v", code, out)
	}
}

func manifest() map[string]any {
	return map[string]any{"version": "hv-manifest-1", "app": "acme-api", "items": map[string]any{
		"DATABASE_URL": map[string]any{"expose": "env", "services": []string{"web"}},
	}}
}

func TestPublishToAnSSHTarget(t *testing.T) {
	f := newFixture(t, true)
	token := f.login("human/admin", f.admin)
	tg := map[string]any{"name": "ssh-web-01", "kind": "ssh", "env": "prod", "config": map[string]any{
		"agent": "web-01", "recipient": f.recipient, "transport": map[string]any{"type": "ssh"},
	}}
	if code, out := f.do(token, "PUT", "/v1/targets/ssh-web-01", tg); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	f.do(token, "PUT", "/v1/secrets/prod/acme-api/DATABASE_URL", b64("v1"))

	code, out := f.do(token, "POST", "/v1/publish", map[string]any{"target": "ssh-web-01", "manifest": manifest(), "dry_run": true})
	if code != 200 || out["status"] != "planned" || f.cons.runs != 0 {
		t.Fatalf("dry run: %d %v", code, out)
	}
	code, out = f.do(token, "POST", "/v1/publish", map[string]any{"target": "ssh-web-01", "manifest": manifest()})
	if code != 200 || out["status"] != "published" {
		t.Fatalf("%d %v", code, out)
	}
	env, _ := os.ReadFile(filepath.Join(f.agentDir, "run", "acme-api", "web", ".env"))
	if string(env) != "DATABASE_URL='v1'\n" {
		t.Fatalf("agent .env %q", env)
	}
	pub, err := f.reg.GetPublication(bg, "ssh-web-01", "acme-api")
	if err != nil || pub.Versions["DATABASE_URL"] != 1 || pub.By != "human/admin" {
		t.Fatalf("%+v %v", pub, err)
	}

	f.do(token, "PUT", "/v1/secrets/prod/acme-api/DATABASE_URL", b64("v2"))
	f.cons.fail = true
	code, out = f.do(token, "POST", "/v1/publish", map[string]any{"target": "ssh-web-01", "manifest": manifest()})
	if code != 502 || out["status"] != "rolled_back" {
		t.Fatalf("%d %v", code, out)
	}
	env, _ = os.ReadFile(filepath.Join(f.agentDir, "run", "acme-api", "web", ".env"))
	if string(env) != "DATABASE_URL='v1'\n" {
		t.Fatalf("after a failed restart the agent must keep v1: %q", env)
	}
	f.cons.fail = false

	// A pinned older version needs the rollback flag.
	code, _ = f.do(token, "POST", "/v1/publish", map[string]any{"target": "ssh-web-01", "manifest": manifest(), "versions": map[string]int{"DATABASE_URL": 2}})
	if code != 200 {
		t.Fatalf("publish v2: %d", code)
	}
	code, _ = f.do(token, "POST", "/v1/publish", map[string]any{"target": "ssh-web-01", "manifest": manifest(), "versions": map[string]int{"DATABASE_URL": 1}})
	if code != 502 {
		t.Fatalf("an unflagged downgrade: %d", code)
	}
	code, _ = f.do(token, "POST", "/v1/publish", map[string]any{"target": "ssh-web-01", "manifest": manifest(), "versions": map[string]int{"DATABASE_URL": 1}, "rollback": true})
	if code != 200 {
		t.Fatalf("a signed rollback: %d", code)
	}
	if code, _ := f.do(token, "POST", "/v1/publish", map[string]any{"target": "ssh-web-01", "manifest": manifest(), "versions": map[string]int{"OTHER": 1}}); code != 400 {
		t.Fatal("pinning a key outside the manifest")
	}
	if code, _ := f.do(token, "POST", "/v1/publish", map[string]any{"target": "missing", "manifest": manifest()}); code != 404 {
		t.Fatal("unknown target")
	}
}

func TestPublishIsAuthorizedPerKeyAndTarget(t *testing.T) {
	f := newFixture(t, true)
	admin := f.login("human/admin", f.admin)
	f.do(admin, "PUT", "/v1/policies/publisher", []byte(publisher))
	bot := authntest.Ed25519()
	f.do(admin, "POST", "/v1/principals", map[string]any{"name": "machine/deployer", "ssh_key": bot.Line})
	f.do(admin, "POST", "/v1/principals/machine/deployer/attach", map[string]any{"policy": "publisher"})
	f.do(admin, "PUT", "/v1/targets/ssh-web-01", map[string]any{"name": "ssh-web-01", "kind": "ssh", "env": "prod", "config": map[string]any{
		"agent": "web-01", "recipient": f.recipient, "transport": map[string]any{"type": "ssh"},
	}})
	f.do(admin, "PUT", "/v1/secrets/prod/acme-api/DATABASE_URL", b64("v1"))
	f.do(admin, "PUT", "/v1/secrets/prod/billing/KEY", b64("b"))
	tok := f.login("machine/deployer", bot)

	if code, out := f.do(tok, "POST", "/v1/publish", map[string]any{"target": "ssh-web-01", "manifest": manifest()}); code != 200 {
		t.Fatalf("allowed publication: %d %v", code, out)
	}
	other := map[string]any{"version": "hv-manifest-1", "app": "billing", "items": map[string]any{"KEY": map[string]any{"expose": "file", "services": []string{"web"}}}}
	if code, _ := f.do(tok, "POST", "/v1/publish", map[string]any{"target": "ssh-web-01", "manifest": other}); code != 403 {
		t.Fatalf("another app's secret was published: %d", code)
	}
}

func TestTargetRegistrationIsBounded(t *testing.T) {
	f := newFixture(t, true)
	token := f.login("human/admin", f.admin)
	for name, tg := range map[string]map[string]any{
		"tcp docker":    {"name": "s", "kind": "swarm", "env": "prod", "config": map[string]any{"docker": "tcp://10.0.0.1:2375"}},
		"unknown field": {"name": "s", "kind": "swarm", "env": "prod", "config": map[string]any{"dockr": "x"}},
		"k3s standby":   {"name": "k", "kind": "k3s", "env": "prod", "config": map[string]any{}},
		"k8s standby":   {"name": "k", "kind": "k8s", "env": "prod", "config": map[string]any{}},
		"bad recipient": {"name": "h", "kind": "ssh", "env": "prod", "config": map[string]any{"agent": "a", "recipient": "nope", "transport": map[string]any{"type": "ssh"}}},
		"bad transport": {"name": "h", "kind": "docker", "env": "prod", "config": map[string]any{"agent": "a", "recipient": f.recipient, "transport": map[string]any{"type": "rsh"}}},
		"name mismatch": {"name": "other", "kind": "swarm", "env": "prod", "config": map[string]any{}},
		"bad kind":      {"name": "s", "kind": "nomad", "env": "prod", "config": map[string]any{}},
	} {
		path := "/v1/targets/" + map[bool]string{true: "s", false: fmt.Sprint(tg["name"])}[name == "name mismatch"]
		if code, _ := f.do(token, "PUT", path, tg); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	ok := map[string]any{"name": "swarm-main", "kind": "swarm", "env": "prod", "config": map[string]any{"stack": "acme"}}
	if code, out := f.do(token, "PUT", "/v1/targets/swarm-main", ok); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := f.do(token, "GET", "/v1/targets", nil); code != 200 || fmt.Sprint(out["targets"]) != "[swarm-main]" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestSSHTransportFilesMustStayInTheSSHDir(t *testing.T) {
	fc := FactoryConfig{SSHDir: "/etc/hashvault/ssh"}
	for _, bad := range []string{"", "/etc/shadow", "../id", "sub/id"} {
		if _, err := fc.inSSHDir(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if p, err := fc.inSSHDir("push_ed25519"); err != nil || p != "/etc/hashvault/ssh/push_ed25519" {
		t.Fatal(p, err)
	}
	if _, err := (FactoryConfig{}).inSSHDir("id"); err == nil {
		t.Fatal("no SSH dir configured, yet accepted")
	}
	tr, err := fc.transport(registry.Target{}, transportConfig{Type: "ssh", Host: "h", User: "u", KeyFile: "push", KnownHostsFile: "known_hosts"})
	if err != nil || tr.Describe() != "ssh u@h" {
		t.Fatal(tr, err)
	}
	if tr, err := fc.transport(registry.Target{}, transportConfig{Type: "sudo"}); err != nil || tr.Describe() != "local sudo" {
		t.Fatal(tr, err)
	}
	_ = target.Swarm
}

// A principal without any policy is refused everywhere, and every refusal is
// a generic 403 that names nothing.
func TestEveryEndpointDeniesWithoutPolicy(t *testing.T) {
	f := newFixture(t, true)
	nobody := authntest.SK(authn.FlagUserPresent)
	if err := f.reg.PutPrincipal(bg, registry.Principal{Name: "human/nobody", SSHKey: nobody.Line}); err != nil {
		t.Fatal(err)
	}
	tok := f.login("human/nobody", nobody)
	calls := []struct {
		method, path string
		body         any
	}{
		{"PUT", "/v1/secrets/prod/acme-api/K", b64("v")},
		{"GET", "/v1/secrets/prod/acme-api/K", nil},
		{"GET", "/v1/secrets/prod/acme-api", nil},
		{"DELETE", "/v1/secrets/prod/acme-api/K/versions/1", nil},
		{"POST", "/v1/secrets/prod/acme-api/K/rewrap", nil},
		{"PUT", "/v1/policies/x", []byte(allowAll)},
		{"GET", "/v1/policies/admin", nil},
		{"POST", "/v1/principals", map[string]any{"name": "machine/x", "ssh_key": authntest.Ed25519().Line}},
		{"GET", "/v1/principals/human/admin", nil},
		{"POST", "/v1/principals/human/nobody/attach", map[string]any{"policy": "admin"}},
		{"POST", "/v1/principals/human/admin/disable", nil},
		{"POST", "/v1/iam/simulate", map[string]any{"principal": "human/admin", "action": "secret:Read", "resource": "hv:prod:secret/a/B"}},
		{"PUT", "/v1/targets/s", map[string]any{"name": "s", "kind": "swarm", "env": "prod", "config": map[string]any{}}},
		{"GET", "/v1/targets", nil},
		{"GET", "/v1/audit/verify", nil},
	}
	for _, c := range calls {
		code, out := f.do(tok, c.method, c.path, c.body)
		if code != 403 || out["error"] != "forbidden" {
			t.Errorf("%s %s: %d %v", c.method, c.path, code, out)
		}
	}
	if p, _ := f.reg.GetPrincipal(bg, "human/nobody"); len(p.Policies) != 0 {
		t.Fatal("a refused attach changed the principal")
	}
}

func TestMalformedRequestsAreRejected(t *testing.T) {
	f := newFixture(t, true)
	tok := f.login("human/admin", f.admin)
	for name, c := range map[string]struct {
		method, path string
		body         any
		want         int
	}{
		"challenge garbage": {"POST", "/v1/auth/challenge", []byte("{"), 400},
		"login garbage":     {"POST", "/v1/auth/login", []byte("[]"), 400},
		"principal garbage": {"POST", "/v1/principals", []byte(`{"name":1}`), 400},
		"attach garbage":    {"POST", "/v1/principals/human/admin/attach", []byte(`{"policy":`), 400},
		"simulate garbage":  {"POST", "/v1/iam/simulate", []byte(`{"x":1}`), 400},
		"target garbage":    {"PUT", "/v1/targets/s", []byte(`{}{}`), 400},
		"publish garbage":   {"POST", "/v1/publish", []byte(`nope`), 400},
		"bad manifest":      {"POST", "/v1/publish", map[string]any{"target": "x", "manifest": map[string]any{"version": "1"}}, 404},
		"simulate unknown":  {"POST", "/v1/iam/simulate", map[string]any{"principal": "human/ghost", "action": "secret:Read", "resource": "hv:a"}, 404},
		"missing principal": {"GET", "/v1/principals/human/ghost", nil, 404},
		"missing policy":    {"GET", "/v1/policies/ghost", nil, 404},
		"disable missing":   {"POST", "/v1/principals/human/ghost/disable", nil, 404},
		"duplicate":         {"POST", "/v1/principals", map[string]any{"name": "human/admin", "ssh_key": f.admin.Line}, 400},
		"huge body":         {"PUT", "/v1/policies/big", bytes.Repeat([]byte("a"), maxBody+1), 400},
	} {
		code, out := f.do(tok, c.method, c.path, c.body)
		if code != c.want {
			t.Errorf("%s: want %d, got %d %v", name, c.want, code, out)
		}
	}
}

func TestAnOpenBaoOutageFailsClosed(t *testing.T) {
	f := newFixture(t, true)
	tok := f.login("human/admin", f.admin)
	f.bao.Stop()
	if code, st := f.do("", "GET", "/v1/sys/status", nil); code != 200 || st["sealed"] != true {
		t.Fatalf("status during an outage: %d %v", code, st)
	}
	for _, c := range [][2]string{{"GET", "/v1/secrets/prod/acme-api/K"}, {"GET", "/v1/targets"}, {"POST", "/v1/publish"}} {
		var body any
		if c[1] == "/v1/publish" {
			body = map[string]any{"target": "x", "manifest": manifest()}
		}
		code, out := f.do(tok, c[0], c[1], body)
		if code < 403 || out["error"] == nil || strings.Contains(fmt.Sprint(out["error"]), "127.0.0.1") {
			t.Errorf("%s %s: %d %v", c[0], c[1], code, out)
		}
	}
}

func TestAuditVerifyReportsTampering(t *testing.T) {
	f := newFixture(t, true)
	tok := f.login("human/admin", f.admin)
	f.do(tok, "GET", "/v1/targets", nil)
	data, _ := os.ReadFile(f.auditPath)
	tampered := bytes.Replace(data, []byte(`"decision":"Allow"`), []byte(`"decision":"Deny"`), 1)
	if err := os.WriteFile(f.auditPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := f.do(tok, "GET", "/v1/audit/verify", nil)
	if code != 200 || out["ok"] != false || !strings.Contains(fmt.Sprint(out["error"]), "modified") {
		t.Fatalf("%d %v", code, out)
	}
}
