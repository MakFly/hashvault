package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/MakFly/hashvault/internal/audit"
	"github.com/MakFly/hashvault/internal/authn"
	"github.com/MakFly/hashvault/internal/authn/authntest"
	"github.com/MakFly/hashvault/internal/openbao/baotest"
	"github.com/MakFly/hashvault/internal/server"
)

var bg = context.Background()

type rig struct {
	t      *testing.T
	d      *Daemon
	sock   string
	bundle Bundle
	admin  authntest.Key
	res    BootstrapResult
	bao    *baotest.Server
	cfg    Config
}

func setup(t *testing.T, tunnel bool, idle int) *rig {
	t.Helper()
	bao := baotest.StartUninitialized(t)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	admin := authntest.SK(authn.FlagUserPresent)
	res, err := Bootstrap(bg, bao.Client, BootstrapOptions{
		KVMount: "hv", TransitMount: "transit", KEK: "hv-kek-prod", AppRoleMount: "approle", Role: "hashvaultd",
		AdminName: "human/admin", AdminKey: admin.Line, Recipients: []age.Recipient{id.Recipient()},
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := OpenBundle(res.Bundle, id)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	uids := []int{}
	if tunnel {
		uids = []int{os.Getuid()}
	}
	cfg := Config{
		VaultID: "vault-test", Listen: filepath.Join(dir, "api.sock"), OpenBao: bao.Address, RoleID: res.RoleID,
		AuditPath: filepath.Join(dir, "audit.jsonl"), TunnelUIDs: uids, SSHDir: dir, IdleSealMinutes: idle,
	}
	d, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: d, ConnContext: server.ConnContext, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(l) }()
	t.Cleanup(func() { _ = hs.Close() })
	return &rig{t: t, d: d, sock: cfg.Listen, bundle: bundle, admin: admin, res: res, bao: bao, cfg: cfg}
}

func (r *rig) do(token, method, path string, body any) (int, map[string]any) {
	r.t.Helper()
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, "http://hashvault"+path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", r.sock)
	}}}
	resp, err := c.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (r *rig) login() string {
	r.t.Helper()
	_, ch := r.do("", "POST", "/v1/auth/challenge", map[string]string{"principal": "human/admin"})
	sig := r.admin.Sign([]byte(ch["message"].(string)), authn.Namespace)
	code, out := r.do("", "POST", "/v1/auth/login", map[string]string{"id": ch["id"].(string), "principal": "human/admin", "signature": string(sig)})
	if code != 200 {
		r.t.Fatalf("login %d %v", code, out)
	}
	return out["token"].(string)
}

func TestBootstrapUnsealServeSeal(t *testing.T) {
	r := setup(t, true, 60)
	if len(r.res.AuditKey) != 32 || len(r.res.BatchKey) != 32 || r.res.RoleID == "" {
		t.Fatalf("bootstrap result %+v", r.res)
	}
	// The root token was revoked: an empty token gets nothing.
	if _, err := r.bao.Client.KVList(bg, "hv", "_sys"); err == nil {
		t.Fatal("the bootstrap left a usable token on the client")
	}

	if code, st := r.do("", "GET", "/v1/sys/status", nil); code != 200 || st["sealed"] != true {
		t.Fatalf("a fresh daemon must be sealed: %d %v", code, st)
	}
	if code, _ := r.do("", "POST", "/v1/auth/challenge", map[string]string{"principal": "human/admin"}); code != 503 {
		t.Fatalf("sealed API answered: %d", code)
	}
	if code, _ := r.do("", "POST", "/v1/sys/unseal", Bundle{UnsealKey: r.bundle.UnsealKey, SecretID: "wrong"}); code != 401 {
		t.Fatalf("a wrong secret id: %d", code)
	}
	if code, out := r.do("", "POST", "/v1/sys/unseal", r.bundle); code != 200 {
		t.Fatalf("unseal: %d %v", code, out)
	}
	token := r.login()
	code, out := r.do(token, "PUT", "/v1/secrets/prod/acme-api/DATABASE_URL", map[string]string{"value": base64.StdEncoding.EncodeToString([]byte("v1"))})
	if code != 200 {
		t.Fatalf("put: %d %v", code, out)
	}

	if code, out := r.do(token, "POST", "/v1/sys/seal", nil); code != 200 {
		t.Fatalf("seal: %d %v", code, out)
	}
	if st, _ := r.bao.Client.SealStatus(bg); !st.Sealed {
		t.Fatal("sealing hashvault must seal OpenBao")
	}
	if code, _ := r.do(token, "GET", "/v1/secrets/prod/acme-api/DATABASE_URL", nil); code != 503 {
		t.Fatalf("a session survived the seal: %d", code)
	}

	// A second ceremony brings everything back, OpenBao included.
	if code, _ := r.do("", "POST", "/v1/sys/unseal", r.bundle); code != 200 {
		t.Fatal("second unseal")
	}
	token = r.login()
	code, out = r.do(token, "GET", "/v1/secrets/prod/acme-api/DATABASE_URL", nil)
	if code != 200 || out["value"] != base64.StdEncoding.EncodeToString([]byte("v1")) {
		t.Fatalf("after re-unseal: %d %v", code, out)
	}
	rep, err := audit.Verify(r.cfg.AuditPath, r.res.AuditKey, nil)
	if err != nil || rep.Entries < 5 {
		t.Fatalf("audit across seals: %+v %v", rep, err)
	}
	data, _ := os.ReadFile(r.cfg.AuditPath)
	for _, want := range []string{`"sys:Unseal"`, `"sys:Seal"`, `"secret:Write"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("audit lacks %s", want)
		}
	}
}

func TestUnsealOnlyFromTheTunnelAndRateLimited(t *testing.T) {
	r := setup(t, false, 60)
	if code, _ := r.do("", "POST", "/v1/sys/unseal", r.bundle); code != 403 {
		t.Fatalf("unseal outside the tunnel: %d", code)
	}
	r.d.cfg.TunnelUIDs = []int{os.Getuid()}
	for range maxUnsealFailures {
		if code, _ := r.do("", "POST", "/v1/sys/unseal", Bundle{UnsealKey: r.bundle.UnsealKey, SecretID: "nope"}); code != 401 {
			t.Fatalf("wrong secret id: %d", code)
		}
	}
	if code, _ := r.do("", "POST", "/v1/sys/unseal", r.bundle); code != 429 {
		t.Fatalf("after %d failures the daemon must lock out: %d", maxUnsealFailures, code)
	}
	if code, _ := r.do("", "POST", "/v1/sys/unseal", map[string]string{"unseal_key": "x"}); code != 429 {
		t.Fatalf("lockout applies to every request: %d", code)
	}
}

func TestIdleSeal(t *testing.T) {
	r := setup(t, true, 1)
	clock := time.Now()
	r.d.now = func() time.Time { return clock }
	if err := r.d.Unseal(bg, r.bundle); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	go r.d.RunIdleSeal(ctx, 20*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	if r.d.Sealed() {
		t.Fatal("sealed before the idle delay")
	}
	clock = clock.Add(2 * time.Minute)
	deadline := time.Now().Add(5 * time.Second)
	for !r.d.Sealed() {
		if time.Now().After(deadline) {
			t.Fatal("the daemon did not seal itself when idle")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestBootstrapRunsOnce(t *testing.T) {
	r := setup(t, true, 60)
	id, _ := age.GenerateX25519Identity()
	_, err := Bootstrap(bg, r.bao.Client, BootstrapOptions{
		KVMount: "hv", TransitMount: "transit", KEK: "hv-kek-prod", AppRoleMount: "approle", Role: "hashvaultd",
		AdminName: "human/admin", AdminKey: r.admin.Line, Recipients: []age.Recipient{id.Recipient()},
	})
	if err == nil || !strings.Contains(err.Error(), "already initialised") {
		t.Fatalf("a second bootstrap: %v", err)
	}
	if _, err := Bootstrap(bg, r.bao.Client, BootstrapOptions{AdminName: "human/admin", AdminKey: r.admin.Line}); err == nil {
		t.Fatal("no recipient accepted")
	}
	if _, err := Bootstrap(bg, r.bao.Client, BootstrapOptions{AdminName: "admin", AdminKey: r.admin.Line, Recipients: []age.Recipient{id.Recipient()}}); err == nil {
		t.Fatal("an invalid admin accepted")
	}
	if _, err := OpenBundle(r.res.Bundle, id); err == nil {
		t.Fatal("a bundle opened with a foreign identity")
	}
	if _, err := New(Config{}, nil); err == nil {
		t.Fatal("a daemon without role id was created")
	}
}
