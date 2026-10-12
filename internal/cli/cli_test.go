package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/MakFly/hashvault/internal/agekeys"
	"github.com/MakFly/hashvault/internal/authn"
	"github.com/MakFly/hashvault/internal/authn/authntest"
	"github.com/MakFly/hashvault/internal/daemon"
	"github.com/MakFly/hashvault/internal/openbao/baotest"
	"github.com/MakFly/hashvault/internal/server"
)

const allowAll = `{"Version":"hv-1","Statement":[{"Effect":"Allow","Action":"*","Resource":"hv:*"}]}`

type env struct {
	t         *testing.T
	dir, sock string
	tokenFile string
	bundle    string
	identity  string
}

func (e env) run(stdin string, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Main(args, IO{
		Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut,
		Getenv: func(k string) string {
			switch k {
			case "HASHVAULT_SOCKET":
				return e.sock
			case "HASHVAULT_TOKEN_FILE":
				return e.tokenFile
			}
			return ""
		},
		Prompter: agekeys.Prompter{Out: io.Discard},
	})
	return code, out.String(), errOut.String()
}

func (e env) must(stdin string, args ...string) string {
	e.t.Helper()
	code, out, errOut := e.run(stdin, args...)
	if code != 0 {
		e.t.Fatalf("hashvault %v: exit %d\n%s", args, code, errOut)
	}
	return out
}

// startVault bootstraps a real OpenBao and serves hashvaultd on a socket.
func startVault(t *testing.T) (env, authntest.Key) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	bao := baotest.StartUninitialized(t)
	id, _ := age.GenerateX25519Identity()
	admin := authntest.SK(authn.FlagUserPresent)
	res, err := daemon.Bootstrap(context.Background(), bao.Client, daemon.BootstrapOptions{
		KVMount: "hv", TransitMount: "transit", KEK: "hv-kek-prod", AppRoleMount: "approle", Role: "hashvaultd",
		AdminName: "human/admin", AdminKey: admin.Line, Recipients: []age.Recipient{id.Recipient()},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	e := env{t: t, dir: dir, sock: filepath.Join(dir, "api.sock"), tokenFile: filepath.Join(dir, "token"),
		bundle: filepath.Join(dir, "bundle.age"), identity: filepath.Join(dir, "id.txt")}
	_ = os.WriteFile(e.bundle, res.Bundle, 0o600)
	_ = os.WriteFile(e.identity, []byte("# offline key\n"+id.String()+"\n"), 0o600)
	d, err := daemon.New(daemon.Config{VaultID: "vault-test", OpenBao: bao.Address, RoleID: res.RoleID,
		AuditPath: filepath.Join(dir, "audit.jsonl"), TunnelUIDs: []int{os.Getuid()}, SSHDir: dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: d, ConnContext: server.ConnContext, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.Serve(l) }()
	t.Cleanup(func() { _ = hs.Close() })
	return e, admin
}

// adminToken logs the FIDO2 admin in directly (no hardware key in CI).
func (e env) adminToken(admin authntest.Key) string {
	e.t.Helper()
	call := func(path string, body any) map[string]any {
		data, _ := json.Marshal(body)
		c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", e.sock)
		}}}
		resp, err := c.Post("http://hashvault"+path, "application/json", bytes.NewReader(data))
		if err != nil {
			e.t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	ch := call("/v1/auth/challenge", map[string]string{"principal": "human/admin"})
	sig := admin.Sign([]byte(ch["message"].(string)), authn.Namespace)
	out := call("/v1/auth/login", map[string]string{"id": ch["id"].(string), "principal": "human/admin", "signature": string(sig)})
	return out["token"].(string)
}

func sshKey(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	return path
}

func TestOperatorWorkflow(t *testing.T) {
	e, admin := startVault(t)

	if out := e.must("", "status"); !strings.Contains(out, `"sealed": true`) {
		t.Fatalf("status %s", out)
	}
	e.must("", "unseal", "--bundle", e.bundle, "--identity", e.identity)

	// The FIDO2 admin creates a CI-friendly operator with a software key.
	_ = os.WriteFile(e.tokenFile, []byte(e.adminToken(admin)), 0o600)
	key := sshKey(t, e.dir, "ops")
	policy := filepath.Join(e.dir, "ops.json")
	_ = os.WriteFile(policy, []byte(allowAll), 0o600)
	e.must("", "policy", "put", "ops", policy)
	if out := e.must("", "policy", "get", "ops"); !strings.Contains(out, "hv-1") {
		t.Fatalf("policy get %s", out)
	}
	e.must("", "principal", "create", "machine/ops", "--key", key+".pub", "--tag", "team=core")
	e.must("", "principal", "attach", "machine/ops", "ops")

	// From here on, the CLI signs with ssh-keygen -Y sign.
	_, _, errOut := e.run("", "login", "--principal", "machine/ops", "--key", key)
	if !strings.Contains(errOut, "logged in as machine/ops") {
		t.Fatalf("login: %s", errOut)
	}
	if out := e.must("", "principal", "get", "machine/ops"); !strings.Contains(out, `"team": "core"`) {
		t.Fatalf("principal get %s", out)
	}

	e.must("postgres://p@ss", "secret", "put", "prod/acme-api/DATABASE_URL")
	if out := e.must("", "secret", "get", "prod/acme-api/DATABASE_URL"); out != "postgres://p@ss" {
		t.Fatalf("get %q", out)
	}
	value := filepath.Join(e.dir, "tls.key")
	_ = os.WriteFile(value, []byte("-----KEY-----\n"), 0o600)
	e.must("", "secret", "put", "prod/acme-api/TLS_KEY", "--file", value)
	if out := e.must("", "secret", "list", "prod/acme-api"); out != "DATABASE_URL\nTLS_KEY\n" {
		t.Fatalf("list %q", out)
	}
	e.must("v2", "secret", "put", "prod/acme-api/DATABASE_URL")
	if out := e.must("", "secret", "get", "prod/acme-api/DATABASE_URL", "--version", "1"); out != "postgres://p@ss" {
		t.Fatalf("get v1 %q", out)
	}
	e.must("", "secret", "rewrap", "prod/acme-api/DATABASE_URL")
	e.must("", "secret", "destroy", "prod/acme-api/DATABASE_URL", "--version", "1")
	if code, _, _ := e.run("", "secret", "get", "prod/acme-api/DATABASE_URL", "--version", "1"); code == 0 {
		t.Fatal("a destroyed version was read")
	}

	dotenvFile := filepath.Join(e.dir, ".env")
	_ = os.WriteFile(dotenvFile, []byte("APP_KEY=base64:abc\nMAIL_DSN='smtp://u:p$w@mail'\nURL=${APP_URL}/x\n"), 0o600)
	out := e.must("", "import", "dotenv", dotenvFile, "--env", "prod", "--app", "legacy", "--dry-run")
	if !strings.Contains(out, "prod/legacy/URL  (references another variable") {
		t.Fatalf("dry run %s", out)
	}
	if code, _, _ := e.run("", "secret", "get", "prod/legacy/APP_KEY"); code == 0 {
		t.Fatal("a dry run stored something")
	}
	e.must("", "import", "dotenv", dotenvFile, "--env", "prod", "--app", "legacy")
	if got := e.must("", "secret", "get", "prod/legacy/MAIL_DSN"); got != "smtp://u:p$w@mail" {
		t.Fatalf("imported %q", got)
	}
	bad := filepath.Join(e.dir, "bad.env")
	_ = os.WriteFile(bad, []byte("app.name=x\nGOOD=1\n"), 0o600)
	if code, _, errOut := e.run("", "import", "dotenv", bad, "--env", "prod", "--app", "bad"); code == 0 || !strings.Contains(errOut, "app.name (line 1)") {
		t.Fatalf("invalid key: %d %s", code, errOut)
	}
	if code, _, _ := e.run("", "secret", "get", "prod/bad/GOOD"); code == 0 {
		t.Fatal("a refused import stored part of the file")
	}

	out = e.must("", "iam", "simulate", "--principal", "machine/ops", "--action", "secret:Read", "--resource", "hv:prod:secret/acme-api/X", "--context", "hv:Env=prod")
	if !strings.HasPrefix(out, "Allow:") {
		t.Fatalf("simulate %s", out)
	}
	tgt := filepath.Join(e.dir, "target.json")
	_ = os.WriteFile(tgt, []byte(`{"name":"web-01","kind":"ssh","env":"prod","config":{"agent":"web-01","recipient":"`+mustHybrid(t)+`","transport":{"type":"sudo"}}}`), 0o600)
	e.must("", "target", "put", tgt)
	if out := e.must("", "target", "list"); out != "web-01\n" {
		t.Fatalf("targets %q", out)
	}
	manifest := filepath.Join(e.dir, "hashvault.json")
	_ = os.WriteFile(manifest, []byte(`{"version":"hv-manifest-1","app":"acme-api","items":{"TLS_KEY":{"expose":"file","services":["web"]}}}`), 0o600)
	if out := e.must("", "publish", "--target", "web-01", "--manifest", manifest, "--dry-run", "--version", "TLS_KEY=1"); !strings.Contains(out, `"status": "planned"`) {
		t.Fatalf("publish dry run %s", out)
	}
	if out := e.must("", "audit", "verify"); !strings.Contains(out, `"ok": true`) {
		t.Fatalf("audit %s", out)
	}

	other := sshKey(t, e.dir, "other")
	e.must("", "principal", "create", "machine/other", "--key", other+".pub")
	e.must("", "principal", "attach", "machine/other", "ops", "--detach")
	e.must("", "principal", "disable", "machine/other")

	e.must("", "seal")
	if out := e.must("", "status"); !strings.Contains(out, `"sealed": true`) {
		t.Fatalf("after seal %s", out)
	}
	e.must("", "unseal", "--bundle", e.bundle, "--identity", e.identity)
	e.must("", "logout")
	if code, _, errOut := e.run("", "secret", "list", "prod/acme-api"); code == 0 || !strings.Contains(errOut, "not logged in") {
		t.Fatalf("after logout: %d %s", code, errOut)
	}
}

func mustHybrid(t *testing.T) string {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id.Recipient().String()
}

func TestUsageErrors(t *testing.T) {
	e := env{t: t, sock: filepath.Join(t.TempDir(), "none.sock"), tokenFile: filepath.Join(t.TempDir(), "token")}
	if code, out, _ := e.run("", "version"); code != 0 || !strings.Contains(out, "hashvault") {
		t.Fatal("version")
	}
	cases := [][]string{
		{}, {"nope"}, {"status"}, {"login"}, {"secret"}, {"secret", "get", "bad"}, {"secret", "list", "prod/acme/KEY"},
		{"secret", "destroy", "prod/acme/KEY"}, {"secret", "frob", "prod/acme/KEY"}, {"import", "csv"},
		{"import", "dotenv", "f"}, {"policy", "list"}, {"principal", "create"}, {"principal", "create", "noslash"},
		{"principal", "attach", "machine/x"}, {"principal", "frob", "machine/x"}, {"iam", "explain"},
		{"iam", "simulate", "--context", "novalue"}, {"target", "frob"}, {"audit"}, {"unseal"},
		{"publish", "--manifest", "/nonexistent"}, {"publish", "--manifest", "/dev/null", "--version", "X"},
		{"principal", "create", "machine/x", "--key", "/nonexistent"}, {"secret", "list", "prod/acme"},
	}
	for _, args := range cases {
		if code, _, _ := e.run("", args...); code == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
	if _, _, _, err := splitRef("prod/acme-api/DB", true); err != nil {
		t.Fatal(err)
	}
}
