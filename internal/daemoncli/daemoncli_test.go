package daemoncli

import (
	"bytes"
	"context"
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

	"github.com/MakFly/hashvault/internal/agekeys"
	"github.com/MakFly/hashvault/internal/authn"
	"github.com/MakFly/hashvault/internal/authn/authntest"
	"github.com/MakFly/hashvault/internal/daemon"
	"github.com/MakFly/hashvault/internal/openbao/baotest"
)

func ioFor(ctx context.Context) (IO, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	return IO{Stdout: &out, Stderr: &errOut, Prompter: agekeys.Prompter{Out: io.Discard}, Ctx: ctx,
		Harden: func(bool, io.Writer) error { return nil }}, &out, &errOut
}

func TestInitThenServe(t *testing.T) {
	bao := baotest.StartUninitialized(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hashvaultd.json")
	sock := filepath.Join(dir, "run", "api.sock")
	cfg := daemon.Config{VaultID: "vault-test", Listen: sock, OpenBao: bao.Address, AuditPath: filepath.Join(dir, "audit.jsonl"), TunnelUIDs: []int{os.Getuid()}}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	admin := authntest.SK(authn.FlagUserPresent)
	keyFile := filepath.Join(dir, "admin.pub")
	_ = os.WriteFile(keyFile, []byte(admin.Line+"\n"), 0o600)
	id, _ := age.GenerateX25519Identity()
	bundle := filepath.Join(dir, "bundle.age")

	args := []string{"init", "--config", cfgPath, "--admin", "human/admin", "--admin-key", keyFile, "--recipient", id.Recipient().String(), "--bundle-out", bundle}
	io1, out, errOut := ioFor(context.Background())
	if code := Main(args, io1); code != 0 {
		t.Fatalf("init: %s", errOut)
	}
	if !strings.Contains(out.String(), "batch signing key:") {
		t.Fatalf("init output %q", out)
	}
	st, _ := os.Stat(bundle)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode %o", st.Mode().Perm())
	}
	got, err := LoadConfig(cfgPath)
	if err != nil || got.RoleID == "" {
		t.Fatalf("role id not recorded: %+v %v", got, err)
	}
	io2, _, _ := ioFor(context.Background())
	if code := Main(args, io2); code == 0 {
		t.Fatal("a second init over the same bundle path")
	}
	_ = os.Rename(bundle, bundle+".kept")
	if code := Main(args, io2); code == 0 {
		t.Fatal("a second init on a bootstrapped config")
	}

	ctx, cancel := context.WithCancel(context.Background())
	io3, _, serveErr := ioFor(ctx)
	done := make(chan int, 1)
	go func() { done <- Main([]string{"serve", "--config", cfgPath}, io3) }()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	var resp *http.Response
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err = client.Get("http://hashvault/v1/sys/status")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve did not come up: %v %s", err, serveErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	var status map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&status)
	resp.Body.Close()
	if status["sealed"] != true {
		t.Fatalf("status %v", status)
	}
	sockStat, _ := os.Stat(sock)
	if sockStat.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %o", sockStat.Mode().Perm())
	}
	raw, _ := os.ReadFile(bundle + ".kept")
	b, err := daemon.OpenBundle(raw, id)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(b)
	resp, err = client.Post("http://hashvault/v1/sys/unseal", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("unseal through serve: %v %v", resp, err)
	}
	resp.Body.Close()
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exited %d: %s", code, serveErr)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not stop on cancel")
	}
	if st, _ := bao.Client.SealStatus(context.Background()); !st.Sealed {
		t.Fatal("stopping hashvaultd must seal OpenBao")
	}
}

func TestUsageAndConfigErrors(t *testing.T) {
	io1, out, _ := ioFor(context.Background())
	if Main([]string{"version"}, io1) != 0 || !strings.Contains(out.String(), "hashvaultd") {
		t.Fatal("version")
	}
	if Main(nil, io1) != 2 || Main([]string{"nope"}, io1) != 1 {
		t.Fatal("usage")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"vault_id":"x","extra":1}`), 0o600)
	for _, args := range [][]string{
		{"serve", "--config", bad},
		{"serve", "--config", filepath.Join(dir, "missing.json")},
		{"init", "--config", bad},
		{"init", "--config", bad, "--admin", "human/a", "--admin-key", "k", "--recipient", "r", "--bundle-out", filepath.Join(dir, "b")},
		{"serve", "--bogus"},
	} {
		if Main(args, io1) == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
	noRole := filepath.Join(dir, "norole.json")
	_ = os.WriteFile(noRole, []byte(`{"vault_id":"x"}`), 0o600)
	if Main([]string{"serve", "--config", noRole}, io1) == 0 {
		t.Fatal("serve without role id")
	}
	var warn bytes.Buffer
	if err := harden(true, &warn); err != nil {
		t.Fatalf("harden with mlock allowed to fail: %v", err)
	}
}
