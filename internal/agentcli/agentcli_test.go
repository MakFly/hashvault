package agentcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/MakFly/hashvault/internal/batch"
	"github.com/MakFly/hashvault/internal/hostagent"
	"github.com/MakFly/hashvault/internal/target"
)

type noConsumers struct{}

func (noConsumers) Run(context.Context, batch.Batch) error { return nil }

type fixture struct {
	dir      string
	cfgPath  string
	priv     ed25519.PrivateKey
	execArgs []string
	execEnv  []string
}

// fakeCreds is a stand-in systemd-creds that stores its input as is. The
// name check in loadConfig only looks at the program name.
func fakeCreds(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "bin", "systemd-creds")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec cat\n"), 0o700); err != nil { // #nosec G306 -- test script
		t.Fatal(err)
	}
	return path
}

func (f *fixture) io(stdin string) (IO, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	return IO{
		Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut,
		Environ: []string{"PATH=/usr/bin", "TOKEN=from-the-shell"},
		Exec: func(argv0 string, argv []string, env []string) error {
			f.execArgs, f.execEnv = argv, env
			return nil
		},
		Agent: func(c *hostagent.Config) {
			c.AllowNonTmpfs = true
			c.Chown = func(string, int, int) error { return nil }
			c.Consumers = noConsumers{}
		},
	}, &out, &errOut
}

func setup(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{dir: dir, cfgPath: filepath.Join(dir, "etc", "config.json"), priv: priv}
	io, out, errOut := f.io("")
	code := Main([]string{"init", "--config", f.cfgPath, "--agent", "web-01", "--trusted-signer", base64.StdEncoding.EncodeToString(pub)}, io)
	if code != 0 {
		t.Fatalf("init: %d %s", code, errOut)
	}
	if !strings.HasPrefix(out.String(), "age1pq1") {
		t.Fatalf("init must print the hybrid recipient, got %q", out.String())
	}
	// Point the generated config at test directories and the fake sealer.
	var c Config
	data, _ := os.ReadFile(f.cfgPath)
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	c.CredstoreDir = filepath.Join(dir, "credstore")
	c.RuntimeDir = filepath.Join(dir, "run")
	c.StateDir = filepath.Join(dir, "state")
	c.SealerCommand = []string{fakeCreds(t, dir)}
	data, _ = json.Marshal(c)
	if err := os.WriteFile(f.cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) recipient(t *testing.T) age.Recipient {
	t.Helper()
	io, out, _ := f.io("")
	if code := Main([]string{"recipient", "--config", f.cfgPath}, io); code != 0 {
		t.Fatal("recipient failed")
	}
	r, err := age.ParseHybridRecipient(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *fixture) batch(t *testing.T, value string) []byte {
	t.Helper()
	now := time.Now()
	b := batch.Batch{
		Version: batch.Version, ID: batch.NewID(), Agent: "web-01", Target: "ssh-web-01", Kind: target.SSH,
		App: "acme-api", Env: "prod", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		Items: []batch.Item{{Key: "TOKEN", Version: 1, Resource: "hv:prod:secret/acme-api/TOKEN", Value: []byte(value),
			Spec: target.ItemSpec{Expose: target.Env, Target: "token", Services: []string{"web"}, UID: "0", GID: "0", Mode: "0400"}}},
	}
	data, err := batch.Seal(b, f.priv, f.recipient(t))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func receipt(t *testing.T, out *bytes.Buffer) hostagent.Receipt {
	t.Helper()
	var r hostagent.Receipt
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("receipt %q: %v", out.String(), err)
	}
	return r
}

func TestReceiveMaterializeExec(t *testing.T) {
	f := setup(t)
	sealed := f.batch(t, "s3cr3t")

	io, out, _ := f.io(string(sealed))
	if code := Main([]string{"receive", "--config", f.cfgPath}, io); code != 0 {
		t.Fatalf("receive exit %d: %s", code, out)
	}
	if r := receipt(t, out); r.Status != hostagent.Applied || r.Items["TOKEN"] != 1 || strings.Contains(out.String(), "s3cr3t") {
		t.Fatalf("receipt %+v (%s)", r, out)
	}
	io, out, _ = f.io(string(sealed))
	if code := Main([]string{"receive", "--config", f.cfgPath}, io); code != 1 || receipt(t, out).Status != hostagent.Refused {
		t.Fatalf("a replayed batch must be refused: %d %s", code, out)
	}
	io, out, _ = f.io("garbage")
	if code := Main([]string{"receive", "--config", f.cfgPath}, io); code != 1 || receipt(t, out).Status != hostagent.Refused {
		t.Fatalf("garbage must be refused: %d %s", code, out)
	}

	// Reboot: tmpfs gone, materialize rebuilds it from the store.
	if err := os.RemoveAll(filepath.Join(f.dir, "run")); err != nil {
		t.Fatal(err)
	}
	io, _, errOut := f.io("")
	if code := Main([]string{"materialize", "--config", f.cfgPath}, io); code != 0 {
		t.Fatalf("materialize: %s", errOut)
	}
	if got, _ := os.ReadFile(filepath.Join(f.dir, "run", "acme-api", "web", "token")); string(got) != "s3cr3t" {
		t.Fatalf("materialised %q", got)
	}
	io, _, errOut = f.io("")
	if code := Main([]string{"materialize", "--config", f.cfgPath, "--app", "acme-api"}, io); code != 0 {
		t.Fatalf("materialize --app: %s", errOut)
	}

	io, _, errOut = f.io("")
	if code := Main([]string{"exec", "--config", f.cfgPath, "--app", "acme-api", "--service", "web", "--", "/usr/bin/env", "-0"}, io); code != 0 {
		t.Fatalf("exec: %s", errOut)
	}
	if !slices.Equal(f.execArgs, []string{"/usr/bin/env", "-0"}) {
		t.Fatalf("argv %v", f.execArgs)
	}
	if !slices.Contains(f.execEnv, "TOKEN=s3cr3t") || slices.Contains(f.execEnv, "TOKEN=from-the-shell") || !slices.Contains(f.execEnv, "PATH=/usr/bin") {
		t.Fatalf("env %v", f.execEnv)
	}
	io, _, _ = f.io("")
	if code := Main([]string{"exec", "--config", f.cfgPath, "--app", "acme-api", "--service", "web", "--", "env"}, io); code == 0 {
		t.Fatal("exec of a relative program accepted")
	}
	if code := Main([]string{"exec", "--config", f.cfgPath, "--app", "acme-api"}, io); code == 0 {
		t.Fatal("exec without a command accepted")
	}
}

func TestConfigurationIsCheckedBeforeAnything(t *testing.T) {
	f := setup(t)
	io, _, errOut := f.io("")
	if code := Main([]string{"init", "--config", f.cfgPath, "--agent", "x", "--trusted-signer", "AAAA"}, io); code == 0 {
		t.Fatal("init over an enrolled identity accepted")
	}
	if code := Main([]string{"init", "--config", filepath.Join(f.dir, "new", "c.json"), "--agent", "x", "--trusted-signer", "nope"}, io); code == 0 {
		t.Fatal("init with an invalid signer accepted")
	}

	data, _ := os.ReadFile(f.cfgPath)
	sealed := string(f.batch(t, "v")) // before the config is broken below
	write := func(content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(f.cfgPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f.cfgPath, mode); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]func(){
		"group writable config": func() { write(string(data), 0o620) },
		"unknown field":         func() { write(strings.Replace(string(data), "{", `{"extra":1,`, 1), 0o600) },
		"not systemd-creds": func() {
			write(strings.Replace(string(data), filepath.Join(f.dir, "bin", "systemd-creds"), "/bin/cat", 1), 0o600)
		},
		"no agent name": func() { write(strings.Replace(string(data), `"agent":"web-01"`, `"agent":""`, 1), 0o600) },
		"bad signer":    func() { write(strings.Replace(string(data), `"trusted_signer":"`, `"trusted_signer":"x`, 1), 0o600) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			mutate()
			defer write(string(data), 0o600)
			io, out, _ := f.io(sealed)
			if code := Main([]string{"receive", "--config", f.cfgPath}, io); code != 1 || receipt(t, out).Status != hostagent.Refused {
				t.Fatalf("exit %d, %s", code, out)
			}
		})
	}
	t.Run("identity readable by group", func(t *testing.T) {
		var c Config
		_ = json.Unmarshal(data, &c)
		if err := os.Chmod(c.IdentityFile, 0o640); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(c.IdentityFile, 0o600)
		io, _, _ := f.io("")
		if code := Main([]string{"recipient", "--config", f.cfgPath}, io); code == 0 {
			t.Fatal("a group-readable identity was used")
		}
	})
	_ = errOut
}

func TestMiscCommands(t *testing.T) {
	f := &fixture{}
	io, out, _ := f.io("")
	if Main([]string{"version"}, io) != 0 || !strings.Contains(out.String(), "hashvault-agent") {
		t.Fatal("version")
	}
	if Main(nil, io) != 2 || Main([]string{"nope"}, io) != 1 {
		t.Fatal("usage errors")
	}
	if Main([]string{"materialize", "--config", "/nonexistent"}, io) != 1 || Main([]string{"recipient", "--bad-flag"}, io) != 1 {
		t.Fatal("bad config or flag must fail")
	}
	if _, err := readLimited(strings.NewReader("abc"), 2); err == nil {
		t.Fatal("input over the limit accepted")
	}
}
