package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MakFly/hashvault/internal/agentcli"
	"github.com/MakFly/hashvault/internal/batch"
	"github.com/MakFly/hashvault/internal/hostagent"
	"github.com/MakFly/hashvault/internal/target"
)

var ctx = context.Background()

// recordingConsumers stands in for compose restarts and reload commands.
type recordingConsumers struct {
	mu   sync.Mutex
	seen []batch.Consumers
	fail bool
}

func (r *recordingConsumers) Run(_ context.Context, b batch.Batch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, b.Consumers)
	if r.fail {
		return errors.New("consumer did not come back")
	}
	return nil
}

// agentTransport runs the real hashvault-agent CLI in process, as
// `sudo -n hashvault-agent receive` would on the host.
type agentTransport struct {
	cfgPath   string
	consumers *recordingConsumers
}

func (t agentTransport) Deliver(_ context.Context, sealed []byte) (hostagent.Receipt, error) {
	var out, errOut bytes.Buffer
	agentcli.Main([]string{"receive", "--config", t.cfgPath}, agentcli.IO{
		Stdin: bytes.NewReader(sealed), Stdout: &out, Stderr: &errOut,
		Agent: func(c *hostagent.Config) {
			c.AllowNonTmpfs = true
			c.Chown = func(string, int, int) error { return nil }
			c.Consumers = t.consumers
		},
	})
	var r hostagent.Receipt
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		return r, errors.New(errOut.String())
	}
	return r, nil
}

func (agentTransport) Describe() string { return "in-process agent" }

type fixture struct {
	dir       string
	recipient string
	priv      ed25519.PrivateKey
	transport agentTransport
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "etc", "config.json")
	var out, errOut bytes.Buffer
	if agentcli.Main([]string{"init", "--config", cfgPath, "--agent", "web-01", "--trusted-signer", base64.StdEncoding.EncodeToString(pub)},
		agentcli.IO{Stdout: &out, Stderr: &errOut}) != 0 {
		t.Fatal(errOut.String())
	}
	creds := filepath.Join(dir, "bin", "systemd-creds")
	if err := os.MkdirAll(filepath.Dir(creds), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(creds, []byte("#!/bin/sh\nexec cat\n"), 0o700); err != nil { // #nosec G306 -- test script
		t.Fatal(err)
	}
	var c agentcli.Config
	data, _ := os.ReadFile(cfgPath)
	_ = json.Unmarshal(data, &c)
	c.CredstoreDir, c.RuntimeDir, c.StateDir = filepath.Join(dir, "credstore"), filepath.Join(dir, "run"), filepath.Join(dir, "state")
	c.SealerCommand = []string{creds}
	data, _ = json.Marshal(c)
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return &fixture{
		dir: dir, recipient: strings.TrimSpace(out.String()), priv: priv,
		transport: agentTransport{cfgPath: cfgPath, consumers: &recordingConsumers{}},
	}
}

func (f *fixture) adapter(t *testing.T, kind target.Kind, mutate ...func(*Config)) *Adapter {
	t.Helper()
	cfg := Config{Name: "host-web-01", Kind: kind, Agent: "web-01", Recipient: f.recipient, Signer: f.priv, Transport: f.transport}
	for _, m := range mutate {
		m(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func desired(version uint64, value string, services ...string) target.Desired {
	return target.Desired{App: "acme-api", Env: "prod", Items: []target.Item{{
		Key: "DATABASE_URL", Version: version, Resource: "hv:prod:secret/acme-api/DATABASE_URL", Value: []byte(value),
		Spec: target.ItemSpec{Expose: target.Env, Target: "database_url", Services: services, UID: "0", GID: "0", Mode: "0400"},
	}}}
}

func (f *fixture) materialised(t *testing.T, svc, file string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, "run", "acme-api", svc, file))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDockerPublicationEndToEnd(t *testing.T) {
	f := newFixture(t)
	a := f.adapter(t, target.Docker, func(c *Config) { c.ComposeProject = "acme" })
	plan, err := a.Plan(ctx, desired(1, "v1", "worker", "api"))
	if err != nil || len(plan.Create) != 1 || plan.Create[0] != "acme-api.DATABASE_URL@v1" || len(plan.Changes) != 2 {
		t.Fatalf("plan %+v %v", plan, err)
	}
	r, err := a.Apply(ctx, desired(1, "v1", "worker", "api"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(ctx, r); err != nil {
		t.Fatal(err)
	}
	if f.materialised(t, "api", "database_url") != "v1" || f.materialised(t, "worker", ".env") != "DATABASE_URL='v1'\n" {
		t.Fatal("values not materialised by the agent")
	}
	got := f.transport.consumers.seen[0]
	if strings.Join(got.Docker, ",") != "api,worker" || got.ComposeProject != "acme" || len(got.Reload) != 0 {
		t.Fatalf("consumers %+v", got)
	}
}

func TestSSHPublicationRotationAndRollback(t *testing.T) {
	f := newFixture(t)
	reload := [][]string{{"/usr/bin/systemctl", "reload", "php8.4-fpm"}}
	a := f.adapter(t, target.SSH, func(c *Config) { c.Reload = map[string][][]string{"acme-api": reload} })
	if _, err := a.Apply(ctx, desired(1, "v1", "web")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(ctx, desired(2, "v2", "web")); err != nil {
		t.Fatal(err)
	}
	if f.materialised(t, "web", "database_url") != "v2" {
		t.Fatal("rotation not applied")
	}
	if got := f.transport.consumers.seen[1].Reload; len(got) != 1 || got[0][2] != "php8.4-fpm" {
		t.Fatalf("reload commands %v", got)
	}
	// Going back to v1 needs the rollback flag, signed in the batch.
	if _, err := a.Apply(ctx, desired(1, "v1", "web")); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("an unflagged downgrade must be refused: %v", err)
	}
	back := desired(1, "v1", "web")
	back.Rollback = true
	if _, err := a.Apply(ctx, back); err != nil {
		t.Fatal(err)
	}
	if f.materialised(t, "web", "database_url") != "v1" {
		t.Fatal("rollback not applied")
	}
	if err := a.Rollback(ctx, target.Receipt{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := a.Inventory(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("inventory: %v", err)
	}
}

func TestAFailedRestartIsReportedAsAVerifyError(t *testing.T) {
	f := newFixture(t)
	a := f.adapter(t, target.SSH)
	if _, err := a.Apply(ctx, desired(1, "v1", "web")); err != nil {
		t.Fatal(err)
	}
	f.transport.consumers.fail = true
	_, err := a.Apply(ctx, desired(2, "v2", "web"))
	if !errors.Is(err, target.ErrVerify) || !strings.Contains(err.Error(), "did not come back") {
		t.Fatalf("got %v", err)
	}
	if f.materialised(t, "web", "database_url") != "v1" {
		t.Fatal("the agent did not restore v1")
	}
}

func TestABatchForAnotherAgentIsRefused(t *testing.T) {
	f := newFixture(t)
	other := newFixture(t)
	// The adapter seals for this agent, but delivers to the other one.
	a := f.adapter(t, target.SSH, func(c *Config) { c.Transport = other.transport })
	if _, err := a.Apply(ctx, desired(1, "v", "web")); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("got %v", err)
	}
}

func TestNewRefusesUnsafeConfigurations(t *testing.T) {
	f := newFixture(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	base := Config{Name: "n", Kind: target.SSH, Agent: "web-01", Recipient: f.recipient, Signer: priv, Transport: f.transport}
	cases := map[string]func(*Config){
		"swarm kind":        func(c *Config) { c.Kind = target.Swarm },
		"no transport":      func(c *Config) { c.Transport = nil },
		"no signer":         func(c *Config) { c.Signer = nil },
		"x25519 recipient":  func(c *Config) { c.Recipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p" },
		"long validity":     func(c *Config) { c.Validity = time.Hour },
		"relative reload":   func(c *Config) { c.Reload = map[string][][]string{"a": {{"systemctl", "reload", "x"}}} },
		"reload on docker":  func(c *Config) { c.Kind = target.Docker; c.Reload = map[string][][]string{"a": {{"/bin/true"}}} },
		"empty reload argv": func(c *Config) { c.Reload = map[string][][]string{"a": {{}}} },
		"no agent name":     func(c *Config) { c.Agent = "" },
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			c := base
			m(&c)
			if _, err := New(c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	a, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Check(ctx)
	if err != nil || p.Details["agent"] != "web-01" || a.Kind() != target.SSH {
		t.Fatalf("check %+v %v", p, err)
	}
	if _, err := a.Plan(ctx, target.Desired{App: "Bad"}); !errors.Is(err, target.ErrContract) {
		t.Fatalf("plan: %v", err)
	}
	if _, err := a.Apply(ctx, target.Desired{App: "Bad"}); !errors.Is(err, target.ErrContract) {
		t.Fatalf("apply: %v", err)
	}
}

func TestLocalSudoTransport(t *testing.T) {
	ok := LocalSudo{Command: []string{"sh", "-c", `cat >/dev/null; echo '{"batch_id":"x","status":"applied"}'`}}
	r, err := ok.Deliver(ctx, []byte("sealed"))
	if err != nil || r.Status != hostagent.Applied || ok.Describe() != "local sudo" {
		t.Fatalf("%+v %v", r, err)
	}
	refused := LocalSudo{Command: []string{"sh", "-c", `echo '{"status":"refused","error":"nope"}'; exit 1`}}
	if r, err := refused.Deliver(ctx, nil); err != nil || r.Status != hostagent.Refused {
		t.Fatalf("a refusal with a receipt is an answer, not a transport error: %+v %v", r, err)
	}
	broken := LocalSudo{Command: []string{"sh", "-c", "echo 'sudo: a password is required' >&2; exit 1"}}
	if _, err := broken.Deliver(ctx, nil); err == nil || !strings.Contains(err.Error(), "password is required") {
		t.Fatalf("got %v", err)
	}
	slow := LocalSudo{Command: []string{"sleep", "5"}, Timeout: 100 * time.Millisecond}
	if _, err := slow.Deliver(ctx, nil); err == nil {
		t.Fatal("a hung agent was not timed out")
	}
	huge := LocalSudo{Command: []string{"sh", "-c", "head -c 70000 /dev/zero"}}
	if _, err := huge.Deliver(ctx, nil); err == nil {
		t.Fatal("an oversized receipt was accepted")
	}
	if (LocalSudo{}).Describe() == "" {
		t.Fatal("describe")
	}
}

func TestSSHArgumentsAreLockedDown(t *testing.T) {
	s := SSH{Host: "web-01.example.com", User: "hashvault", KeyFile: "/k", KnownHostsFile: "/kh"}
	argv, err := s.argv()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{"-F /dev/null", "StrictHostKeyChecking=yes", "UserKnownHostsFile=/kh", "BatchMode=yes", "IdentitiesOnly=yes", "ForwardAgent=no", "-p 22", "-- web-01.example.com"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	if argv[len(argv)-1] != "web-01.example.com" {
		t.Fatal("no remote command may follow the host: the server decides what runs")
	}
	for name, bad := range map[string]SSH{
		"option as host": {Host: "-oProxyCommand=x", User: "u", KeyFile: "/k", KnownHostsFile: "/kh"},
		"option as user": {Host: "h", User: "-x", KeyFile: "/k", KnownHostsFile: "/kh"},
		"no known_hosts": {Host: "h", User: "u", KeyFile: "/k"},
		"no key":         {Host: "h", User: "u", KnownHostsFile: "/kh"},
	} {
		if _, err := bad.argv(); err == nil {
			t.Errorf("%s accepted", name)
		}
		if _, err := bad.Deliver(ctx, nil); err == nil {
			t.Errorf("%s delivered", name)
		}
	}
	if s.Describe() != "ssh hashvault@web-01.example.com" {
		t.Fatal(s.Describe())
	}
}
