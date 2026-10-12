package hostagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/MakFly/hashvault/internal/batch"
	"github.com/MakFly/hashvault/internal/target"
)

var ctx = context.Background()

// testSealer mimics systemd-creds: authenticated encryption with the
// credential name bound in, so a renamed file does not open.
type testSealer struct{ key [32]byte }

func (s testSealer) Seal(_ context.Context, name string, value []byte) ([]byte, error) {
	aead, _ := chacha20poly1305.NewX(s.key[:])
	nonce := make([]byte, aead.NonceSize())
	sum := sha256.Sum256(append([]byte(name), value...))
	copy(nonce, sum[:]) // deterministic is fine for a test double
	return aead.Seal(nonce, nonce, value, []byte(name)), nil
}

func (s testSealer) Open(_ context.Context, name string, sealed []byte) ([]byte, error) {
	aead, _ := chacha20poly1305.NewX(s.key[:])
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("short")
	}
	return aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte(name))
}

type fakeConsumers struct {
	mu    sync.Mutex
	runs  []string
	fail  func(b batch.Batch, call int) error
	calls int
}

func (f *fakeConsumers) Run(_ context.Context, b batch.Batch) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.runs = append(f.runs, b.ID)
	if f.fail != nil {
		return f.fail(b, f.calls)
	}
	return nil
}

type chownCall struct {
	path     string
	uid, gid int
}

type env struct {
	agent     *Agent
	consumers *fakeConsumers
	cfg       Config
	chowns    *[]chownCall
}

func newEnv(t *testing.T) env {
	t.Helper()
	root := t.TempDir()
	var calls []chownCall
	cons := &fakeConsumers{}
	cfg := Config{
		CredstoreDir:  filepath.Join(root, "credstore.encrypted"),
		RuntimeDir:    filepath.Join(root, "run"),
		StateDir:      filepath.Join(root, "state"),
		AllowNonTmpfs: true,
		Sealer:        testSealer{key: [32]byte{1, 2, 3}},
		Consumers:     cons,
		Chown: func(p string, uid, gid int) error {
			calls = append(calls, chownCall{filepath.Base(p), uid, gid})
			return nil
		},
		Now: func() time.Time { return time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC) },
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return env{agent: a, consumers: cons, cfg: cfg, chowns: &calls}
}

func item(key string, version uint64, value string, expose target.Exposure, services ...string) batch.Item {
	return batch.Item{
		Key: key, Version: version, Resource: "hv:prod:secret/acme-api/" + key, Value: []byte(value),
		Spec: target.ItemSpec{Expose: expose, Target: strings.ToLower(key), Services: services, UID: "33", GID: "33", Mode: "0400"},
	}
}

func mkBatch(items ...batch.Item) batch.Batch {
	return batch.Batch{
		Version: batch.Version, ID: batch.NewID(), Agent: "web-01", Target: "ssh-web-01", Kind: target.SSH,
		App: "acme-api", Env: "prod", Items: items,
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestApplySealsMaterialisesAndRestarts(t *testing.T) {
	e := newEnv(t)
	b := mkBatch(
		item("DATABASE_URL", 1, "postgres://p@ss$word@db/acme", target.Env, "web", "worker"),
		item("TLS_KEY", 1, "-----BEGIN KEY-----\nabc\n", target.File, "web"),
	)
	r := e.agent.Apply(ctx, b)
	if r.Status != Applied || r.Error != "" {
		t.Fatalf("receipt %+v", r)
	}
	// Sealed at rest, never in clear.
	sealed := read(t, filepath.Join(e.cfg.CredstoreDir, "acme-api.DATABASE_URL"))
	if strings.Contains(sealed, "p@ss") {
		t.Fatal("credential store holds the plaintext")
	}
	if mode(t, filepath.Join(e.cfg.CredstoreDir, "acme-api.DATABASE_URL")) != 0o600 {
		t.Fatal("credential file must be 0600")
	}
	// Materialised per service, with the declared mode and owner.
	web := filepath.Join(e.cfg.RuntimeDir, "acme-api", "web")
	if read(t, filepath.Join(web, "database_url")) != "postgres://p@ss$word@db/acme" {
		t.Fatal("web/database_url")
	}
	if read(t, filepath.Join(web, "tls_key")) != "-----BEGIN KEY-----\nabc\n" {
		t.Fatal("web/tls_key")
	}
	if mode(t, filepath.Join(web, "tls_key")) != 0o400 || mode(t, filepath.Join(web, ".env")) != 0o400 {
		t.Fatal("materialised files must be 0400")
	}
	// The .env holds env items only, single-quoted so "$word" is not expanded.
	if got := read(t, filepath.Join(web, ".env")); got != "DATABASE_URL='postgres://p@ss$word@db/acme'\n" {
		t.Fatalf(".env = %q", got)
	}
	worker := filepath.Join(e.cfg.RuntimeDir, "acme-api", "worker")
	if _, err := os.Stat(filepath.Join(worker, "tls_key")); !os.IsNotExist(err) {
		t.Fatal("worker must not receive a key it does not consume")
	}
	if len(*e.chowns) == 0 || (*e.chowns)[0].uid != 33 {
		t.Fatalf("chown calls %+v", *e.chowns)
	}
	if len(e.consumers.runs) != 1 {
		t.Fatalf("consumers ran %d times", len(e.consumers.runs))
	}
	if again := e.agent.Apply(ctx, b); again.Status != Refused {
		t.Fatalf("a replayed batch must be refused, got %+v", again)
	}
}

func TestRotationKeepsThePreviousSealedValue(t *testing.T) {
	e := newEnv(t)
	if r := e.agent.Apply(ctx, mkBatch(item("TOKEN", 1, "one", target.File, "web"))); r.Status != Applied {
		t.Fatal(r)
	}
	if r := e.agent.Apply(ctx, mkBatch(item("TOKEN", 2, "two", target.File, "web"))); r.Status != Applied {
		t.Fatal(r)
	}
	if got := read(t, filepath.Join(e.cfg.RuntimeDir, "acme-api", "web", "token")); got != "two" {
		t.Fatalf("got %q", got)
	}
	prev, err := e.cfg.Sealer.Open(ctx, "acme-api.TOKEN", []byte(read(t, filepath.Join(e.cfg.CredstoreDir, "acme-api.TOKEN.prev"))))
	if err != nil || string(prev) != "one" {
		t.Fatalf("prev %q %v", prev, err)
	}
	if r := e.agent.Apply(ctx, mkBatch(item("TOKEN", 1, "one", target.File, "web"))); r.Status != Refused {
		t.Fatalf("an unsigned downgrade must be refused: %+v", r)
	}
	down := mkBatch(item("TOKEN", 1, "one", target.File, "web"))
	down.Rollback = true
	if r := e.agent.Apply(ctx, down); r.Status != Applied {
		t.Fatalf("a signed rollback must apply: %+v", r)
	}
}

func TestAFailedRestartPutsThePreviousValuesBack(t *testing.T) {
	e := newEnv(t)
	if r := e.agent.Apply(ctx, mkBatch(item("TOKEN", 1, "good", target.Env, "web"))); r.Status != Applied {
		t.Fatal(r)
	}
	e.consumers.fail = func(_ batch.Batch, call int) error {
		if call == 2 {
			return errors.New("service did not come back")
		}
		return nil
	}
	bad := mkBatch(item("TOKEN", 2, "bad", target.Env, "web"))
	r := e.agent.Apply(ctx, bad)
	if r.Status != RolledBack || !strings.Contains(r.Error, "did not come back") {
		t.Fatalf("receipt %+v", r)
	}
	web := filepath.Join(e.cfg.RuntimeDir, "acme-api", "web")
	if got := read(t, filepath.Join(web, "token")); got != "good" {
		t.Fatalf("after rollback token=%q", got)
	}
	if got := read(t, filepath.Join(web, ".env")); got != "TOKEN='good'\n" {
		t.Fatalf("after rollback .env=%q", got)
	}
	if e.consumers.calls != 3 {
		t.Fatalf("consumers must restart again after the restore, ran %d times", e.consumers.calls)
	}
	// Not recorded: the same batch can be retried once the cause is fixed.
	e.consumers.fail = nil
	if r := e.agent.Apply(ctx, bad); r.Status != Applied {
		t.Fatalf("retry: %+v", r)
	}
}

func TestAFailedFirstPublicationLeavesNothing(t *testing.T) {
	e := newEnv(t)
	e.consumers.fail = func(batch.Batch, int) error { return errors.New("boom") }
	r := e.agent.Apply(ctx, mkBatch(item("TOKEN", 1, "v", target.File, "web")))
	if r.Status != RolledBack {
		t.Fatalf("receipt %+v", r)
	}
	if _, err := os.Stat(filepath.Join(e.cfg.CredstoreDir, "acme-api.TOKEN")); !os.IsNotExist(err) {
		t.Fatal("a failed first publication left a credential")
	}
	if _, err := os.Stat(filepath.Join(e.cfg.RuntimeDir, "acme-api", "web")); !os.IsNotExist(err) {
		t.Fatal("a failed first publication left a materialised directory")
	}
}

func TestAValueADotenvCannotCarryIsRefusedAndRolledBack(t *testing.T) {
	e := newEnv(t)
	for _, v := range []string{"it's", "two\nlines", "nul\x00"} {
		r := e.agent.Apply(ctx, mkBatch(item("PASSWORD", 1, v, target.Env, "web")))
		if r.Status != RolledBack || !strings.Contains(r.Error, ErrDotenv.Error()) {
			t.Fatalf("%q: receipt %+v", v, r)
		}
	}
	// The same value exposed as a file is fine.
	if r := e.agent.Apply(ctx, mkBatch(item("PASSWORD", 1, "it's", target.File, "web"))); r.Status != Applied {
		t.Fatalf("file exposure: %+v", r)
	}
}

func TestBootMaterialisationNeedsOnlyTheStore(t *testing.T) {
	e := newEnv(t)
	if r := e.agent.Apply(ctx, mkBatch(item("TOKEN", 1, "v1", target.File, "web"))); r.Status != Applied {
		t.Fatal(r)
	}
	other := mkBatch(item("KEY", 1, "k", target.Env, "api"))
	other.App = "billing"
	other.Items[0].Resource = "hv:prod:secret/billing/KEY"
	if r := e.agent.Apply(ctx, other); r.Status != Applied {
		t.Fatal(r)
	}
	// Reboot: tmpfs is empty.
	if err := os.RemoveAll(e.cfg.RuntimeDir); err != nil {
		t.Fatal(err)
	}
	if err := e.agent.MaterializeAll(ctx); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(e.cfg.RuntimeDir, "acme-api", "web", "token")) != "v1" || read(t, filepath.Join(e.cfg.RuntimeDir, "billing", "api", "key")) != "k" {
		t.Fatal("boot materialisation incomplete")
	}
	// A renamed sealed file does not open under another credential name.
	src := filepath.Join(e.cfg.CredstoreDir, "billing.KEY")
	if err := os.Rename(src, filepath.Join(e.cfg.CredstoreDir, "acme-api.TOKEN")); err != nil {
		t.Fatal(err)
	}
	if err := e.agent.Materialize(ctx, "acme-api"); err == nil {
		t.Fatal("a credential renamed to another name opened")
	}
}

func TestMovingAKeyToAnotherServicePrunesTheOldCopy(t *testing.T) {
	e := newEnv(t)
	if r := e.agent.Apply(ctx, mkBatch(item("TOKEN", 1, "v", target.File, "web"))); r.Status != Applied {
		t.Fatal(r)
	}
	if r := e.agent.Apply(ctx, mkBatch(item("TOKEN", 2, "v2", target.File, "worker"))); r.Status != Applied {
		t.Fatal(r)
	}
	if _, err := os.Stat(filepath.Join(e.cfg.RuntimeDir, "acme-api", "web")); !os.IsNotExist(err) {
		t.Fatal("the web copy must be removed once web no longer consumes the key")
	}
	if read(t, filepath.Join(e.cfg.RuntimeDir, "acme-api", "worker", "token")) != "v2" {
		t.Fatal("worker copy")
	}
}

func TestEnvForExec(t *testing.T) {
	e := newEnv(t)
	b := mkBatch(item("A_KEY", 1, "a", target.Env, "web"), item("FILE_ONLY", 1, "f", target.File, "web"))
	if r := e.agent.Apply(ctx, b); r.Status != Applied {
		t.Fatal(r)
	}
	pairs, err := e.agent.Env(ctx, "acme-api", "web")
	if err != nil || len(pairs) != 1 || string(pairs[0]) != "A_KEY=a" {
		t.Fatalf("pairs %q %v", pairs, err)
	}
	if _, err := e.agent.Env(ctx, "acme-api", "nothing"); err == nil {
		t.Fatal("a service without env items must be an error")
	}
}

func TestRefusals(t *testing.T) {
	e := newEnv(t)
	mixed := mkBatch(item("A", 1, "a", target.Env, "web"), item("B", 1, "b", target.Env, "web"))
	mixed.Items[1].Spec.UID = "0"
	if r := e.agent.Apply(ctx, mixed); r.Status != Refused {
		t.Fatalf("env items with two owners in one .env: %+v", r)
	}
	r := e.agent.Receive(ctx, []byte("x"), func([]byte) (batch.Batch, error) { return batch.Batch{}, batch.ErrInvalid })
	if r.Status != Refused || r.Error == "" {
		t.Fatalf("an unopenable batch: %+v", r)
	}
	ok := mkBatch(item("TOKEN", 1, "v", target.File, "web"))
	if r := e.agent.Receive(ctx, nil, func([]byte) (batch.Batch, error) { return ok, nil }); r.Status != Applied {
		t.Fatalf("receive: %+v", r)
	}
	if _, err := New(Config{}); err == nil {
		t.Fatal("an agent without sealer was created")
	}
}

func TestMaterialisationRefusesADiskBackedRuntimeDir(t *testing.T) {
	e := newEnv(t)
	cfg := e.cfg
	cfg.AllowNonTmpfs = false
	cfg.RuntimeDir = filepath.Join(".", "testdata-runtime")
	t.Cleanup(func() { _ = os.RemoveAll(cfg.RuntimeDir) })
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Materialize(ctx, "acme-api"); !errors.Is(err, ErrNotTmpfs) {
		t.Fatalf("want ErrNotTmpfs on the repository disk, got %v", err)
	}
	if _, err := os.Stat("/dev/shm"); err == nil {
		cfg.RuntimeDir = filepath.Join("/dev/shm", "hv-test-"+batch.NewID())
		t.Cleanup(func() { _ = os.RemoveAll(cfg.RuntimeDir) })
		a, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Materialize(ctx, "acme-api"); err != nil {
			t.Fatalf("/dev/shm is tmpfs: %v", err)
		}
	}
}

func TestDotenvEncodingIsSortedAndLiteral(t *testing.T) {
	out, err := encodeDotenv([]envLine{{"B", []byte(`x"$y\z`)}, {"A", []byte("")}})
	if err != nil || !bytes.Equal(out, []byte("A=''\nB='x\"$y\\z'\n")) {
		t.Fatalf("%q %v", out, err)
	}
}
