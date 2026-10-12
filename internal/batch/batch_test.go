package batch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/MakFly/hashvault/internal/target"
)

var now = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

type keys struct {
	vaultPub  ed25519.PublicKey
	vaultPriv ed25519.PrivateKey
	agent     *age.HybridIdentity
}

func newKeys(t testing.TB) keys {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return keys{pub, priv, id}
}

func sample() Batch {
	return Batch{
		Version: Version, ID: NewID(), Agent: "web-01", Target: "ssh-web-01", Kind: target.SSH,
		App: "acme-api", Env: "prod", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		Items: []Item{{
			Key: "DATABASE_URL", Version: 3, Resource: "hv:prod:secret/acme-api/DATABASE_URL",
			Value: []byte("postgres://s3cr3t"),
			Spec:  target.ItemSpec{Expose: target.Env, Target: "database_url", Services: []string{"web"}, UID: "33", GID: "33", Mode: "0400"},
		}},
		Consumers: Consumers{Reload: [][]string{{"/usr/bin/systemctl", "reload", "php8.4-fpm"}}},
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := newKeys(t)
	b := sample()
	data, err := Seal(b, k.vaultPriv, k.agent.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "s3cr3t") || strings.Contains(string(data), "DATABASE_URL") {
		t.Fatal("the sealed batch leaks its content")
	}
	got, err := Open(data, k.agent, k.vaultPub, "web-01", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != b.ID || string(got.Items[0].Value) != "postgres://s3cr3t" || got.Consumers.Reload[0][2] != "php8.4-fpm" {
		t.Fatalf("round trip lost data: %+v", got)
	}
	got.Clear()
	if string(got.Items[0].Value) != strings.Repeat("\x00", len("postgres://s3cr3t")) {
		t.Fatal("Clear did not wipe the value")
	}
}

func TestOpenRefusesWhatItCannotTrust(t *testing.T) {
	k := newKeys(t)
	other := newKeys(t)
	good, err := Seal(sample(), k.vaultPriv, k.agent.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	// Anyone holding the agent's public recipient can encrypt: the signature
	// is what stops a forged batch.
	forged, err := Seal(sample(), other.vaultPriv, k.agent.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-5] ^= 1
	cases := map[string]func() error{
		"forged by another signer": func() error { _, err := Open(forged, k.agent, k.vaultPub, "web-01", now); return err },
		"for another agent":        func() error { _, err := Open(good, other.agent, k.vaultPub, "web-01", now); return err },
		"wrong agent name":         func() error { _, err := Open(good, k.agent, k.vaultPub, "web-02", now); return err },
		"tampered":                 func() error { _, err := Open(tampered, k.agent, k.vaultPub, "web-01", now); return err },
		"expired":                  func() error { _, err := Open(good, k.agent, k.vaultPub, "web-01", now.Add(6*time.Minute)); return err },
		"from the future":          func() error { _, err := Open(good, k.agent, k.vaultPub, "web-01", now.Add(-time.Minute)); return err },
		"no trusted key":           func() error { _, err := Open(good, k.agent, nil, "web-01", now); return err },
		"garbage":                  func() error { _, err := Open([]byte("not age"), k.agent, k.vaultPub, "web-01", now); return err },
		"oversized":                func() error { _, err := Open(make([]byte, maxSize+1), k.agent, k.vaultPub, "web-01", now); return err },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if err := f(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestOpenValidatesTheSignedPayload(t *testing.T) {
	k := newKeys(t)
	mutate := map[string]func(*Batch){
		"version":              func(b *Batch) { b.Version = "hv-batch-0" },
		"short id":             func(b *Batch) { b.ID = "abc" },
		"bad target":           func(b *Batch) { b.Target = "Bad Target" },
		"swarm kind":           func(b *Batch) { b.Kind = target.Swarm },
		"long validity":        func(b *Batch) { b.ExpiresAt = b.IssuedAt.Add(time.Hour) },
		"no items":             func(b *Batch) { b.Items = nil },
		"bad item":             func(b *Batch) { b.Items[0].Key = "lower" },
		"version zero":         func(b *Batch) { b.Items[0].Version = 0 },
		"docker in ssh":        func(b *Batch) { b.Consumers.Docker = []string{"web"} },
		"reload in docker":     func(b *Batch) { b.Kind = target.Docker },
		"relative reload":      func(b *Batch) { b.Consumers.Reload = [][]string{{"systemctl", "reload", "x"}} },
		"empty reload command": func(b *Batch) { b.Consumers.Reload = [][]string{{}} },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			b := sample()
			m(&b)
			data, err := Seal(b, k.vaultPriv, k.agent.Recipient())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Open(data, k.agent, k.vaultPub, "web-01", now.Add(time.Second)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestReplayRefusesReuseAndDowngrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "replay.json")
	r, err := LoadReplay(path)
	if err != nil {
		t.Fatal(err)
	}
	b := sample()
	if err := r.Check(b); err != nil {
		t.Fatal(err)
	}
	if err := r.Record(b, now); err != nil {
		t.Fatal(err)
	}
	if err := r.Check(b); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replay accepted: %v", err)
	}
	older := sample()
	older.Items[0].Version = 2
	if err := r.Check(older); !errors.Is(err, ErrInvalid) {
		t.Fatalf("downgrade accepted: %v", err)
	}
	older.Rollback = true
	if err := r.Check(older); err != nil {
		t.Fatalf("a signed rollback must be accepted: %v", err)
	}

	// State survives a restart, and expired ids are pruned on the next write.
	again, err := LoadReplay(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Applied("acme-api", "DATABASE_URL") != 3 {
		t.Fatal("applied version lost across a restart")
	}
	if err := again.Check(b); !errors.Is(err, ErrInvalid) {
		t.Fatal("seen id lost across a restart")
	}
	later := sample()
	later.Items[0].Version = 4
	if err := again.Record(later, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := again.Check(b); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("after pruning, the old batch must still fail on its version: %v", err)
	}
}

func TestLoadReplayRefusesACorruptedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.json")
	if err := writeFile(path, "{not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReplay(path); err == nil {
		t.Fatal("a corrupted replay state was accepted")
	}
}

func FuzzOpen(f *testing.F) {
	k := newKeys(f)
	good, err := Seal(sample(), k.vaultPriv, k.agent.Recipient())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte("age-encryption.org/v1\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := Open(data, k.agent, k.vaultPub, "web-01", now.Add(time.Second))
		if err == nil && b.ID == "" {
			t.Fatal("an empty batch was accepted")
		}
	})
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// sealRaw signs and encrypts an arbitrary payload, to test the strict parser
// behind a valid signature.
func sealRaw(t *testing.T, k keys, payload []byte) []byte {
	t.Helper()
	inner, err := json.Marshal(sealed{Payload: payload, Signature: ed25519.Sign(k.vaultPriv, message(payload))})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, k.agent.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(inner)
	_ = w.Close()
	return out.Bytes()
}

func TestSignedButMalformedPayloadsAreRefused(t *testing.T) {
	k := newKeys(t)
	valid, err := json.Marshal(sample())
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string]string{
		"trailing data": string(valid) + `{}`,
		"unknown field": strings.Replace(string(valid), `{"version"`, `{"extra":1,"version"`, 1),
		"not json":      `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(sealRaw(t, k, []byte(payload)), k.agent, k.vaultPub, "web-01", now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
	var out bytes.Buffer
	w, _ := age.Encrypt(&out, k.agent.Recipient())
	_, _ = w.Write([]byte(`{"payload":"AA==","signature":"AA==","x":1}`))
	_ = w.Close()
	if _, err := Open(out.Bytes(), k.agent, k.vaultPub, "web-01", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown envelope field: %v", err)
	}
}

func TestReplayPersistenceErrorsSurface(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadReplay(dir); err == nil {
		t.Fatal("a directory was read as a replay state")
	}
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	r, err := LoadReplay(filepath.Join(ro, "replay.json"))
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if err := r.Record(sample(), now); err == nil {
			t.Fatal("recording into a read-only directory succeeded")
		}
	}
	empty := filepath.Join(dir, "empty.json")
	if err := writeFile(empty, `{}`); err != nil {
		t.Fatal(err)
	}
	r, err = LoadReplay(empty)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Record(sample(), now); err != nil {
		t.Fatalf("an empty state must be usable: %v", err)
	}
}

type failingRecipient struct{}

func (failingRecipient) Wrap([]byte) ([]*age.Stanza, error) { return nil, errors.New("no key") }

func TestSealSurfacesEncryptionErrors(t *testing.T) {
	k := newKeys(t)
	if _, err := Seal(sample(), k.vaultPriv, failingRecipient{}); err == nil {
		t.Fatal("a failing recipient did not fail the seal")
	}
}
