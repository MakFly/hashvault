package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func key(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func clock() func() time.Time {
	t := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t = t.Add(time.Second)
		return t
	}
}

func event(i int) Entry {
	return Entry{
		Principal: "human/alice", Action: "secret:Read", Resource: "hv:prod:secret/acme-api/DB",
		Decision: "Allow", Outcome: "ok", Detail: map[string]string{"version": string(rune('0' + i%10)), "key": "DB"},
	}
}

func filled(t *testing.T, n int) (string, ed25519.PublicKey, *Log) {
	t.Helper()
	pub, priv := key(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, priv, clock())
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := l.Append(event(i)); err != nil {
			t.Fatal(err)
		}
	}
	return path, pub, l
}

func lines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.SplitAfter(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
}

func write(t *testing.T, path string, ls [][]byte) {
	t.Helper()
	var out []byte
	for _, l := range ls {
		out = append(out, bytes.TrimSuffix(l, []byte("\n"))...)
		out = append(out, '\n')
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAppendChainsAndVerifies(t *testing.T) {
	path, pub, l := filled(t, 5)
	if _, err := l.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	seq, head := l.Head()
	if seq != 5 || len(head) != 64 {
		t.Fatalf("head %d %s", seq, head)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(path, pub, nil)
	if err != nil || rep.Entries != 5 || rep.Head != head || rep.Checkpoints != 1 {
		t.Fatalf("report %+v %v", rep, err)
	}
	// Reopening continues the chain.
	_, priv := key(t)
	l2, err := Open(path, priv, clock())
	if err != nil {
		t.Fatal(err)
	}
	e, err := l2.Append(event(6))
	if err != nil || e.Seq != 6 || e.Prev != head {
		t.Fatalf("continued entry %+v %v", e, err)
	}
	_ = l2.Close()
}

func TestTamperingIsDetected(t *testing.T) {
	cases := map[string]func([][]byte) [][]byte{
		"edited field": func(ls [][]byte) [][]byte {
			ls[2] = bytes.Replace(ls[2], []byte(`"decision":"Allow"`), []byte(`"decision":"Deny"`), 1)
			return ls
		},
		"deleted line":  func(ls [][]byte) [][]byte { return append(ls[:2:2], ls[3:]...) },
		"reordered":     func(ls [][]byte) [][]byte { ls[1], ls[2] = ls[2], ls[1]; return ls },
		"injected line": func(ls [][]byte) [][]byte { return append(ls[:2:2], append([][]byte{ls[0]}, ls[2:]...)...) },
		"garbage line":  func(ls [][]byte) [][]byte { ls[3] = []byte("not json"); return ls },
		"unknown field": func(ls [][]byte) [][]byte {
			ls[1] = bytes.Replace(ls[1], []byte(`{"seq"`), []byte(`{"x":1,"seq"`), 1)
			return ls
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			path, pub, l := filled(t, 5)
			_ = l.Close()
			write(t, path, mutate(lines(t, path)))
			if _, err := Verify(path, pub, nil); !errors.Is(err, ErrBroken) {
				t.Fatalf("want ErrBroken, got %v", err)
			}
			_, priv := key(t)
			if _, err := Open(path, priv, nil); !errors.Is(err, ErrBroken) {
				t.Fatalf("a broken log must not open for appending: %v", err)
			}
		})
	}
}

func TestATruncatedLastLineRefusesToOpen(t *testing.T) {
	path, pub, l := filled(t, 3)
	_ = l.Close()
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, data[:len(data)-10], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path, pub, nil); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("got %v", err)
	}
}

// A rewritten history whose own chain is consistent still fails against the
// anchors taken before.
func TestAnchorsCatchARewrittenHistory(t *testing.T) {
	path, pub, l := filled(t, 4)
	anchor, err := l.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	// The attacker rebuilds a consistent log from scratch, same length.
	_ = os.Remove(path)
	_ = os.Remove(path + ".checkpoints")
	_, attackerKey := key(t)
	forged, err := Open(path, attackerKey, clock())
	if err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		e := event(i)
		e.Decision = "Deny"
		if _, err := forged.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	_ = forged.Close()
	if _, err := Verify(path, pub, nil); err != nil {
		t.Fatalf("without anchors the forged chain is self-consistent: %v", err)
	}
	if _, err := Verify(path, pub, []Checkpoint{anchor}); !errors.Is(err, ErrBroken) {
		t.Fatalf("the anchor must expose the rewrite: %v", err)
	}
	// Truncation below an anchor is caught too.
	write(t, path, lines(t, path)[:2])
	if _, err := Verify(path, pub, []Checkpoint{anchor}); err == nil || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("truncation: %v", err)
	}
}

func TestCheckpointsNeedTheTrustedKey(t *testing.T) {
	path, _, l := filled(t, 2)
	if _, err := l.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	other, _ := key(t)
	if _, err := Verify(path, other, nil); !errors.Is(err, ErrBroken) {
		t.Fatalf("a checkpoint signed by another key was accepted: %v", err)
	}
	cps, err := ReadCheckpoints(path + ".checkpoints")
	if err != nil || len(cps) != 1 {
		t.Fatal(cps, err)
	}
	cps[0].Signature[0] ^= 1
	if _, err := Verify(path, nil, cps); !errors.Is(err, ErrBroken) {
		t.Fatalf("no trusted key: %v", err)
	}
	if err := os.WriteFile(path+".checkpoints", []byte("{bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCheckpoints(path + ".checkpoints"); !errors.Is(err, ErrBroken) {
		t.Fatalf("corrupted checkpoints: %v", err)
	}
}

func TestDetailsCannotCarrySecrets(t *testing.T) {
	_, _, l := filled(t, 0)
	defer l.Close()
	for _, k := range []string{"value", "Secret", "password", "api_token", "plaintext", "private_key"} {
		e := event(1)
		e.Detail = map[string]string{k: "x"}
		if _, err := l.Append(e); !errors.Is(err, ErrSecretDetail) {
			t.Errorf("detail key %q accepted", k)
		}
	}
	big := event(1)
	big.Detail = map[string]string{"note": strings.Repeat("x", maxLine)}
	if _, err := l.Append(big); err == nil {
		t.Fatal("an oversized entry was accepted")
	}
}

func TestConcurrentAppendsStayChained(t *testing.T) {
	path, pub, l := filled(t, 0)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Append(event(i)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	_ = l.Close()
	rep, err := Verify(path, pub, nil)
	if err != nil || rep.Entries != 50 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestOpenNeedsAKey(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "a"), nil, nil); err == nil {
		t.Fatal("opened without a signing key")
	}
	if _, err := Verify(filepath.Join(t.TempDir(), "missing"), nil, nil); err == nil {
		t.Fatal("verified a missing file")
	}
}

func FuzzVerifyChain(f *testing.F) {
	f.Add([]byte(`{"seq":1,"prev":"0","hash":"x"}` + "\n"))
	f.Add([]byte("\n\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := verifyChain(bytes.NewReader(data))
		if err == nil && rep.Entries > 0 && rep.Head == Genesis {
			t.Fatal("a non-empty chain kept the genesis head")
		}
	})
}

func TestIOErrorsSurface(t *testing.T) {
	_, _, l := filled(t, 1)
	_ = l.Close()
	if _, err := l.Append(event(1)); err == nil {
		t.Fatal("append to a closed log succeeded")
	}
	if _, err := l.Checkpoint(); err == nil {
		t.Fatal("checkpoint on a closed log succeeded")
	}
	dir := t.TempDir()
	_, priv := key(t)
	if _, err := Open(dir, priv, nil); err == nil {
		t.Fatal("a directory opened as a log")
	}
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.Mkdir(path+".checkpoints", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, priv, nil); err == nil {
		t.Fatal("a directory opened as the checkpoints file")
	}
	if _, err := Verify(path, nil, nil); err == nil {
		t.Fatal("verify read a directory as checkpoints")
	}
}
