// Package baotest starts a real OpenBao dev server for integration tests.
//
// The binary is HASHVAULT_BAO_BIN, or .tools/bao-<version> at the module
// root (`make openbao` downloads it, checksum verified). Without it the
// tests are skipped, unless HASHVAULT_REQUIRE_INTEGRATION=1, which CI sets:
// there a missing binary fails the run instead of hiding the tests.
package baotest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/MakFly/hashvault/internal/openbao"
)

// Version is the OpenBao release the tests run against.
const Version = "2.7.1"

// Mounts created on every server.
const (
	KVMount          = "hv"
	TransitMount     = "transit"
	KEK              = "hv-kek-test"
	readinessTimeout = 15 * time.Second
)

// Server is a running dev server.
type Server struct {
	Address string
	Token   string
	Client  *openbao.Client
	stop    func()
}

// Stop kills the server before the end of the test, to test outages.
func (s *Server) Stop() { s.stop() }

func binary(t testing.TB) string {
	t.Helper()
	if bin := os.Getenv("HASHVAULT_BAO_BIN"); bin != "" {
		return bin
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "..")
	bin := filepath.Join(root, ".tools", "bao-"+Version)
	if _, err := os.Stat(bin); err != nil {
		if os.Getenv("HASHVAULT_REQUIRE_INTEGRATION") == "1" {
			t.Fatalf("OpenBao binary missing (%s): run `make openbao`", bin)
		}
		t.Skipf("OpenBao binary missing (%s): run `make openbao` to enable integration tests", bin)
	}
	return bin
}

func freePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForKV2(client *openbao.Client, mount, probe string) error {
	ctx, cancel := context.WithTimeout(context.Background(), readinessTimeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		entry, err := client.KVGet(ctx, mount, probe, 0)
		if err == nil {
			if entry.Version == 0 || entry.Data["ready"] != "true" {
				return fmt.Errorf("KV v2 readiness probe returned unexpected data")
			}
			if err := client.KVDestroy(ctx, mount, probe, []int{entry.Version}); err != nil {
				return fmt.Errorf("remove KV v2 readiness probe: %w", err)
			}
			return nil
		}

		if errors.Is(err, openbao.ErrNotFound) {
			version, putErr := client.KVPut(ctx, mount, probe, map[string]string{"ready": "true"}, 0)
			switch {
			case putErr == nil && version == 0:
				return fmt.Errorf("KV v2 readiness probe returned no version")
			case putErr == nil, errors.Is(putErr, openbao.ErrCASMismatch):
				// A successful write, or a prior write whose response was lost,
				// should be readable on the next iteration.
				continue
			default:
				lastErr = putErr
			}
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			return fmt.Errorf("KV v2 mount %q did not become ready within %s: %w", mount, readinessTimeout, lastErr)
		case <-ticker.C:
		}
	}
}

// Start runs a dev server for the duration of the test, with a KV v2 mount,
// a Transit mount and a chacha20-poly1305 KEK.
func Start(t testing.TB) *Server {
	t.Helper()
	bin := binary(t)
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	token := "test-" + hex.EncodeToString(raw)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	ctx, cancel := context.WithCancel(context.Background())
	// bin comes from the test environment (HASHVAULT_BAO_BIN or .tools/), not
	// from untrusted input; arguments are fixed.
	cmd := exec.CommandContext(ctx, bin, "server", "-dev", "-dev-root-token-id="+token, "-dev-listen-address="+addr, "-dev-no-store-token") // #nosec G204
	cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=/usr/bin:/bin"}
	logs, err := os.CreateTemp(t.TempDir(), "bao-*.log")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			_ = cmd.Wait()
			_ = logs.Close()
		})
	}
	t.Cleanup(stop)

	client, err := openbao.New(openbao.Config{Address: "http://" + addr, Token: token, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		st, err := client.SealStatus(context.Background())
		if err == nil && st.Initialized && !st.Sealed {
			break
		}
		if time.Now().After(deadline) {
			out, _ := os.ReadFile(logs.Name())
			t.Fatalf("OpenBao dev server did not start: %v\n%s", err, out)
		}
		time.Sleep(100 * time.Millisecond)
	}
	bg := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(client.Mount(bg, KVMount, "kv", map[string]string{"version": "2"}))
	if err := waitForKV2(client, KVMount, "readiness-"+hex.EncodeToString(raw)); err != nil {
		t.Fatalf("OpenBao KV v2 mount did not become ready: %v", err)
	}
	must(client.Mount(bg, TransitMount, "transit", nil))
	must(client.TransitCreateKey(bg, TransitMount, KEK, "chacha20-poly1305"))
	return &Server{Address: "http://" + addr, Token: token, Client: client, stop: stop}
}

// StartUninitialized runs a real (non-dev) server with file storage, not
// initialised and sealed: what a fresh production install looks like. The
// client has no token.
func StartUninitialized(t testing.TB) *Server {
	t.Helper()
	bin := binary(t)
	dir := t.TempDir()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cluster := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := os.MkdirAll(filepath.Join(dir, "raft"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`storage "raft" {
  path    = %q
  node_id = "test"
}
listener "tcp" {
  address         = %q
  cluster_address = %q
  tls_disable     = true
}
api_addr     = "http://%s"
cluster_addr = "http://%s"
`, filepath.Join(dir, "raft"), addr, cluster, addr, cluster)
	cfgPath := filepath.Join(dir, "bao.hcl")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "server", "-config="+cfgPath) // #nosec G204 -- test binary, fixed arguments
	cmd.Env = []string{"HOME=" + dir, "PATH=/usr/bin:/bin"}
	logs, err := os.CreateTemp(dir, "bao-*.log")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			_ = cmd.Wait()
			_ = logs.Close()
		})
	}
	t.Cleanup(stop)
	client, err := openbao.New(openbao.Config{Address: "http://" + addr})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := client.SealStatus(context.Background()); err == nil {
			break
		}
		if time.Now().After(deadline) {
			out, _ := os.ReadFile(logs.Name())
			t.Fatalf("OpenBao server did not start:\n%s", out)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return &Server{Address: "http://" + addr, Client: client, stop: stop}
}
