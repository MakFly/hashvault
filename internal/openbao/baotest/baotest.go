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
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/MakFly/hashvault/internal/openbao"
)

// Version is the OpenBao release the tests run against.
const Version = "2.7.1"

// Mounts created on every server.
const (
	KVMount      = "hv"
	TransitMount = "transit"
	KEK          = "hv-kek-test"
)

// Server is a running dev server.
type Server struct {
	Address string
	Token   string
	Client  *openbao.Client
}

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
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		_ = logs.Close()
	})

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
	must(client.Mount(bg, TransitMount, "transit", nil))
	must(client.TransitCreateKey(bg, TransitMount, KEK, "chacha20-poly1305"))
	return &Server{Address: "http://" + addr, Token: token, Client: client}
}
