package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MakFly/hashvault/internal/cli"
	"github.com/MakFly/hashvault/internal/openbao/baotest"
)

// Exercise the backend lifecycle with real persistent OpenBao storage. This is
// not the UI launcher: each fixture owns and reaps its API and OpenBao child.
func TestLocalVaultPersistentAuthenticatedLifecycle(t *testing.T) {
	bin, err := filepath.Abs(filepath.Join("..", "..", ".tools", "bao-"+baotest.Version))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		if os.Getenv("HASHVAULT_REQUIRE_INTEGRATION") == "1" {
			t.Fatal("OpenBao binary missing")
		}
		t.Skip("OpenBao binary missing")
	}
	dir, err := os.MkdirTemp("", "hv-local-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	start := func() func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- run(ctx, dir, bin) }()
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(10 * time.Second):
				t.Error("local fixture did not stop")
			}
		}
		t.Cleanup(stop)
		deadline := time.Now().Add(50 * time.Second)
		for {
			if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
				break
			}
			select {
			case err := <-done:
				stopped = true
				cancel()
				logs, _ := os.ReadFile(filepath.Join(dir, "bao.log"))
				for _, line := range strings.Split(string(logs), "\n") {
					if strings.Contains(strings.ToLower(line), "error") || strings.HasPrefix(line, "unknown storage type") {
						t.Log(line)
					}
				}
				t.Fatalf("local startup: %v", err)
			default:
			}
			if time.Now().After(deadline) {
				stop()
				t.Fatal("local fixture readiness timeout")
			}
			time.Sleep(100 * time.Millisecond)
		}
		return stop
	}
	var output bytes.Buffer
	getenv := func(name string) string {
		switch name {
		case "HASHVAULT_SOCKET":
			return filepath.Join(dir, "api.sock")
		case "HASHVAULT_TOKEN_FILE":
			return filepath.Join(dir, "token")
		default:
			return ""
		}
	}
	call := func(args []string, input string) string {
		output.Reset()
		if cli.Main(args, cli.IO{Stdin: bytes.NewBufferString(input), Stdout: &output, Stderr: io.Discard, Getenv: getenv}) != 0 {
			t.Fatalf("local command failed: %s", args[0])
		}
		return output.String()
	}
	stop := start()
	call([]string{"secret", "put", "dev/acme-api/DATABASE_URL"}, "local-fixture-value")
	if got := call([]string{"secret", "get", "dev/acme-api/DATABASE_URL"}, ""); got != "local-fixture-value" {
		t.Fatal("local secret read did not match")
	}
	call([]string{"audit", "verify"}, "")
	var creds credentials
	data, err := os.ReadFile(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &creds); err != nil {
		t.Fatal(err)
	}
	clear(data)
	if creds.RootToken != "" || creds.SecretID == "" {
		t.Fatal("bootstrap root token was retained")
	}
	for _, name := range []string{"credentials.json", "login-key", "token", "api.sock"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private file mode: %s", name)
		}
	}
	stop()
	for _, name := range []string{"token", "api.sock", "bao.sock", "ready"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("runtime file retained: %s", name)
		}
	}
	stop = start()
	if got := call([]string{"secret", "get", "dev/acme-api/DATABASE_URL"}, ""); got != "local-fixture-value" {
		t.Fatal("local secret lost across restart")
	}
	call([]string{"audit", "verify"}, "")
	stop()
}
