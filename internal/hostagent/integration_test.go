package hostagent

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MakFly/hashvault/internal/batch"
	"github.com/MakFly/hashvault/internal/dockerapi/dindtest"
	"github.com/MakFly/hashvault/internal/target"
)

func TestSystemdCredsPlumbing(t *testing.T) {
	echo := SystemdCreds{Command: []string{"sh", "-c", "cat", "sh"}}
	out, err := echo.Seal(ctx, "acme-api.KEY", []byte("v"))
	if err != nil || string(out) != "v" {
		t.Fatalf("stdin must reach the program: %q %v", out, err)
	}
	if _, err := echo.Open(ctx, "acme-api.KEY", []byte("v")); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "acme-api", "Acme.KEY", "acme.key", "../x.KEY", "a.KEY/b"} {
		if _, err := echo.Seal(ctx, bad, nil); err == nil {
			t.Errorf("credential name %q accepted", bad)
		}
		if _, err := echo.Open(ctx, bad, nil); err == nil {
			t.Errorf("credential name %q accepted on open", bad)
		}
	}
	failing := SystemdCreds{Command: []string{"sh", "-c", "echo 'refusing\nsecond line' >&2; exit 3", "sh"}}
	_, err = failing.Seal(ctx, "acme-api.KEY", []byte("v"))
	if err == nil || !strings.Contains(err.Error(), "refusing") || strings.Contains(err.Error(), "second line") {
		t.Fatalf("error must carry the first stderr line only: %v", err)
	}
	slow := SystemdCreds{Command: []string{"sleep", "5"}, Timeout: 100 * time.Millisecond}
	if _, err := slow.Seal(ctx, "acme-api.KEY", nil); err == nil {
		t.Fatal("a hung systemd-creds was not timed out")
	}
}

var (
	credsOnce sync.Once
	credsCID  string
	credsErr  error
)

// credsContainer is a throwaway Debian container with systemd-creds, run as
// root inside it: the real tool, without touching the host's credentials.
func credsContainer(t *testing.T) string {
	t.Helper()
	dindtest.Require(t)
	credsOnce.Do(func() {
		out, err := exec.Command("docker", "run", "-d", "--rm", "--label", "hashvault.test=creds",
			dindtest.Mirror+"debian:13-slim", "sleep", "900").Output()
		if err != nil {
			credsErr = err
			return
		}
		credsCID = strings.TrimSpace(string(out))
		install := exec.Command("docker", "exec", credsCID, "sh", "-c", // #nosec G204 -- fixed arguments
			"apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends systemd")
		if out, err := install.CombinedOutput(); err != nil {
			credsErr = err
			t.Logf("%s", out)
		}
	})
	if credsErr != nil {
		t.Fatalf("systemd-creds container: %v", credsErr)
	}
	return credsCID
}

func TestMain(m *testing.M) {
	code := m.Run()
	if credsCID != "" {
		_ = exec.Command("docker", "rm", "-f", credsCID).Run() // #nosec G204 -- ID from docker run
	}
	os.Exit(code)
}

func TestRealSystemdCredsBindsTheName(t *testing.T) {
	cid := credsContainer(t)
	s := SystemdCreds{Command: []string{"docker", "exec", "-i", cid, "systemd-creds"}}
	sealed, err := s.Seal(ctx, "acme-api.DATABASE_URL", []byte("p@ss$word"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "p@ss") {
		t.Fatal("systemd-creds output holds the plaintext")
	}
	got, err := s.Open(ctx, "acme-api.DATABASE_URL", sealed)
	if err != nil || string(got) != "p@ss$word" {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := s.Open(ctx, "acme-api.OTHER", sealed); err == nil {
		t.Fatal("a credential opened under another name")
	}
}

func TestRealSystemdCredsThroughTheAgent(t *testing.T) {
	cid := credsContainer(t)
	e := newEnv(t)
	e.agent.cfg.Sealer = SystemdCreds{Command: []string{"docker", "exec", "-i", cid, "systemd-creds"}}
	if r := e.agent.Apply(ctx, mkBatch(item("TOKEN", 1, "real", target.Env, "web"))); r.Status != Applied {
		t.Fatalf("%+v", r)
	}
	if got := read(t, e.cfg.RuntimeDir+"/acme-api/web/.env"); got != "TOKEN='real'\n" {
		t.Fatalf(".env %q", got)
	}
}

func TestReloadCommands(t *testing.T) {
	h := HostConsumers{ReadyTimeout: 300 * time.Millisecond}
	ssh := func(argv ...[]string) batch.Batch {
		return batch.Batch{App: "acme-api", Kind: target.SSH, Consumers: batch.Consumers{Reload: argv}}
	}
	if err := h.Run(ctx, ssh([]string{"/bin/true"}, []string{"/bin/sh", "-c", "exit 0"})); err != nil {
		t.Fatal(err)
	}
	err := h.Run(ctx, ssh([]string{"/bin/sh", "-c", "echo reload refused >&2; exit 2"}))
	if err == nil || !strings.Contains(err.Error(), "reload refused") {
		t.Fatalf("got %v", err)
	}
	if err := h.Run(ctx, ssh([]string{"/bin/sleep", "5"})); err == nil {
		t.Fatal("a hung reload was not timed out")
	}
	docker := batch.Batch{App: "acme-api", Kind: target.Docker, Consumers: batch.Consumers{Docker: []string{"web"}}}
	if err := h.Run(ctx, docker); err == nil {
		t.Fatal("docker consumers without a Docker client must fail")
	}
}

func TestDockerConsumersRestartComposeContainers(t *testing.T) {
	dindtest.Require(t)
	d, err := dindtest.Start(ctx, dindtest.Options{PullTestImage: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Stop)
	image := dindtest.TestImage + ":" + dindtest.TestImageTag
	create := func(name, service string, cmd ...string) string {
		id, err := d.Client.ContainerCreate(ctx, name, map[string]any{
			"Image": image, "Cmd": cmd,
			"Labels": map[string]string{"com.docker.compose.project": "acme-api", "com.docker.compose.service": service},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Client.ContainerStart(ctx, id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	create("acme-web-1", "web", "sleep", "3600")
	// Runs the first time, exits 3 on every restart.
	create("acme-broken-1", "broken", "sh", "-c", "test -f /tmp/once && exit 3; touch /tmp/once; exec sleep 3600")

	h := HostConsumers{Docker: d.Client, StopTimeout: time.Second, ReadyTimeout: 30 * time.Second, Poll: 200 * time.Millisecond}
	b := func(services ...string) batch.Batch {
		return batch.Batch{App: "acme-api", Kind: target.Docker, Consumers: batch.Consumers{Docker: services}}
	}
	if err := h.Run(ctx, b("web")); err != nil {
		t.Fatal(err)
	}
	if err := h.Run(ctx, b("broken")); err == nil || !strings.Contains(err.Error(), "exited with code 3") {
		t.Fatalf("got %v", err)
	}
	if err := h.Run(ctx, b("missing")); err == nil || !strings.Contains(err.Error(), "no container") {
		t.Fatalf("got %v", err)
	}
	other := b("web")
	other.Consumers.ComposeProject = "another-project"
	if err := h.Run(ctx, other); err == nil {
		t.Fatal("a service of another compose project was restarted")
	}
}
