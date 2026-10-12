package host

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MakFly/hashvault/internal/dockerapi/dindtest"
	"github.com/MakFly/hashvault/internal/hostagent"
)

// sshServer is a throwaway Debian container running OpenSSH, with a user
// whose key is restricted to a fake agent: it stores stdin and prints a
// receipt. The real agent is covered in process; this test is about the
// transport: pinned host key, forced command, exact bytes.
type sshServer struct {
	cid, keyFile, knownHosts string
	port                     int
}

const fakeAgent = `#!/bin/sh
cat > /tmp/received
echo "{\"batch_id\":\"fixed\",\"status\":\"applied\",\"app\":\"acme-api\",\"error\":\"cmd=$SSH_ORIGINAL_COMMAND\"}"
`

func startSSH(t *testing.T) sshServer {
	t.Helper()
	dindtest.Require(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "push")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "hashvault-push", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	cid, err := dindtest.Run(ctx, "--label", "hashvault.test=ssh", "-p", "127.0.0.1::22", dindtest.Mirror+"debian:13-slim", "sleep", "900")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", cid).Run() }) // #nosec G204 -- ID from docker run
	setup := `set -e
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends openssh-server >/dev/null
useradd -m -s /bin/sh hashvault
install -d -m 0700 -o hashvault ~hashvault/.ssh
printf 'restrict,command="/usr/local/bin/fake-agent" %s\n' "$PUBKEY" > ~hashvault/.ssh/authorized_keys
chown hashvault ~hashvault/.ssh/authorized_keys && chmod 0600 ~hashvault/.ssh/authorized_keys
printf '%s' "$FAKE_AGENT" > /usr/local/bin/fake-agent && chmod 0755 /usr/local/bin/fake-agent
ssh-keygen -A >/dev/null
mkdir -p /run/sshd
/usr/sbin/sshd -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no
`
	cmd := exec.Command("docker", "exec", "-e", "PUBKEY="+strings.TrimSpace(string(pub)), "-e", "FAKE_AGENT="+fakeAgent, cid, "sh", "-c", setup) // #nosec G204 -- fixed script
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sshd setup: %v\n%s", err, out)
	}
	portOut, err := exec.Command("docker", "port", cid, "22/tcp").Output() // #nosec G204 -- ID from docker run
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := strings.Cut(strings.TrimSpace(strings.Split(string(portOut), "\n")[0]), ":")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q", portOut)
	}
	hostKey, err := exec.Command("docker", "exec", cid, "cat", "/etc/ssh/ssh_host_ed25519_key.pub").Output() // #nosec G204 -- ID from docker run
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(hostKey))
	knownHosts := filepath.Join(dir, "known_hosts")
	line := "[127.0.0.1]:" + portStr + " " + fields[0] + " " + fields[1] + "\n"
	if err := os.WriteFile(knownHosts, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	// sshd may need a moment after daemonising.
	deadline := time.Now().Add(20 * time.Second)
	for exec.Command("docker", "exec", cid, "sh", "-c", "test -f /run/sshd.pid").Run() != nil { // #nosec G204 -- ID from docker run
		if time.Now().After(deadline) {
			t.Fatal("sshd did not start")
		}
		time.Sleep(200 * time.Millisecond)
	}
	return sshServer{cid: cid, keyFile: key, knownHosts: knownHosts, port: port}
}

func (s sshServer) transport() SSH {
	return SSH{Host: "127.0.0.1", Port: s.port, User: "hashvault", KeyFile: s.keyFile, KnownHostsFile: s.knownHosts, Timeout: 30 * time.Second}
}

func (s sshServer) received(t *testing.T) []byte {
	t.Helper()
	out, err := exec.Command("docker", "exec", s.cid, "cat", "/tmp/received").Output() // #nosec G204 -- ID from docker run
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSSHTransportAgainstARealServer(t *testing.T) {
	srv := startSSH(t)
	payload := make([]byte, 64<<10)
	_, _ = rand.Read(payload)

	r, err := srv.transport().Deliver(ctx, payload)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != hostagent.Applied || r.BatchID != "fixed" {
		t.Fatalf("receipt %+v", r)
	}
	if !bytes.Equal(srv.received(t), payload) {
		t.Fatal("the bytes received differ from the bytes sent")
	}
	if r.Error != "cmd=" {
		t.Fatalf("the client must not send a remote command, server saw %q", r.Error)
	}

	// The key cannot run anything else: whatever the client asks, the server
	// runs the forced command.
	s := srv.transport()
	argv, _ := s.argv()
	argv = append(argv, "id")
	out, _ := exec.Command(argv[0], argv[1:]...).Output() // #nosec G204 -- test argv
	if bytes.Contains(out, []byte("uid=")) || !bytes.Contains(out, []byte("cmd=id")) {
		t.Fatalf("the restricted key ran another command: %s", out)
	}
}

func TestSSHRefusesAnUnpinnedHostKey(t *testing.T) {
	srv := startSSH(t)
	wrong := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(wrong, []byte("[127.0.0.1]:"+strconv.Itoa(srv.port)+" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := srv.transport()
	s.KnownHostsFile = wrong
	if _, err := s.Deliver(ctx, []byte("x")); err == nil {
		t.Fatal("delivered to a host whose key is not the pinned one")
	}
	s.KnownHostsFile = filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(s.KnownHostsFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deliver(ctx, []byte("x")); err == nil {
		t.Fatal("delivered to an unknown host (trust on first use)")
	}
}
