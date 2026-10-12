package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/MakFly/hashvault/internal/hostagent"
)

// Transport hands a sealed batch to a host agent and returns its receipt.
type Transport interface {
	Deliver(ctx context.Context, sealed []byte) (hostagent.Receipt, error)
	Describe() string
}

// maxReceiptSize bounds what the agent may answer.
const maxReceiptSize = 64 << 10

// run executes argv with sealed on stdin and parses the one-line receipt on
// stdout. A non-zero exit with a parseable receipt is a normal answer
// (rolled_back, refused); anything else is a transport failure.
func run(ctx context.Context, timeout time.Duration, argv []string, sealed []byte) (hostagent.Receipt, error) {
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- argv from the target configuration, no shell
	cmd.Stdin = bytes.NewReader(sealed)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	runErr := cmd.Run()
	if out.Len() > maxReceiptSize {
		return hostagent.Receipt{}, fmt.Errorf("host: receipt larger than %d bytes", maxReceiptSize)
	}
	var r hostagent.Receipt
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &r); err != nil || r.Status == "" {
		msg, _, _ := bytes.Cut(bytes.TrimSpace(errOut.Bytes()), []byte("\n"))
		return hostagent.Receipt{}, errors.Join(fmt.Errorf("host: no receipt from %s: %s", argv[0], msg), runErr)
	}
	return r, nil
}

// LocalSudo runs the agent on this host through sudo, which the sudoers
// rule in deploy/ limits to exactly that command.
type LocalSudo struct {
	// Command defaults to sudo -n /usr/local/bin/hashvault-agent receive.
	Command []string
	Timeout time.Duration
}

// Deliver implements Transport.
func (l LocalSudo) Deliver(ctx context.Context, sealed []byte) (hostagent.Receipt, error) {
	argv := l.Command
	if len(argv) == 0 {
		argv = []string{"sudo", "-n", "/usr/local/bin/hashvault-agent", "receive"}
	}
	return run(ctx, l.Timeout, argv, sealed)
}

// Describe implements Transport.
func (l LocalSudo) Describe() string { return "local sudo" }

// SSH delivers through the system OpenSSH client. The remote key is
// restricted to the receive command (deploy/authorized_keys.example), so no
// remote command is sent: the server decides what runs.
type SSH struct {
	Host string
	Port int
	User string
	// KeyFile is the private key of the vault's push identity.
	KeyFile string
	// KnownHostsFile pins the host key. There is no trust on first use.
	KnownHostsFile string
	Timeout        time.Duration
	// Program is the ssh client, "ssh" by default.
	Program string
}

var hostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$|^\[?[0-9a-fA-F:.]+\]?$`)

func (s SSH) argv() ([]string, error) {
	switch {
	case !hostPattern.MatchString(s.Host):
		return nil, fmt.Errorf("host: invalid ssh host %q", s.Host)
	case s.User == "" || s.User[0] == '-':
		return nil, fmt.Errorf("host: invalid ssh user %q", s.User)
	case s.KeyFile == "" || s.KnownHostsFile == "":
		return nil, errors.New("host: ssh needs a key file and a pinned known_hosts file")
	}
	port := s.Port
	if port == 0 {
		port = 22
	}
	program := s.Program
	if program == "" {
		program = "ssh"
	}
	return []string{
		program,
		"-F", "/dev/null", // ignore user and system configs: nothing may override the options below
		"-i", s.KeyFile,
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + s.KnownHostsFile,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UpdateHostKeys=no",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "PermitLocalCommand=no",
		"-o", "ConnectTimeout=15",
		"-o", "ServerAliveInterval=15",
		"-T",
		"-p", strconv.Itoa(port),
		"-l", s.User,
		"--", s.Host,
	}, nil
}

// Deliver implements Transport.
func (s SSH) Deliver(ctx context.Context, sealed []byte) (hostagent.Receipt, error) {
	argv, err := s.argv()
	if err != nil {
		return hostagent.Receipt{}, err
	}
	return run(ctx, s.Timeout, argv, sealed)
}

// Describe implements Transport.
func (s SSH) Describe() string { return "ssh " + s.User + "@" + s.Host }
