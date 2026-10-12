package hostagent

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"time"
)

// Sealer encrypts values at rest on the host. name is bound into the
// ciphertext, so a file renamed to another credential does not decrypt.
type Sealer interface {
	Seal(ctx context.Context, name string, value []byte) ([]byte, error)
	Open(ctx context.Context, name string, sealed []byte) ([]byte, error)
}

var credName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.[A-Z][A-Z0-9_]*$`)

// SystemdCreds seals with systemd-creds, using the host key and the TPM2
// when one is present (--with-key=auto). The result is what
// LoadCredentialEncrypted= reads.
type SystemdCreds struct {
	// Command is the program and leading arguments, "systemd-creds" by
	// default. Tests point it at a container: ["docker", "exec", "-i", id,
	// "systemd-creds"].
	Command []string
	Timeout time.Duration
}

func (s SystemdCreds) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	cmd := s.Command
	if len(cmd) == 0 {
		cmd = []string{"systemd-creds"}
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	argv := append(append([]string{}, cmd[1:]...), args...)
	c := exec.CommandContext(ctx, cmd[0], argv...) // #nosec G204 -- program from configuration, fixed arguments
	c.Stdin = bytes.NewReader(stdin)
	var out, errOut bytes.Buffer
	c.Stdout, c.Stderr = &out, &errOut
	if err := c.Run(); err != nil {
		// systemd-creds never echoes the plaintext on stderr; keep only
		// the first line in case a future version does something else.
		msg, _, _ := bytes.Cut(errOut.Bytes(), []byte("\n"))
		return nil, fmt.Errorf("systemd-creds %s: %w: %s", args[0], err, msg)
	}
	return out.Bytes(), nil
}

// Seal implements Sealer.
func (s SystemdCreds) Seal(ctx context.Context, name string, value []byte) ([]byte, error) {
	if !credName.MatchString(name) {
		return nil, fmt.Errorf("hostagent: invalid credential name %q", name)
	}
	return s.run(ctx, value, "encrypt", "--with-key=auto", "--name="+name, "-", "-")
}

// Open implements Sealer.
func (s SystemdCreds) Open(ctx context.Context, name string, sealed []byte) ([]byte, error) {
	if !credName.MatchString(name) {
		return nil, fmt.Errorf("hostagent: invalid credential name %q", name)
	}
	return s.run(ctx, sealed, "decrypt", "--name="+name, "-", "-")
}
