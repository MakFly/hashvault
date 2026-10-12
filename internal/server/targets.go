package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/MakFly/hashvault/internal/dockerapi"
	"github.com/MakFly/hashvault/internal/registry"
	"github.com/MakFly/hashvault/internal/target"
	"github.com/MakFly/hashvault/internal/target/host"
	"github.com/MakFly/hashvault/internal/target/swarm"
)

// ErrStandby reports a target kind designed but not implemented yet.
var ErrStandby = errors.New("target kind on standby: designed, not implemented")

// FactoryConfig bounds what a target registration may point at. Registering
// a target must not be a way to run code or read files as the daemon.
type FactoryConfig struct {
	// BatchSigner signs batches for host agents.
	BatchSigner ed25519.PrivateKey
	// SSHDir holds the push keys and pinned known_hosts files; ssh targets
	// may only name files inside it.
	SSHDir string
	// AllowTCPDocker accepts tcp:// Docker addresses (tests only: an
	// unauthenticated TCP daemon is root for anyone who reaches it).
	AllowTCPDocker bool
	// Transport overrides host transports (tests only).
	Transport func(registry.Target) host.Transport
}

type swarmConfig struct {
	Docker        string `json:"docker"`
	Stack         string `json:"stack"`
	VerifySeconds int    `json:"verify_seconds"`
}

type transportConfig struct {
	Type           string `json:"type"` // sudo or ssh
	Host           string `json:"host"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	KeyFile        string `json:"key_file"`
	KnownHostsFile string `json:"known_hosts_file"`
}

type hostConfig struct {
	Agent          string                `json:"agent"`
	Recipient      string                `json:"recipient"`
	Transport      transportConfig       `json:"transport"`
	ComposeProject string                `json:"compose_project"`
	Reload         map[string][][]string `json:"reload"`
}

func strict(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

// NewFactory returns the TargetFactory of the daemon.
func NewFactory(fc FactoryConfig) TargetFactory {
	return func(ctx context.Context, t registry.Target) (target.Target, error) {
		switch t.Kind {
		case target.Swarm:
			var c swarmConfig
			if err := strict(t.Config, &c); err != nil {
				return nil, fmt.Errorf("swarm config: %w", err)
			}
			if c.Docker == "" {
				c.Docker = "unix:///var/run/docker.sock"
			}
			if !strings.HasPrefix(c.Docker, "unix://") && !fc.AllowTCPDocker {
				return nil, errors.New("swarm config: the Docker address must be a unix socket")
			}
			d, err := dockerapi.New(c.Docker)
			if err != nil {
				return nil, err
			}
			return swarm.New(d, swarm.Config{Name: t.Name, Stack: c.Stack, VerifyTimeout: time.Duration(c.VerifySeconds) * time.Second})
		case target.Docker, target.SSH:
			var c hostConfig
			if err := strict(t.Config, &c); err != nil {
				return nil, fmt.Errorf("%s config: %w", t.Kind, err)
			}
			tr, err := fc.transport(t, c.Transport)
			if err != nil {
				return nil, err
			}
			return host.New(host.Config{
				Name: t.Name, Kind: t.Kind, Agent: c.Agent, Recipient: c.Recipient, Signer: fc.BatchSigner,
				Transport: tr, ComposeProject: c.ComposeProject, Reload: c.Reload,
			})
		case target.K3s, target.K8s:
			return nil, fmt.Errorf("%w: %s", ErrStandby, t.Kind)
		}
		return nil, fmt.Errorf("unknown target kind %q", t.Kind)
	}
}

func (fc FactoryConfig) transport(t registry.Target, c transportConfig) (host.Transport, error) {
	if c.Type != "sudo" && c.Type != "ssh" {
		return nil, fmt.Errorf("transport type must be sudo or ssh, got %q", c.Type)
	}
	if fc.Transport != nil {
		return fc.Transport(t), nil
	}
	switch c.Type {
	case "sudo":
		return host.LocalSudo{}, nil
	case "ssh":
		key, err := fc.inSSHDir(c.KeyFile)
		if err != nil {
			return nil, err
		}
		kh, err := fc.inSSHDir(c.KnownHostsFile)
		if err != nil {
			return nil, err
		}
		return host.SSH{Host: c.Host, Port: c.Port, User: c.User, KeyFile: key, KnownHostsFile: kh}, nil
	}
	return nil, fmt.Errorf("transport type must be sudo or ssh, got %q", c.Type)
}

// inSSHDir resolves name inside SSHDir and refuses anything outside it.
func (fc FactoryConfig) inSSHDir(name string) (string, error) {
	if fc.SSHDir == "" {
		return "", errors.New("ssh transport: no SSH directory configured on the daemon")
	}
	if name == "" || filepath.IsAbs(name) || strings.Contains(name, "..") || strings.ContainsRune(name, '/') {
		return "", fmt.Errorf("ssh transport: %q must be a plain file name inside the daemon's SSH directory", name)
	}
	return filepath.Join(fc.SSHDir, name), nil
}
