// Package agentcli is the command line of hashvault-agent, the root helper
// installed on Docker and SSH-deployed hosts.
//
//	hashvault-agent init --agent NAME --trusted-signer KEY   create identity and config
//	hashvault-agent recipient                               print the public recipient
//	hashvault-agent receive                                 apply a batch read on stdin
//	hashvault-agent materialize [--app APP]                 rebuild tmpfs copies (boot)
//	hashvault-agent exec --app APP --service SVC -- CMD...  run CMD with the env items
//	hashvault-agent version
//
// receive is what the vault runs, through `sudo -n` locally or an SSH key
// restricted to that command. It prints a JSON receipt and never a value.
package agentcli

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/MakFly/hashvault/internal/batch"
	"github.com/MakFly/hashvault/internal/dockerapi"
	"github.com/MakFly/hashvault/internal/hostagent"
)

// Version is set at build time.
var Version = "dev"

// DefaultConfig is where the agent reads its configuration.
const DefaultConfig = "/etc/hashvault-agent/config.json"

// Config is the agent configuration file.
type Config struct {
	Agent         string   `json:"agent"`
	IdentityFile  string   `json:"identity_file"`
	TrustedSigner string   `json:"trusted_signer"`
	CredstoreDir  string   `json:"credstore_dir"`
	RuntimeDir    string   `json:"runtime_dir"`
	StateDir      string   `json:"state_dir"`
	DockerSocket  string   `json:"docker_socket,omitempty"`
	SealerCommand []string `json:"sealer_command,omitempty"`
}

func (c *Config) defaults(dir string) {
	if c.IdentityFile == "" {
		c.IdentityFile = filepath.Join(dir, "identity.age")
	}
	if c.CredstoreDir == "" {
		c.CredstoreDir = "/etc/credstore.encrypted"
	}
	if c.RuntimeDir == "" {
		c.RuntimeDir = "/run/hashvault"
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/hashvault-agent"
	}
	if len(c.SealerCommand) == 0 {
		c.SealerCommand = []string{"systemd-creds"}
	}
}

// IO bundles the process plumbing, so tests can drive the CLI.
type IO struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// Exec replaces the process; syscall.Exec in production.
	Exec func(argv0 string, argv []string, envv []string) error
	// Environ is the current environment.
	Environ []string
	// Agent overrides parts of the host agent configuration (tests).
	Agent func(*hostagent.Config)
}

// Main runs one command and returns the exit code.
func Main(args []string, io IO) int {
	if len(args) == 0 {
		fmt.Fprintln(io.Stderr, "usage: hashvault-agent init|recipient|receive|materialize|exec|version")
		return 2
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "version":
		fmt.Fprintln(io.Stdout, "hashvault-agent", Version)
		return 0
	case "init":
		err = cmdInit(rest, io)
	case "recipient":
		err = cmdRecipient(rest, io)
	case "receive":
		return cmdReceive(rest, io)
	case "materialize":
		err = cmdMaterialize(rest, io)
	case "exec":
		err = cmdExec(rest, io)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(io.Stderr, "hashvault-agent:", err)
		return 1
	}
	return 0
}

func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", DefaultConfig, "configuration file")
}

// loadConfig reads the configuration and refuses files others could change
// or, for the identity, read.
func loadConfig(path string) (Config, error) {
	if err := checkPrivate(path, 0o022); err != nil {
		return Config{}, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-chosen path
	if err != nil {
		return Config{}, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	c.defaults(filepath.Dir(path))
	if c.Agent == "" {
		return Config{}, errors.New("config: agent name missing")
	}
	last := c.SealerCommand[len(c.SealerCommand)-1]
	if filepath.Base(last) != "systemd-creds" {
		return Config{}, fmt.Errorf("config: sealer_command must end with systemd-creds, got %q", last)
	}
	return c, nil
}

// checkPrivate refuses a file whose mode grants any bit in forbidden.
func checkPrivate(path string, forbidden os.FileMode) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&forbidden != 0 {
		return fmt.Errorf("%s has mode %04o: refusing a file others can %s", path, st.Mode().Perm(), map[bool]string{true: "read", false: "write"}[forbidden&0o044 != 0])
	}
	return nil
}

func (c Config) identity() (*age.HybridIdentity, error) {
	if err := checkPrivate(c.IdentityFile, 0o077); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(c.IdentityFile)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return age.ParseHybridIdentity(strings.TrimSpace(string(data)))
}

func (c Config) signer() (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.DecodeString(c.TrustedSigner)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("config: trusted_signer must be a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(key), nil
}

func (c Config) agent(io IO) (*hostagent.Agent, error) {
	cons := hostagent.HostConsumers{}
	if c.DockerSocket != "" {
		d, err := dockerapi.New(c.DockerSocket)
		if err != nil {
			return nil, err
		}
		cons.Docker = d
	}
	hc := hostagent.Config{
		CredstoreDir: c.CredstoreDir,
		RuntimeDir:   c.RuntimeDir,
		StateDir:     c.StateDir,
		Sealer:       hostagent.SystemdCreds{Command: c.SealerCommand},
		Consumers:    cons,
	}
	if io.Agent != nil {
		io.Agent(&hc)
	}
	return hostagent.New(hc)
}

func cmdInit(args []string, io IO) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Stderr)
	cfgPath := configFlag(fs)
	name := fs.String("agent", "", "agent name, as registered in the vault")
	signer := fs.String("trusted-signer", "", "base64 Ed25519 public key of the vault")
	docker := fs.String("docker-socket", "", "Docker socket for compose consumers, e.g. unix:///var/run/docker.sock")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*cfgPath); err == nil {
		return fmt.Errorf("%s exists: refusing to replace an enrolled identity", *cfgPath)
	}
	c := Config{Agent: *name, TrustedSigner: *signer, DockerSocket: *docker}
	c.defaults(filepath.Dir(*cfgPath))
	if _, err := c.signer(); err != nil {
		return err
	}
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*cfgPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(c.IdentityFile, []byte(id.String()+"\n"), 0o600); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*cfgPath, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if _, err := loadConfig(*cfgPath); err != nil {
		return err
	}
	fmt.Fprintln(io.Stdout, id.Recipient().String())
	return nil
}

func cmdRecipient(args []string, io IO) error {
	fs := flag.NewFlagSet("recipient", flag.ContinueOnError)
	fs.SetOutput(io.Stderr)
	cfgPath := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	id, err := c.identity()
	if err != nil {
		return err
	}
	fmt.Fprintln(io.Stdout, id.Recipient().String())
	return nil
}

func cmdReceive(args []string, io IO) int {
	fs := flag.NewFlagSet("receive", flag.ContinueOnError)
	fs.SetOutput(io.Stderr)
	cfgPath := configFlag(fs)
	fail := func(err error) int {
		r := hostagent.Receipt{Status: hostagent.Refused, Error: err.Error(), At: time.Now().UTC()}
		_ = json.NewEncoder(io.Stdout).Encode(r)
		return 1
	}
	if err := fs.Parse(args); err != nil {
		return fail(err)
	}
	c, err := loadConfig(*cfgPath)
	if err != nil {
		return fail(err)
	}
	id, err := c.identity()
	if err != nil {
		return fail(err)
	}
	signer, err := c.signer()
	if err != nil {
		return fail(err)
	}
	a, err := c.agent(io)
	if err != nil {
		return fail(err)
	}
	data, err := readLimited(io.Stdin, 8<<20)
	if err != nil {
		return fail(err)
	}
	r := a.Receive(context.Background(), data, func(d []byte) (batch.Batch, error) {
		return batch.Open(d, id, signer, c.Agent, time.Now())
	})
	_ = json.NewEncoder(io.Stdout).Encode(r)
	if r.Status != hostagent.Applied {
		return 1
	}
	return 0
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("input larger than %d bytes", limit)
	}
	return data, nil
}

func cmdMaterialize(args []string, io IO) error {
	fs := flag.NewFlagSet("materialize", flag.ContinueOnError)
	fs.SetOutput(io.Stderr)
	cfgPath := configFlag(fs)
	app := fs.String("app", "", "only this app (default: every app)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	a, err := c.agent(io)
	if err != nil {
		return err
	}
	if *app != "" {
		return a.Materialize(context.Background(), *app)
	}
	return a.MaterializeAll(context.Background())
}

func cmdExec(args []string, io IO) error {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(io.Stderr)
	cfgPath := configFlag(fs)
	app := fs.String("app", "", "app")
	service := fs.String("service", "", "service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if *app == "" || *service == "" || len(argv) == 0 {
		return errors.New("usage: exec --app APP --service SVC -- CMD [ARG...]")
	}
	if !filepath.IsAbs(argv[0]) {
		return fmt.Errorf("exec needs an absolute program path, got %q", argv[0])
	}
	c, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	a, err := c.agent(io)
	if err != nil {
		return err
	}
	pairs, err := a.Env(context.Background(), *app, *service)
	if err != nil {
		return err
	}
	env := make([]string, 0, len(io.Environ)+len(pairs))
	secretKeys := map[string]bool{}
	for _, p := range pairs {
		k, _, _ := strings.Cut(string(p), "=")
		secretKeys[k] = true
	}
	for _, kv := range io.Environ {
		k, _, _ := strings.Cut(kv, "=")
		if !secretKeys[k] {
			env = append(env, kv)
		}
	}
	for _, p := range pairs {
		env = append(env, string(p))
		clear(p)
	}
	return io.Exec(argv[0], argv, env)
}
