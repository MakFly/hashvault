// Package daemoncli is the command line of hashvaultd.
//
//	hashvaultd init  --config FILE --admin human/NAME --admin-key KEY.pub --recipient R [--recipient R...] --bundle-out FILE
//	hashvaultd serve --config FILE [--allow-no-mlock]
//	hashvaultd version
//
// init runs the one-time ceremony against an empty OpenBao. serve starts
// sealed and waits for an operator to unseal it.
package daemoncli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"golang.org/x/sys/unix"

	"github.com/MakFly/hashvault/internal/agekeys"
	"github.com/MakFly/hashvault/internal/daemon"
	"github.com/MakFly/hashvault/internal/openbao"
	"github.com/MakFly/hashvault/internal/server"
)

// IO bundles the process plumbing.
type IO struct {
	Stdout, Stderr io.Writer
	Prompter       agekeys.Prompter
	// Ctx ends serve (SIGTERM in production).
	Ctx context.Context
	// Harden replaces the memory hardening (tests); nil means harden.
	Harden func(allowNoMlock bool, stderr io.Writer) error
}

// Main runs one command and returns the exit code.
func Main(args []string, io IO) int {
	if len(args) == 0 {
		fmt.Fprintln(io.Stderr, "usage: hashvaultd init|serve|version")
		return 2
	}
	var err error
	switch args[0] {
	case "version":
		fmt.Fprintln(io.Stdout, "hashvaultd", server.Version)
		return 0
	case "init":
		err = cmdInit(args[1:], io)
	case "serve":
		err = cmdServe(args[1:], io)
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		fmt.Fprintln(io.Stderr, "hashvaultd:", err)
		return 1
	}
	return 0
}

// LoadConfig reads the daemon configuration; unknown fields are refused.
func LoadConfig(path string) (daemon.Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-chosen path
	if err != nil {
		return daemon.Config{}, err
	}
	var c daemon.Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return daemon.Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	c.Defaults()
	return c, nil
}

func writeConfig(path string, c daemon.Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func cmdInit(args []string, io IO) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Stderr)
	cfgPath := fs.String("config", "/etc/hashvault/hashvaultd.json", "daemon configuration")
	admin := fs.String("admin", "", "first administrator, human/NAME")
	adminKey := fs.String("admin-key", "", "the administrator's FIDO2 public key file (sk-ssh-ed25519)")
	bundleOut := fs.String("bundle-out", "", "where to write the encrypted unseal bundle")
	var recipients multi
	fs.Var(&recipients, "recipient", "age recipient of the unseal bundle (repeat: hardware keys, offline key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *admin == "" || *adminKey == "" || *bundleOut == "" || len(recipients) == 0 {
		return errors.New("init needs --admin, --admin-key, --bundle-out and at least one --recipient")
	}
	if _, err := os.Stat(*bundleOut); err == nil {
		return fmt.Errorf("%s exists: refusing to overwrite an unseal bundle", *bundleOut)
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.RoleID != "" {
		return errors.New("the configuration already has a role_id: this vault was bootstrapped")
	}
	keyLine, err := os.ReadFile(*adminKey) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	var rs []age.Recipient
	for _, s := range recipients {
		r, err := agekeys.ParseRecipient(s, io.Prompter.UI())
		if err != nil {
			return fmt.Errorf("recipient %q: %w", s, err)
		}
		rs = append(rs, r)
	}
	bao, err := openbao.New(openbao.Config{Address: cfg.OpenBao})
	if err != nil {
		return err
	}
	ctx := io.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := daemon.Bootstrap(ctx, bao, daemon.BootstrapOptions{
		KVMount: cfg.KVMount, TransitMount: cfg.TransitMount, KEK: cfg.KEK, AppRoleMount: cfg.AppRoleMount, Role: cfg.Role,
		AdminName: *admin, AdminKey: strings.TrimSpace(string(keyLine)), Recipients: rs,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(*bundleOut, res.Bundle, 0o600); err != nil {
		return fmt.Errorf("the vault is initialised but the bundle could not be written (%w): the unseal key is lost, reinstall", err)
	}
	cfg.RoleID = res.RoleID
	if err := writeConfig(*cfgPath, cfg); err != nil {
		return err
	}
	fmt.Fprintf(io.Stdout, "vault %s initialised\n", cfg.VaultID)
	fmt.Fprintf(io.Stdout, "unseal bundle:        %s (keep copies offline)\n", *bundleOut)
	fmt.Fprintf(io.Stdout, "audit public key:     %s\n", base64.StdEncoding.EncodeToString(res.AuditKey))
	fmt.Fprintf(io.Stdout, "batch signing key:    %s  (hashvault-agent init --trusted-signer)\n", base64.StdEncoding.EncodeToString(res.BatchKey))
	return nil
}

// harden locks memory and disables core dumps; a daemon that cannot lock
// its memory refuses to start, unless explicitly allowed (development).
func harden(allowNoMlock bool, stderr io.Writer) error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE): %w", err)
	}
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		if !allowNoMlock {
			return fmt.Errorf("mlockall: %w (raise LimitMEMLOCK, or --allow-no-mlock for development)", err)
		}
		fmt.Fprintln(stderr, "hashvaultd: WARNING: memory not locked (--allow-no-mlock): secrets may reach swap")
	}
	return nil
}

func cmdServe(args []string, io IO) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Stderr)
	cfgPath := fs.String("config", "/etc/hashvault/hashvaultd.json", "daemon configuration")
	allowNoMlock := fs.Bool("allow-no-mlock", false, "start even if memory cannot be locked (development only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	h := io.Harden
	if h == nil {
		h = harden
	}
	if err := h(*allowNoMlock, io.Stderr); err != nil {
		return err
	}
	d, err := daemon.New(cfg, nil)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Listen), 0o750); err != nil {
		return err
	}
	if err := os.Remove(cfg.Listen); err != nil && !os.IsNotExist(err) {
		return err
	}
	l, err := net.Listen("unix", cfg.Listen)
	if err != nil {
		return err
	}
	// 0660: the hashvault group holds the operator and helper accounts; the
	// kernel-reported peer uid still decides what each of them may do.
	if err := os.Chmod(cfg.Listen, 0o660); err != nil { // #nosec G302
		_ = l.Close()
		return err
	}
	hs := &http.Server{
		Handler: d, ConnContext: server.ConnContext,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, WriteTimeout: 10 * time.Minute, IdleTimeout: time.Minute,
		MaxHeaderBytes: 16 << 10,
	}
	ctx := io.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	go d.RunIdleSeal(ctx, 30*time.Second)
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(l) }()
	fmt.Fprintf(io.Stderr, "hashvaultd: serving %s (sealed)\n", cfg.Listen)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = hs.Shutdown(shutdown)
	return d.Seal(shutdown, "shutdown")
}
