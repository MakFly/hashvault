// Command hashvault-local owns the persistent development vault used by make dev.
// It is excluded from release packaging and never reads production configuration.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/MakFly/hashvault/internal/cli"
	"github.com/MakFly/hashvault/internal/daemon"
	"github.com/MakFly/hashvault/internal/openbao"
	"github.com/MakFly/hashvault/internal/registry"
	"github.com/MakFly/hashvault/internal/secrets"
	"github.com/MakFly/hashvault/internal/server"
)

const localPrincipal = "machine/dev-local"

type credentials struct {
	UnsealKey string `json:"unseal_key"`
	RootToken string `json:"bootstrap_token,omitempty"`
	SecretID  string `json:"secret_id,omitempty"`
	RoleID    string `json:"role_id,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fs := flag.NewFlagSet("hashvault-local", flag.ExitOnError)
	dir := fs.String("state", "", "private development state directory")
	bao := fs.String("bao", "", "checksum-verified OpenBao binary")
	_ = fs.Parse(os.Args[1:])
	if *dir == "" || *bao == "" {
		fmt.Fprintln(os.Stderr, "hashvault-local: --state and --bao are required")
		os.Exit(2)
	}
	if err := run(ctx, *dir, *bao); err != nil {
		// Underlying responses can contain credentials. Report only the stage.
		fmt.Fprintln(os.Stderr, "hashvault-local:", err)
		os.Exit(1)
	}
}

// save atomically replaces private state, including the bridge's short-lived token.
func save(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".local-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func saveCredentials(dir string, c credentials) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	defer clear(data)
	return save(filepath.Join(dir, "credentials.json"), data)
}

// bootstrap is resumable: a temporary root token survives only an interrupted
// local setup. Once the AppRole is ready it is revoked and removed from disk.
func bootstrap(ctx context.Context, bao *openbao.Client, dir string) (credentials, error) {
	var c credentials
	path := filepath.Join(dir, "credentials.json")
	data, err := os.ReadFile(path) // #nosec G304 -- private development state
	if err == nil {
		err = json.Unmarshal(data, &c)
		clear(data)
		if err != nil || c.UnsealKey == "" || (c.RootToken == "" && (c.SecretID == "" || c.RoleID == "")) {
			return c, errors.New("invalid local credentials; preserve the state directory for recovery")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		st, err := bao.SealStatus(ctx)
		if err != nil || st.Initialized {
			return c, errors.New("local storage already initialized without its credentials")
		}
		init, err := bao.Init(ctx, 1, 1)
		if err != nil {
			return c, errors.New("local OpenBao initialization failed")
		}
		c.UnsealKey, c.RootToken = init.KeysB64[0], init.RootToken
		if err := saveCredentials(dir, c); err != nil {
			return c, errors.New("cannot persist local initialization credentials")
		}
	} else {
		return c, errors.New("cannot read local credentials")
	}
	if _, err := bao.Unseal(ctx, c.UnsealKey); err != nil {
		return c, errors.New("local unseal failed")
	}
	if err := bao.WaitActive(ctx, 30*time.Second); err != nil {
		return c, errors.New("local OpenBao did not become active")
	}
	if c.RootToken == "" {
		return c, nil
	}
	// A completed bootstrap may have been interrupted between root revocation
	// and the final atomic credential write. Prove the AppRole works first.
	if c.RoleID != "" && c.SecretID != "" {
		if _, err := bao.AppRoleLogin(ctx, "approle", c.RoleID, c.SecretID); err != nil {
			return c, errors.New("cannot recover local AppRole")
		}
		bao.SetToken(c.RootToken)
		if err := bao.RevokeSelf(ctx); err != nil {
			var api *openbao.APIError
			if !errors.As(err, &api) || api.Status != http.StatusForbidden {
				return c, errors.New("cannot revoke recovered bootstrap token")
			}
		}
		c.RootToken = ""
		bao.SetToken("")
		if err := saveCredentials(dir, c); err != nil {
			return c, errors.New("cannot persist recovered AppRole")
		}
		return c, nil
	}
	bao.SetToken(c.RootToken)
	// Mount creation is retried after an interrupted bootstrap. Only the exact
	// existing-mount conflict is accepted; other failures remain fatal.
	acceptMounted := func(err error) error {
		var api *openbao.APIError
		if errors.As(err, &api) && api.Status == 400 && len(api.Errors) == 1 && (api.Errors[0] == "path is already in use at hv/" || api.Errors[0] == "path is already in use at transit/" || api.Errors[0] == "path is already in use at approle/") {
			return nil
		}
		return err
	}
	steps := []func() error{
		func() error { return acceptMounted(bao.Mount(ctx, "hv", "kv", map[string]string{"version": "2"})) },
		func() error { return acceptMounted(bao.Mount(ctx, "transit", "transit", nil)) },
		func() error { return bao.TransitCreateKey(ctx, "transit", "hv-kek-local", "chacha20-poly1305") },
		func() error { return acceptMounted(bao.EnableAuth(ctx, "approle", "approle")) },
		func() error {
			return bao.PutACLPolicy(ctx, "hashvault-local", `path "hv/data/*" { capabilities = ["create", "read", "update"] }
path "hv/metadata/*" { capabilities = ["read", "list"] }
path "hv/destroy/*" { capabilities = ["update"] }
path "transit/datakey/plaintext/hv-kek-local" { capabilities = ["update"] }
path "transit/decrypt/hv-kek-local" { capabilities = ["update"] }
path "transit/rewrap/hv-kek-local" { capabilities = ["update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "sys/seal" { capabilities = ["update", "sudo"] }`)
		},
		func() error {
			return bao.AppRoleWrite(ctx, "approle", "hashvault-local", map[string]any{"token_policies": []string{"hashvault-local"}, "token_period": "1h", "token_type": "service", "secret_id_num_uses": 0, "bind_secret_id": true})
		},
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return c, errors.New("local OpenBao provisioning failed")
		}
	}
	store := secrets.New(bao, "hv", openbao.NewTransitWrapper(bao, "transit", "hv-kek-local"))
	// KV v2 mount initialization is asynchronous. A read probes its readiness.
	for {
		_, _, err := store.Get(ctx, daemon.AuditKeyRef, 0)
		if err == nil || errors.Is(err, secrets.ErrNotFound) {
			break
		}
		select {
		case <-ctx.Done():
			return c, errors.New("local KV mount did not become ready")
		case <-time.After(100 * time.Millisecond):
		}
	}
	for _, ref := range []secrets.Ref{daemon.AuditKeyRef, daemon.BatchKeyRef} {
		value, _, err := store.Get(ctx, ref, 0)
		clear(value)
		if err == nil {
			continue
		}
		if !errors.Is(err, secrets.ErrNotFound) {
			return c, errors.New("cannot inspect local signing keys")
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return c, errors.New("cannot generate local signing keys")
		}
		_, err = store.Put(ctx, ref, priv)
		clear(priv)
		if err != nil {
			return c, errors.New("cannot persist local signing keys")
		}
	}
	keyPath := filepath.Join(dir, "login-key")
	keyData, err := os.ReadFile(keyPath) // #nosec G304 -- private development state
	if errors.Is(err, os.ErrNotExist) {
		_, priv, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return c, errors.New("cannot generate local login key")
		}
		block, genErr := ssh.MarshalPrivateKey(priv, "hashvault local development")
		clear(priv)
		if genErr != nil {
			return c, errors.New("cannot encode local login key")
		}
		keyData = pem.EncodeToMemory(block)
		err = save(keyPath, keyData)
	}
	if err != nil {
		return c, errors.New("cannot read or persist local login key")
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	clear(keyData)
	if err != nil {
		return c, errors.New("invalid local login key")
	}
	reg := registry.New(bao, "hv")
	// The machine session has no MFA claim. Local grants never reach the host's
	// Docker or SSH adapters: the development daemon refuses those operations.
	if err := reg.PutPolicy(ctx, "local-admin", []byte(`{"Version":"hv-1","Statement":[{"Effect":"Allow","Action":"*","Resource":"hv:*"}]}`)); err != nil {
		return c, errors.New("cannot persist local policy")
	}
	if err := reg.PutPrincipal(ctx, registry.Principal{Name: localPrincipal, SSHKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), Policies: []string{"local-admin"}}); err != nil {
		return c, errors.New("cannot persist local principal")
	}
	if c.RoleID, err = bao.AppRoleRoleID(ctx, "approle", "hashvault-local"); err != nil {
		return c, errors.New("cannot read local AppRole")
	}
	if c.SecretID == "" {
		if c.SecretID, err = bao.AppRoleSecretID(ctx, "approle", "hashvault-local"); err != nil {
			return c, errors.New("cannot create local AppRole credential")
		}
	}
	if err := saveCredentials(dir, c); err != nil {
		return c, errors.New("cannot persist local AppRole")
	}
	if err := bao.RevokeSelf(ctx); err != nil {
		return c, errors.New("cannot revoke local bootstrap token")
	}
	c.RootToken = ""
	if err := saveCredentials(dir, c); err != nil {
		return c, errors.New("cannot remove revoked bootstrap token")
	}
	bao.SetToken("")
	return c, nil
}

func run(ctx context.Context, state, binary string) error {
	dir, err := filepath.Abs(state)
	if err != nil {
		return errors.New("invalid local state directory")
	}
	if len(filepath.Join(dir, "bao.sock")) > 100 {
		return errors.New("local state path too long for Unix sockets")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("cannot create local state directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- owner-only directory needs traversal permission
		return errors.New("cannot protect local state directory")
	}
	lock, err := os.OpenFile(filepath.Join(dir, "running.lock"), os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- private development state
	if err != nil {
		return errors.New("cannot lock local state")
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("local vault already owned; stop its launcher before retrying")
	}
	for _, name := range []string{"bao.sock", "api.sock", "token", "ready"} {
		_ = os.Remove(filepath.Join(dir, name))
	}
	defer func() {
		for _, name := range []string{"bao.sock", "api.sock", "token", "ready"} {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o700); err != nil {
		return errors.New("cannot create local Raft storage")
	}
	cluster, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.New("cannot select local cluster port")
	}
	clusterAddress := cluster.Addr().String()
	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = cluster.Close()
		return errors.New("cannot select local OpenBao port")
	}
	apiAddress := apiListener.Addr().String()
	_ = apiListener.Close()
	_ = cluster.Close()
	config, err := json.Marshal(map[string]any{
		"storage":  map[string]any{"raft": map[string]string{"path": filepath.Join(dir, "data"), "node_id": "hashvault-local"}},
		"listener": map[string]any{"tcp": map[string]any{"address": apiAddress, "cluster_address": clusterAddress, "tls_disable": true}},
		"api_addr": "http://" + apiAddress, "cluster_addr": "http://" + clusterAddress,
	})
	if err != nil || save(filepath.Join(dir, "bao.json"), config) != nil {
		return errors.New("cannot write local OpenBao configuration")
	}
	baoCtx, stopBao := context.WithCancel(context.Background())
	defer stopBao()
	cmd := exec.CommandContext(baoCtx, binary, "server", "-config="+filepath.Join(dir, "bao.json")) // #nosec G204 -- explicit local tooling binary, fixed arguments
	cmd.Env = []string{"HOME=" + dir, "PATH=" + os.Getenv("PATH")}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	logs, err := os.OpenFile(filepath.Join(dir, "bao.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- private local diagnostics
	if err != nil {
		return errors.New("cannot open local OpenBao diagnostics")
	}
	defer logs.Close()
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		return errors.New("cannot start local OpenBao")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	defer func() { stopBao(); <-done }()
	bao, err := openbao.New(openbao.Config{Address: "http://" + apiAddress, Timeout: 30 * time.Second})
	if err != nil {
		return errors.New("invalid local OpenBao address")
	}
	startup, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		if _, err := bao.SealStatus(startup); err == nil {
			break
		}
		select {
		case <-done:
			return errors.New("local OpenBao exited before readiness")
		case <-startup.Done():
			return errors.New("local OpenBao startup timed out")
		case <-time.After(100 * time.Millisecond):
		}
	}
	c, err := bootstrap(startup, bao, dir)
	if err != nil {
		return err
	}
	d, err := daemon.New(daemon.Config{VaultID: "hashvault-local", OpenBao: "http://" + apiAddress, RoleID: c.RoleID, Role: "hashvault-local", KEK: "hv-kek-local", AuditPath: filepath.Join(dir, "audit.jsonl"), SSHDir: filepath.Join(dir, "ssh"), IdleSealMinutes: -1}, nil)
	if err != nil {
		return errors.New("cannot configure local API")
	}
	if err := d.Unseal(startup, daemon.Bundle{UnsealKey: c.UnsealKey, SecretID: c.SecretID}); err != nil {
		return errors.New("cannot open local API")
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.Seal(shutdown, "local development stopped")
	}()
	l, err := net.Listen("unix", filepath.Join(dir, "api.sock"))
	if err != nil {
		return errors.New("cannot listen on local API socket")
	}
	if err := os.Chmod(filepath.Join(dir, "api.sock"), 0o600); err != nil {
		_ = l.Close()
		return errors.New("cannot protect local API socket")
	}
	// Local development exercises the real IAM, audit, encryption and API.
	// Publication adapters stay outside this automatic local setup.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (r.URL.Path == "/v1/publish" || r.URL.Path == "/v1/preparations") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"Deployment requires an explicitly configured vault; the automatic local vault does not access Docker or SSH."}`)
			return
		}
		d.ServeHTTP(w, r)
	})
	httpServer := &http.Server{Handler: handler, ConnContext: server.ConnContext, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	served := make(chan error, 1)
	go func() { served <- httpServer.Serve(l) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
		_ = l.Close()
	}()
	login := func() error {
		tmp := filepath.Join(dir, "token.next")
		defer os.Remove(tmp)
		getenv := func(name string) string {
			switch name {
			case "HASHVAULT_SOCKET":
				return filepath.Join(dir, "api.sock")
			case "HASHVAULT_TOKEN_FILE":
				return tmp
			default:
				return ""
			}
		}
		if cli.Main([]string{"login", "--principal", localPrincipal, "--key", filepath.Join(dir, "login-key")}, cli.IO{Context: ctx, Stdin: nil, Stdout: io.Discard, Stderr: io.Discard, Getenv: getenv}) != 0 {
			return errors.New("local machine authentication failed")
		}
		token, err := os.ReadFile(tmp) // #nosec G304 -- private local session token
		if err != nil {
			return errors.New("cannot read local machine session")
		}
		defer clear(token)
		if err := save(filepath.Join(dir, "token"), token); err != nil {
			return errors.New("cannot persist local machine session")
		}
		return nil
	}
	if err := login(); err != nil {
		return err
	}
	if err := save(filepath.Join(dir, "ready"), fmt.Appendf(nil, "%d\n", os.Getpid())); err != nil {
		return errors.New("cannot signal local readiness")
	}
	fmt.Println("[local] hashvault-local ready (machine/dev-local); data retained in .tools/dev-vault")
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-done:
			return errors.New("local OpenBao stopped unexpectedly")
		case <-served:
			return errors.New("local API stopped unexpectedly")
		case <-ticker.C:
			if d.Sealed() {
				continue
			}
			if err := login(); err != nil {
				return err
			}
		}
	}
}
