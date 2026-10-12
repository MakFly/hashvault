// Package cli is the operator command line, `hashvault`.
//
// It talks to hashvaultd's unix socket, usually reached through an SSH
// tunnel: ssh -L /tmp/hv.sock:/run/hashvault/api.sock ops@vault, then
// HASHVAULT_SOCKET=/tmp/hv.sock. Secret values are read from stdin or a
// file, never from the command line (shell history, ps).
package cli

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
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/MakFly/hashvault/internal/agekeys"
	"github.com/MakFly/hashvault/internal/authn"
	"github.com/MakFly/hashvault/internal/daemon"
	"github.com/MakFly/hashvault/internal/dotenv"
)

// Version is set at build time.
var Version = "dev"

// IO bundles the process plumbing, so tests can drive the CLI.
type IO struct {
	// Context ends long-running CLI commands; nil uses process signals.
	Context        context.Context
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Prompter       agekeys.Prompter
}

const usage = `usage: hashvault <command>

  status                                   vault state
  login    --principal NAME --key FILE     sign a challenge (touch your key)
  logout
  secret   put ENV/APP/KEY [--file F]      value from stdin or a file
  secret   get ENV/APP/KEY [--version N]
  secret   list ENV/APP
  secret   destroy ENV/APP/KEY --version N
  secret   rewrap ENV/APP/KEY
  import   dotenv FILE --env ENV --app APP [--dry-run]
  policy   put NAME FILE | get NAME
  principal create NAME --key FILE [--tag k=v] | get NAME | disable NAME
  principal attach NAME POLICY [--boundary] [--detach]
  iam      simulate --principal P --action A --resource R [--context k=v]
  target   put FILE | list
  publish  --target T --manifest FILE [--version KEY=N] [--rollback] [--dry-run]
  prepare  --target T --manifest FILE [--version KEY=N] [--output FILE]
  preparation get ID | list --target T --app APP
  confirm  ID --release RELEASE [--previous ID]
  publication --target T --app APP
  render   FILE --format json|stack|compose|systemd [--service SVC]
  ui       [--assets DIR] [--listen 127.0.0.1:8822]
  audit    verify
  unseal   --bundle FILE --identity FILE
  seal
  version
`

// Main runs one command and returns the exit code.
func Main(args []string, o IO) int {
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if len(args) == 0 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	c := &client{io: o}
	var err error
	switch args[0] {
	case "version":
		fmt.Fprintln(o.Stdout, "hashvault", Version)
		return 0
	case "status":
		err = c.status()
	case "login":
		err = c.login(args[1:])
	case "logout":
		err = c.logout()
	case "secret":
		err = c.secret(args[1:])
	case "import":
		err = c.importCmd(args[1:])
	case "policy":
		err = c.policy(args[1:])
	case "principal":
		err = c.principal(args[1:])
	case "iam":
		err = c.iam(args[1:])
	case "target":
		err = c.target(args[1:])
	case "publish":
		err = c.publish(args[1:])
	case "prepare":
		err = c.prepare(args[1:])
	case "preparation":
		err = c.preparation(args[1:])
	case "confirm":
		err = c.confirm(args[1:])
	case "publication":
		err = c.publication(args[1:])
	case "ui":
		err = c.ui(args[1:])
	case "render":
		err = c.render(args[1:])
	case "audit":
		err = c.audit(args[1:])
	case "unseal":
		err = c.unseal(args[1:])
	case "seal":
		_, err = c.call("POST", "/v1/sys/seal", nil, true)
	default:
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(o.Stderr, "hashvault:", err)
		return 1
	}
	return 0
}

// ---- Transport -----------------------------------------------------------------

type client struct {
	io IO
}

func (c *client) socket() string {
	if s := c.io.Getenv("HASHVAULT_SOCKET"); s != "" {
		return s
	}
	return "/run/hashvault/api.sock"
}

// tokenFile lives on tmpfs when possible ($XDG_RUNTIME_DIR): a token is a
// credential for 15 minutes.
func (c *client) tokenFile() string {
	if f := c.io.Getenv("HASHVAULT_TOKEN_FILE"); f != "" {
		return f
	}
	if d := c.io.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "hashvault", "token")
	}
	return filepath.Join(c.io.Getenv("HOME"), ".cache", "hashvault", "token")
}

type apiError struct {
	status int
	msg    string
}

func (e apiError) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.msg, e.status) }

// call sends a request; body is JSON-encoded unless it is []byte.
func (c *client) call(method, path string, body any, auth bool) (map[string]any, error) {
	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		reader = bytes.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, "http://hashvault"+path, reader)
	if err != nil {
		return nil, err
	}
	if auth {
		tok, err := os.ReadFile(c.tokenFile())
		if err != nil {
			return nil, errors.New("not logged in: run hashvault login")
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	hc := &http.Client{Timeout: 15 * time.Minute, Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", c.socket())
		},
	}}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach hashvaultd at %s: %w", c.socket(), err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("unexpected answer (HTTP %d)", resp.StatusCode)
		}
	}
	if resp.StatusCode >= 300 {
		msg, _ := out["error"].(string)
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return out, apiError{status: resp.StatusCode, msg: msg}
	}
	return out, nil
}

func (c *client) printJSON(v any) error {
	enc := json.NewEncoder(c.io.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newFlags(name string, o IO) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(o.Stderr)
	return fs
}

// parseInterspersed lets flags follow positional arguments, as operators type them.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// ---- Commands -------------------------------------------------------------------

func (c *client) status() error {
	out, err := c.call("GET", "/v1/sys/status", nil, false)
	if err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *client) login(args []string) error {
	fs := newFlags("login", c.io)
	principal := fs.String("principal", "", "principal name, e.g. human/alice")
	key := fs.String("key", "", "SSH key file (FIDO2 key handle or private key), as for ssh -i")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *principal == "" || *key == "" {
		return errors.New("login needs --principal and --key")
	}
	ch, err := c.call("POST", "/v1/auth/challenge", map[string]string{"principal": *principal}, false)
	if err != nil {
		return err
	}
	msg, _ := ch["message"].(string)
	id, _ := ch["id"].(string)
	fmt.Fprintln(c.io.Stderr, "signing the login challenge: touch your security key if it blinks")
	sig, err := sshSign(*key, []byte(msg))
	if err != nil {
		return err
	}
	out, err := c.call("POST", "/v1/auth/login", map[string]string{"id": id, "principal": *principal, "signature": string(sig)}, false)
	if err != nil {
		return err
	}
	token, _ := out["token"].(string)
	path := c.tokenFile()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(c.io.Stderr, "logged in as %s until %v (mfa: %v)\n", *principal, out["expires_at"], out["mfa"])
	return nil
}

// sshSign runs `ssh-keygen -Y sign`: the same tool that handles FIDO2 keys,
// PINs and touches, and ssh-agent.
func sshSign(key string, msg []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "hashvault-login-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "challenge")
	if err := os.WriteFile(file, msg, 0o600); err != nil {
		return nil, err
	}
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-q", "-n", authn.Namespace, "-f", key, file) // #nosec G204 -- key path chosen by the operator
	cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ssh-keygen -Y sign: %w", err)
	}
	return os.ReadFile(file + ".sig") // #nosec G304 -- inside the temporary directory created above
}

func (c *client) logout() error {
	_, err := c.call("POST", "/v1/auth/logout", nil, true)
	_ = os.Remove(c.tokenFile())
	// A token the vault no longer knows (expired, or the vault was sealed
	// since) is already logged out.
	var api apiError
	if errors.As(err, &api) && api.status == http.StatusUnauthorized {
		return nil
	}
	return err
}

var coordinates = regexp.MustCompile(`^([a-z][a-z0-9-]*)/([a-z0-9][a-z0-9-]*)(?:/([A-Z][A-Z0-9_]*))?$`)

func splitRef(s string, wantKey bool) (env, app, key string, err error) {
	m := coordinates.FindStringSubmatch(s)
	if m == nil || (wantKey && m[3] == "") || (!wantKey && m[3] != "") {
		form := "ENV/APP"
		if wantKey {
			form = "ENV/APP/KEY"
		}
		return "", "", "", fmt.Errorf("expected %s, got %q", form, s)
	}
	return m[1], m[2], m[3], nil
}

func (c *client) secret(args []string) error {
	if len(args) == 0 {
		return errors.New("secret put|get|list|destroy|rewrap")
	}
	sub, args := args[0], args[1:]
	fs := newFlags("secret "+sub, c.io)
	file := fs.String("file", "", "read the value from this file instead of stdin")
	version := fs.Uint64("version", 0, "version")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("secret %s needs one ENV/APP[/KEY] argument", sub)
	}
	if sub == "list" {
		env, app, _, err := splitRef(pos[0], false)
		if err != nil {
			return err
		}
		out, err := c.call("GET", "/v1/secrets/"+env+"/"+app, nil, true)
		if err != nil {
			return err
		}
		for _, k := range out["keys"].([]any) {
			fmt.Fprintln(c.io.Stdout, k)
		}
		return nil
	}
	env, app, key, err := splitRef(pos[0], true)
	if err != nil {
		return err
	}
	path := "/v1/secrets/" + env + "/" + app + "/" + key
	switch sub {
	case "put":
		var value []byte
		if *file != "" {
			value, err = os.ReadFile(*file)
		} else {
			value, err = io.ReadAll(io.LimitReader(c.io.Stdin, 1<<20+1))
		}
		if err != nil {
			return err
		}
		defer clear(value)
		out, err := c.call("PUT", path, map[string]string{"value": base64.StdEncoding.EncodeToString(value)}, true)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.io.Stderr, "%s stored as version %v\n", pos[0], out["version"])
		return nil
	case "get":
		q := ""
		if *version > 0 {
			q = "?version=" + strconv.FormatUint(*version, 10)
		}
		out, err := c.call("GET", path+q, nil, true)
		if err != nil {
			return err
		}
		value, err := base64.StdEncoding.DecodeString(out["value"].(string))
		if err != nil {
			return err
		}
		defer clear(value)
		_, err = c.io.Stdout.Write(value)
		return err
	case "destroy":
		if *version == 0 {
			return errors.New("secret destroy needs --version")
		}
		_, err := c.call("DELETE", path+"/versions/"+strconv.FormatUint(*version, 10), nil, true)
		if err == nil {
			fmt.Fprintf(c.io.Stderr, "%s version %d destroyed\n", pos[0], *version)
		}
		return err
	case "rewrap":
		out, err := c.call("POST", path+"/rewrap", nil, true)
		if err == nil {
			fmt.Fprintf(c.io.Stderr, "%s: %v version(s) rewrapped\n", pos[0], out["rewrapped"])
		}
		return err
	}
	return fmt.Errorf("unknown secret command %q", sub)
}

var secretKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

// importCmd stores every variable of a .env as a secret. Keys are checked
// first: nothing is stored unless the whole file can be.
func (c *client) importCmd(args []string) error {
	if len(args) == 0 || args[0] != "dotenv" {
		return errors.New("import dotenv FILE --env ENV --app APP [--dry-run]")
	}
	fs := newFlags("import dotenv", c.io)
	env := fs.String("env", "", "environment")
	app := fs.String("app", "", "app")
	dry := fs.Bool("dry-run", false, "list what would be imported")
	pos, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) != 1 || *env == "" || *app == "" {
		return errors.New("import dotenv FILE --env ENV --app APP [--dry-run]")
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	defer clear(data)
	entries, err := dotenv.Parse(data)
	if err != nil {
		return err
	}
	var invalid []string
	for _, e := range entries {
		if !secretKey.MatchString(e.Key) {
			invalid = append(invalid, fmt.Sprintf("%s (line %d)", e.Key, e.Line))
		}
	}
	if len(invalid) > 0 {
		return fmt.Errorf("keys hashvault cannot store as is, rename them first: %s", strings.Join(invalid, ", "))
	}
	for _, e := range entries {
		note := ""
		if e.References {
			note = "  (references another variable: stored literally, not expanded)"
		}
		if *dry {
			fmt.Fprintf(c.io.Stdout, "%s/%s/%s%s\n", *env, *app, e.Key, note)
			continue
		}
		out, err := c.call("PUT", "/v1/secrets/"+*env+"/"+*app+"/"+e.Key, map[string]string{"value": base64.StdEncoding.EncodeToString(e.Value)}, true)
		clear(e.Value)
		if err != nil {
			return fmt.Errorf("%s: %w", e.Key, err)
		}
		fmt.Fprintf(c.io.Stdout, "%s/%s/%s v%v%s\n", *env, *app, e.Key, out["version"], note)
	}
	return nil
}

func (c *client) policy(args []string) error {
	switch {
	case len(args) == 3 && args[0] == "put":
		doc, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		_, err = c.call("PUT", "/v1/policies/"+args[1], doc, true)
		return err
	case len(args) == 2 && args[0] == "get":
		out, err := c.call("GET", "/v1/policies/"+args[1], nil, true)
		if err != nil {
			return err
		}
		return c.printJSON(out["document"])
	}
	return errors.New("policy put NAME FILE | policy get NAME")
}

func (c *client) principal(args []string) error {
	if len(args) < 2 {
		return errors.New("principal create|get|disable|attach NAME [ARGS]")
	}
	sub := args[0]
	fs := newFlags("principal "+sub, c.io)
	key := fs.String("key", "", "public key file (authorized_keys line)")
	var tags multi
	fs.Var(&tags, "tag", "tag k=v (repeat)")
	boundary := fs.Bool("boundary", false, "attach as a permission boundary")
	detach := fs.Bool("detach", false, "detach instead of attaching")
	pos, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) == 0 || strings.Count(pos[0], "/") != 1 {
		return errors.New("principal names look like human/alice or machine/deployer")
	}
	name := pos[0]
	switch sub {
	case "create":
		line, err := os.ReadFile(*key)
		if err != nil {
			return fmt.Errorf("--key: %w", err)
		}
		t := map[string]string{}
		for _, kv := range tags {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return fmt.Errorf("tag %q is not k=v", kv)
			}
			t[k] = v
		}
		_, err = c.call("POST", "/v1/principals", map[string]any{"name": name, "ssh_key": strings.TrimSpace(string(line)), "tags": t}, true)
		return err
	case "get":
		out, err := c.call("GET", "/v1/principals/"+name, nil, true)
		if err != nil {
			return err
		}
		return c.printJSON(out)
	case "disable":
		_, err := c.call("POST", "/v1/principals/"+name+"/disable", nil, true)
		return err
	case "attach":
		if len(pos) != 2 {
			return errors.New("principal attach NAME POLICY [--boundary] [--detach]")
		}
		_, err := c.call("POST", "/v1/principals/"+name+"/attach", map[string]any{"policy": pos[1], "boundary": *boundary, "detach": *detach}, true)
		return err
	}
	return fmt.Errorf("unknown principal command %q", sub)
}

func (c *client) iam(args []string) error {
	if len(args) == 0 || args[0] != "simulate" {
		return errors.New("iam simulate --principal P --action A --resource R [--context k=v]")
	}
	fs := newFlags("iam simulate", c.io)
	p := fs.String("principal", "", "principal")
	a := fs.String("action", "", "action")
	r := fs.String("resource", "", "resource")
	var ctxs multi
	fs.Var(&ctxs, "context", "condition key k=v (repeat)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ctx := map[string][]string{}
	for _, kv := range ctxs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("context %q is not k=v", kv)
		}
		ctx[k] = append(ctx[k], v)
	}
	out, err := c.call("POST", "/v1/iam/simulate", map[string]any{"principal": *p, "action": *a, "resource": *r, "context": ctx}, true)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.io.Stdout, "%v: %v\n", out["Decision"], out["Reason"])
	trace, _ := out["Trace"].([]any)
	for _, st := range trace {
		m := st.(map[string]any)
		fmt.Fprintf(c.io.Stdout, "  %-8v %s/%v  action=%v resource=%v applies=%v\n", m["Effect"], m["Policy"], m["Sid"], m["ActionMatch"], m["ResourceMatch"], m["Applies"])
	}
	return nil
}

func (c *client) target(args []string) error {
	switch {
	case len(args) == 2 && args[0] == "put":
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var t struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(data, &t); err != nil || t.Name == "" {
			return errors.New("the target file must be JSON with a name")
		}
		_, err = c.call("PUT", "/v1/targets/"+t.Name, data, true)
		return err
	case len(args) == 1 && args[0] == "list":
		out, err := c.call("GET", "/v1/targets", nil, true)
		if err != nil {
			return err
		}
		for _, n := range out["targets"].([]any) {
			fmt.Fprintln(c.io.Stdout, n)
		}
		return nil
	}
	return errors.New("target put FILE | target list")
}

func (c *client) publish(args []string) error {
	fs := newFlags("publish", c.io)
	tgt := fs.String("target", "", "registered target")
	manifest := fs.String("manifest", "hashvault.json", "app manifest")
	rollback := fs.Bool("rollback", false, "allow versions older than the published ones")
	dry := fs.Bool("dry-run", false, "show the plan only")
	var versions multi
	fs.Var(&versions, "version", "pin KEY=N (repeat)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	m, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	pins := map[string]uint64{}
	for _, kv := range versions {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 64)
		if !ok || err != nil {
			return fmt.Errorf("--version %q is not KEY=N", kv)
		}
		pins[k] = n
	}
	out, err := c.call("POST", "/v1/publish", map[string]any{"target": *tgt, "manifest": json.RawMessage(m), "versions": pins, "rollback": *rollback, "dry_run": *dry}, true)
	if out != nil {
		_ = c.printJSON(out)
	}
	return err
}

func (c *client) audit(args []string) error {
	if len(args) != 1 || args[0] != "verify" {
		return errors.New("audit verify")
	}
	out, err := c.call("GET", "/v1/audit/verify", nil, true)
	if err != nil {
		return err
	}
	_ = c.printJSON(out)
	if out["ok"] != true {
		return errors.New("the audit log does not verify")
	}
	return nil
}

func (c *client) unseal(args []string) error {
	fs := newFlags("unseal", c.io)
	bundle := fs.String("bundle", "", "encrypted unseal bundle")
	identity := fs.String("identity", "", "age identity file (YubiKey plugin identity or offline key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundle == "" || *identity == "" {
		return errors.New("unseal --bundle FILE --identity FILE")
	}
	enc, err := os.ReadFile(*bundle)
	if err != nil {
		return err
	}
	idData, err := os.ReadFile(*identity)
	if err != nil {
		return err
	}
	ids, err := agekeys.ParseIdentities(idData, c.io.Prompter.UI())
	clear(idData)
	if err != nil {
		return err
	}
	b, err := daemon.OpenBundle(enc, ids...)
	if err != nil {
		return err
	}
	_, err = c.call("POST", "/v1/sys/unseal", b, false)
	if err == nil {
		fmt.Fprintln(c.io.Stderr, "unsealed")
	}
	return err
}
