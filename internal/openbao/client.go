// Package openbao is a minimal client for the parts of the OpenBao HTTP API
// that hashvault uses: KV v2 (records), Transit (the key encryption key) and
// the seal endpoints. It is deliberately small, with no dependency outside the
// standard library, so that the whole path between hashvault and its storage
// can be reviewed in one sitting.
package openbao

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseSize bounds every response body: the largest legitimate one is a
// KV read of a 1 MiB value, base64 and JSON encoded.
const maxResponseSize = 8 << 20

// ErrNotFound reports a path with no data (HTTP 404).
var ErrNotFound = errors.New("openbao: not found")

// ErrCASMismatch reports a KV v2 check-and-set conflict.
var ErrCASMismatch = errors.New("openbao: check-and-set conflict")

// APIError is an error answer from OpenBao. Its text never contains request
// data, only what OpenBao returned.
type APIError struct {
	Status int
	Errors []string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("openbao: HTTP %d: %s", e.Status, strings.Join(e.Errors, "; "))
}

// Config locates an OpenBao server.
type Config struct {
	// Address is "unix:///run/openbao/api.sock" or an http(s) URL. Production
	// uses the unix socket; TCP is for tests on loopback.
	Address string
	// Token authenticates the requests.
	Token string
	// Timeout bounds each request. Zero means 30 seconds.
	Timeout time.Duration
}

// Client talks to one OpenBao server.
type Client struct {
	base  *url.URL
	http  *http.Client
	token string
}

// New returns a client for cfg.
func New(cfg Config) (*Client, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	transport := &http.Transport{
		DisableCompression:  true,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		Proxy:               nil, // never route secrets through an environment proxy
	}
	var base *url.URL
	switch {
	case strings.HasPrefix(cfg.Address, "unix://"):
		socket := strings.TrimPrefix(cfg.Address, "unix://")
		if !strings.HasPrefix(socket, "/") {
			return nil, fmt.Errorf("openbao: unix socket path must be absolute: %q", socket)
		}
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}
		base = &url.URL{Scheme: "http", Host: "openbao"}
	case strings.HasPrefix(cfg.Address, "http://"), strings.HasPrefix(cfg.Address, "https://"):
		u, err := url.Parse(cfg.Address)
		if err != nil {
			return nil, fmt.Errorf("openbao: address: %w", err)
		}
		base = u
	default:
		return nil, fmt.Errorf("openbao: address must start with unix://, http:// or https://")
	}
	return &Client{
		base:  base,
		http:  &http.Client{Transport: transport, Timeout: timeout},
		token: cfg.Token,
	}, nil
}

// SetToken replaces the token, for example after an AppRole login.
func (c *Client) SetToken(token string) { c.token = token }

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("openbao: encode request: %w", err)
		}
		reader = bytes.NewReader(data)
	}
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/v1/" + strings.TrimPrefix(path, "/")
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return fmt.Errorf("openbao: %w", err)
	}
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("openbao: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return fmt.Errorf("openbao: read response: %w", err)
	}
	if len(data) > maxResponseSize {
		return fmt.Errorf("openbao: response larger than %d bytes", maxResponseSize)
	}
	if resp.StatusCode >= 300 {
		err := decodeError(resp.StatusCode, data)
		// KV v2 answers 404 for a destroyed or deleted version, with its
		// metadata in the body: hand that body to the caller too.
		if errors.Is(err, ErrNotFound) && out != nil && len(data) > 0 {
			_ = json.Unmarshal(data, out)
		}
		return err
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("openbao: decode response: %w", err)
	}
	return nil
}

func decodeError(status int, data []byte) error {
	var body struct {
		Errors []string `json:"errors"`
	}
	_ = json.Unmarshal(data, &body)
	if status == http.StatusNotFound && len(body.Errors) == 0 {
		return ErrNotFound
	}
	for _, e := range body.Errors {
		if strings.Contains(e, "check-and-set parameter did not match") {
			return ErrCASMismatch
		}
	}
	if len(body.Errors) == 0 {
		body.Errors = []string{http.StatusText(status)}
	}
	return &APIError{Status: status, Errors: body.Errors}
}

// envelope is the common OpenBao response wrapper.
type response[T any] struct {
	Data T `json:"data"`
}

// Mount enables a secrets engine at path, for setup and tests.
func (c *Client) Mount(ctx context.Context, path, engine string, options map[string]string) error {
	body := map[string]any{"type": engine}
	if len(options) > 0 {
		body["options"] = options
	}
	return c.do(ctx, http.MethodPost, "sys/mounts/"+path, nil, body, nil)
}

// SealStatus is the subset of sys/seal-status hashvault reads.
type SealStatus struct {
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Threshold   int    `json:"t"`
	Shares      int    `json:"n"`
	Progress    int    `json:"progress"`
	Version     string `json:"version"`
}

// SealStatus reports whether the server is sealed. It needs no token.
func (c *Client) SealStatus(ctx context.Context) (SealStatus, error) {
	var s SealStatus
	err := c.do(ctx, http.MethodGet, "sys/seal-status", nil, nil, &s)
	return s, err
}

// ---- Lifecycle and auth (bootstrap, unseal, AppRole) --------------------------

// InitResult is the one-time answer of sys/init. It holds the only copies of
// the unseal key and the root token: the caller encrypts the first and
// revokes the second.
type InitResult struct {
	KeysB64   []string `json:"keys_base64"`
	RootToken string   `json:"root_token"`
}

// Init initialises an empty server with shares unseal keys, threshold of
// them needed.
func (c *Client) Init(ctx context.Context, shares, threshold int) (InitResult, error) {
	var out InitResult
	err := c.do(ctx, http.MethodPut, "sys/init", nil, map[string]int{"secret_shares": shares, "secret_threshold": threshold}, &out)
	return out, err
}

// Unseal submits one unseal key share.
func (c *Client) Unseal(ctx context.Context, keyB64 string) (SealStatus, error) {
	var out SealStatus
	err := c.do(ctx, http.MethodPut, "sys/unseal", nil, map[string]string{"key": keyB64}, &out)
	return out, err
}

// Seal seals the server (needs sudo on sys/seal).
func (c *Client) Seal(ctx context.Context) error {
	return c.do(ctx, http.MethodPut, "sys/seal", nil, nil, nil)
}

// EnableAuth enables an auth method at path.
func (c *Client) EnableAuth(ctx context.Context, path, method string) error {
	return c.do(ctx, http.MethodPost, "sys/auth/"+path, nil, map[string]string{"type": method}, nil)
}

// PutACLPolicy writes an OpenBao ACL policy (HCL).
func (c *Client) PutACLPolicy(ctx context.Context, name, hcl string) error {
	return c.do(ctx, http.MethodPut, "sys/policies/acl/"+name, nil, map[string]string{"policy": hcl}, nil)
}

// AppRoleWrite creates or updates an AppRole role.
func (c *Client) AppRoleWrite(ctx context.Context, mount, role string, params map[string]any) error {
	return c.do(ctx, http.MethodPost, "auth/"+mount+"/role/"+role, nil, params, nil)
}

// AppRoleRoleID returns the role id of a role.
func (c *Client) AppRoleRoleID(ctx context.Context, mount, role string) (string, error) {
	var out response[struct {
		RoleID string `json:"role_id"`
	}]
	err := c.do(ctx, http.MethodGet, "auth/"+mount+"/role/"+role+"/role-id", nil, nil, &out)
	return out.Data.RoleID, err
}

// AppRoleSecretID generates a secret id for a role.
func (c *Client) AppRoleSecretID(ctx context.Context, mount, role string) (string, error) {
	var out response[struct {
		SecretID string `json:"secret_id"`
	}]
	err := c.do(ctx, http.MethodPost, "auth/"+mount+"/role/"+role+"/secret-id", nil, map[string]any{}, &out)
	return out.Data.SecretID, err
}

type authResponse struct {
	Auth *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// AppRoleLogin exchanges a role id and secret id for a token, sets it on
// the client and returns its lifetime.
func (c *Client) AppRoleLogin(ctx context.Context, mount, roleID, secretID string) (time.Duration, error) {
	var out authResponse
	if err := c.do(ctx, http.MethodPost, "auth/"+mount+"/login", nil, map[string]string{"role_id": roleID, "secret_id": secretID}, &out); err != nil {
		return 0, err
	}
	if out.Auth == nil || out.Auth.ClientToken == "" {
		return 0, errors.New("openbao: login returned no token")
	}
	c.SetToken(out.Auth.ClientToken)
	return time.Duration(out.Auth.LeaseDuration) * time.Second, nil
}

// RenewSelf renews the client's token and returns its new lifetime.
func (c *Client) RenewSelf(ctx context.Context) (time.Duration, error) {
	var out authResponse
	if err := c.do(ctx, http.MethodPost, "auth/token/renew-self", nil, map[string]any{}, &out); err != nil {
		return 0, err
	}
	if out.Auth == nil {
		return 0, errors.New("openbao: renew returned no auth")
	}
	return time.Duration(out.Auth.LeaseDuration) * time.Second, nil
}

// RevokeSelf revokes the client's token (used on the root token at the end
// of the bootstrap) and forgets it.
func (c *Client) RevokeSelf(ctx context.Context) error {
	err := c.do(ctx, http.MethodPost, "auth/token/revoke-self", nil, map[string]any{}, nil)
	c.SetToken("")
	return err
}

// WaitActive waits until the server is unsealed and active (sys/health
// answers 200): after an unseal, integrated storage elects a leader first.
func (c *Client) WaitActive(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := c.do(ctx, http.MethodGet, "sys/health", nil, nil, nil)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("openbao: not active after %s: %w", timeout, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
