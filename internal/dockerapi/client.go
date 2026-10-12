// Package dockerapi is a minimal Docker Engine API client for the calls the
// swarm and docker targets need: secrets, services, tasks and swarm state.
// Like internal/openbao it uses the standard library only, so the path that
// carries secret values to the orchestrator stays reviewable.
//
// Service specs are handled as generic JSON: hashvault edits the secret
// references and nothing else, and every other field round-trips untouched.
package dockerapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// APIVersion is the Engine API version requested. 1.44 is Docker 25, the
// oldest release that still receives security fixes as of 2026.
const APIVersion = "v1.44"

const maxResponseSize = 16 << 20

var (
	// ErrNotFound reports a missing object (HTTP 404).
	ErrNotFound = errors.New("dockerapi: not found")
	// ErrConflict reports a name already taken or an object in use (HTTP 409).
	ErrConflict = errors.New("dockerapi: conflict")
	// ErrOutOfSequence reports a service update based on a stale version.
	ErrOutOfSequence = errors.New("dockerapi: update out of sequence")
)

// APIError is an error answer from the daemon.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("dockerapi: HTTP %d: %s", e.Status, e.Message)
}

// Client talks to one Docker daemon.
type Client struct {
	base *url.URL
	http *http.Client
}

// New returns a client for "unix:///var/run/docker.sock" or a tcp:// or
// http:// address (tests only: an unauthenticated TCP daemon is root for
// anyone who reaches it).
func New(address string) (*Client, error) {
	transport := &http.Transport{DisableCompression: true, Proxy: nil, IdleConnTimeout: 30 * time.Second}
	var base *url.URL
	switch {
	case strings.HasPrefix(address, "unix://"):
		socket := strings.TrimPrefix(address, "unix://")
		if !strings.HasPrefix(socket, "/") {
			return nil, fmt.Errorf("dockerapi: unix socket path must be absolute: %q", socket)
		}
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}
		base = &url.URL{Scheme: "http", Host: "docker"}
	case strings.HasPrefix(address, "tcp://"), strings.HasPrefix(address, "http://"):
		u, err := url.Parse(strings.Replace(address, "tcp://", "http://", 1))
		if err != nil {
			return nil, fmt.Errorf("dockerapi: address: %w", err)
		}
		base = u
	default:
		return nil, fmt.Errorf("dockerapi: address must start with unix://, tcp:// or http://")
	}
	return &Client{base: base, http: &http.Client{Transport: transport, Timeout: 60 * time.Second}}, nil
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("dockerapi: encode request: %w", err)
		}
		reader = bytes.NewReader(data)
	}
	u := *c.base
	u.Path = "/" + APIVersion + path
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return fmt.Errorf("dockerapi: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dockerapi: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return fmt.Errorf("dockerapi: read response: %w", err)
	}
	if len(data) > maxResponseSize {
		return fmt.Errorf("dockerapi: response larger than %d bytes", maxResponseSize)
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return fmt.Errorf("%w: %s", ErrNotFound, e.Message)
		case resp.StatusCode == http.StatusConflict:
			return fmt.Errorf("%w: %s", ErrConflict, e.Message)
		case strings.Contains(e.Message, "update out of sequence"):
			return fmt.Errorf("%w: %s", ErrOutOfSequence, e.Message)
		}
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
		return &APIError{Status: resp.StatusCode, Message: e.Message}
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("dockerapi: decode response: %w", err)
	}
	return nil
}

// Ping checks that the daemon answers.
func (c *Client) Ping(ctx context.Context) error {
	u := *c.base
	u.Path = "/_ping"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dockerapi: ping: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dockerapi: ping: HTTP %d", resp.StatusCode)
	}
	return nil
}

// SwarmState is the node's swarm membership.
type SwarmState struct {
	LocalNodeState   string
	ControlAvailable bool
}

// Swarm reports whether this node is a swarm manager.
func (c *Client) Swarm(ctx context.Context) (SwarmState, error) {
	var info struct {
		Swarm SwarmState `json:"Swarm"`
	}
	err := c.do(ctx, http.MethodGet, "/info", nil, nil, &info)
	return info.Swarm, err
}

// SwarmInit makes this node a single-node swarm (tests).
func (c *Client) SwarmInit(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/swarm/init", nil, map[string]string{"ListenAddr": "0.0.0.0:2377"}, nil)
}

// Secret is a swarm secret, without its value (the API never returns it).
type Secret struct {
	ID        string    `json:"ID"`
	CreatedAt time.Time `json:"CreatedAt"`
	Spec      struct {
		Name   string            `json:"Name"`
		Labels map[string]string `json:"Labels"`
	} `json:"Spec"`
}

// SecretCreate creates a swarm secret and returns its ID.
func (c *Client) SecretCreate(ctx context.Context, name string, labels map[string]string, value []byte) (string, error) {
	body := map[string]any{"Name": name, "Labels": labels, "Data": base64.StdEncoding.EncodeToString(value)}
	var out struct {
		ID string `json:"ID"`
	}
	if err := c.do(ctx, http.MethodPost, "/secrets/create", nil, body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// SecretList lists secrets matching label filters ("k=v" or "k").
func (c *Client) SecretList(ctx context.Context, labels ...string) ([]Secret, error) {
	q := url.Values{}
	if len(labels) > 0 {
		f, _ := json.Marshal(map[string][]string{"label": labels})
		q.Set("filters", string(f))
	}
	var out []Secret
	err := c.do(ctx, http.MethodGet, "/secrets", q, nil, &out)
	return out, err
}

// SecretRemove deletes a secret. The daemon refuses one still in use.
func (c *Client) SecretRemove(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/secrets/"+url.PathEscape(id), nil, nil, nil)
}

// Service is a swarm service. Spec is kept as generic JSON.
type Service struct {
	ID      string `json:"ID"`
	Version struct {
		Index uint64 `json:"Index"`
	} `json:"Version"`
	Spec         map[string]any `json:"Spec"`
	UpdateStatus *struct {
		State       string    `json:"State"`
		Message     string    `json:"Message"`
		StartedAt   time.Time `json:"StartedAt"`
		CompletedAt time.Time `json:"CompletedAt"`
	} `json:"UpdateStatus"`
}

// Name returns the service name from its spec.
func (s Service) Name() string {
	name, _ := s.Spec["Name"].(string)
	return name
}

// ServiceInspect reads a service by name or ID.
func (c *Client) ServiceInspect(ctx context.Context, nameOrID string) (Service, error) {
	var out Service
	err := c.do(ctx, http.MethodGet, "/services/"+url.PathEscape(nameOrID), nil, nil, &out)
	return out, err
}

// ServiceList lists every service.
func (c *Client) ServiceList(ctx context.Context) ([]Service, error) {
	var out []Service
	err := c.do(ctx, http.MethodGet, "/services", nil, nil, &out)
	return out, err
}

// ServiceCreate creates a service from a generic spec (tests).
func (c *Client) ServiceCreate(ctx context.Context, spec map[string]any) (string, error) {
	var out struct {
		ID string `json:"ID"`
	}
	err := c.do(ctx, http.MethodPost, "/services/create", nil, spec, &out)
	return out.ID, err
}

// ServiceUpdate replaces the spec of a service at the given version.
func (c *Client) ServiceUpdate(ctx context.Context, id string, version uint64, spec map[string]any) error {
	q := url.Values{"version": []string{strconv.FormatUint(version, 10)}}
	return c.do(ctx, http.MethodPost, "/services/"+url.PathEscape(id)+"/update", q, spec, nil)
}

// Task is the subset of a swarm task hashvault reads.
type Task struct {
	ID           string `json:"ID"`
	DesiredState string `json:"DesiredState"`
	Status       struct {
		State string `json:"State"`
		Err   string `json:"Err"`
	} `json:"Status"`
}

// TaskList lists the tasks of a service.
func (c *Client) TaskList(ctx context.Context, serviceID string) ([]Task, error) {
	f, _ := json.Marshal(map[string][]string{"service": {serviceID}})
	var out []Task
	err := c.do(ctx, http.MethodGet, "/tasks", url.Values{"filters": []string{string(f)}}, nil, &out)
	return out, err
}

// ImagePull pulls an image (tests). The progress stream is drained.
func (c *Client) ImagePull(ctx context.Context, image, tag string) error {
	q := url.Values{"fromImage": []string{image}, "tag": []string{tag}}
	u := *c.base
	u.Path = "/" + APIVersion + "/images/create"
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("dockerapi: pull: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dockerapi: pull %s:%s: HTTP %d", image, tag, resp.StatusCode)
	}
	return nil
}

// Container is the subset of a container hashvault reads.
type Container struct {
	ID     string            `json:"Id"`
	Labels map[string]string `json:"Labels"`
}

// ContainerList lists containers (running or not) matching label filters.
func (c *Client) ContainerList(ctx context.Context, labels ...string) ([]Container, error) {
	f, _ := json.Marshal(map[string][]string{"label": labels})
	q := url.Values{"all": []string{"true"}, "filters": []string{string(f)}}
	var out []Container
	err := c.do(ctx, http.MethodGet, "/containers/json", q, nil, &out)
	return out, err
}

// ContainerRestart restarts a container, waiting up to timeout for it to stop.
func (c *Client) ContainerRestart(ctx context.Context, id string, timeout time.Duration) error {
	q := url.Values{"t": []string{strconv.Itoa(int(timeout.Seconds()))}}
	return c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/restart", q, nil, nil)
}

// ContainerState is the runtime state of a container.
type ContainerState struct {
	Running    bool      `json:"Running"`
	Restarting bool      `json:"Restarting"`
	ExitCode   int       `json:"ExitCode"`
	StartedAt  time.Time `json:"StartedAt"`
	Health     *struct {
		Status string `json:"Status"`
	} `json:"Health"`
}

// ContainerInspect returns the state of a container.
func (c *Client) ContainerInspect(ctx context.Context, id string) (ContainerState, error) {
	var out struct {
		State ContainerState `json:"State"`
	}
	err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, nil, &out)
	return out.State, err
}

// ContainerCreate creates a container from a generic config (tests).
func (c *Client) ContainerCreate(ctx context.Context, name string, config map[string]any) (string, error) {
	var out struct {
		ID string `json:"Id"`
	}
	err := c.do(ctx, http.MethodPost, "/containers/create", url.Values{"name": []string{name}}, config, &out)
	return out.ID, err
}

// ContainerStart starts a created container (tests).
func (c *Client) ContainerStart(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil, nil, nil)
}
