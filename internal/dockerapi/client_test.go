package dockerapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

var ctx = context.Background()

func fake(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(strings.Replace(srv.URL, "http://", "tcp://", 1))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func status(code int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

func TestNewRefusesUnknownAddresses(t *testing.T) {
	for _, addr := range []string{"", "/var/run/docker.sock", "unix://relative.sock", "ssh://host"} {
		if _, err := New(addr); err == nil {
			t.Errorf("address %q accepted", addr)
		}
	}
}

func TestErrorsAreMapped(t *testing.T) {
	if _, err := fake(t, status(404, `{"message":"no such secret"}`)).ServiceInspect(ctx, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: %v", err)
	}
	if _, err := fake(t, status(409, `{"message":"name conflicts"}`)).SecretCreate(ctx, "x", nil, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("409: %v", err)
	}
	seq := `{"message":"rpc error: update out of sequence"}`
	if err := fake(t, status(500, seq)).ServiceUpdate(ctx, "x", 1, map[string]any{}); !errors.Is(err, ErrOutOfSequence) {
		t.Fatalf("out of sequence: %v", err)
	}
	var apiErr *APIError
	if err := fake(t, status(503, ``)).SecretRemove(ctx, "x"); !errors.As(err, &apiErr) || apiErr.Status != 503 || apiErr.Message == "" {
		t.Fatalf("503: %v", err)
	}
	if _, err := fake(t, status(200, `{`)).Swarm(ctx); err == nil {
		t.Fatal("a truncated body must fail to decode")
	}
	big := `[` + strings.Repeat(" ", maxResponseSize) + `]`
	if _, err := fake(t, status(200, big)).ServiceList(ctx); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized: %v", err)
	}
}

func TestRequestsCarryTheExpectedShape(t *testing.T) {
	var seen []string
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		switch {
		case strings.HasSuffix(r.URL.Path, "/tasks"):
			_, _ = w.Write([]byte(`[{"ID":"t1","DesiredState":"running","Status":{"State":"running"}}]`))
		case strings.HasSuffix(r.URL.Path, "/secrets"):
			_, _ = w.Write([]byte(`[{"ID":"s1","Spec":{"Name":"n","Labels":{"hv.app":"a"}}}]`))
		case strings.HasSuffix(r.URL.Path, "/services/create"):
			_, _ = w.Write([]byte(`{"ID":"svc"}`))
		default:
			w.WriteHeader(200)
		}
	})
	tasks, err := c.TaskList(ctx, "svc1")
	if err != nil || len(tasks) != 1 || tasks[0].Status.State != "running" {
		t.Fatalf("tasks %+v %v", tasks, err)
	}
	secrets, err := c.SecretList(ctx, "hv.app=a")
	if err != nil || len(secrets) != 1 || secrets[0].Spec.Labels["hv.app"] != "a" {
		t.Fatalf("secrets %+v %v", secrets, err)
	}
	if id, err := c.ServiceCreate(ctx, map[string]any{"Name": "x"}); err != nil || id != "svc" {
		t.Fatalf("create %q %v", id, err)
	}
	if err := c.ServiceUpdate(ctx, "svc", 42, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(seen, "\n")
	for _, want := range []string{
		"GET /" + APIVersion + "/tasks?filters=%7B%22service%22%3A%5B%22svc1%22%5D%7D",
		"GET /" + APIVersion + "/secrets?filters=%7B%22label%22%3A%5B%22hv.app%3Da%22%5D%7D",
		"POST /" + APIVersion + "/services/svc/update?version=42",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing request %q in\n%s", want, joined)
		}
	}
}

func TestPingAndPull(t *testing.T) {
	if err := fake(t, status(200, "OK")).Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := fake(t, status(500, "")).Ping(ctx); err == nil {
		t.Fatal("ping accepted a 500")
	}
	if err := fake(t, status(200, `{"status":"done"}`)).ImagePull(ctx, "busybox", "1"); err != nil {
		t.Fatal(err)
	}
	if err := fake(t, status(404, ``)).ImagePull(ctx, "busybox", "1"); err == nil {
		t.Fatal("pull accepted a 404")
	}
	dead, err := New("tcp://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if err := dead.Ping(ctx); err == nil {
		t.Fatal("ping of a closed port succeeded")
	}
	if err := dead.ImagePull(ctx, "a", "b"); err == nil {
		t.Fatal("pull from a closed port succeeded")
	}
	if _, err := dead.Swarm(ctx); err == nil {
		t.Fatal("info from a closed port succeeded")
	}
}

func TestUnixSocketAndServiceName(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ID":"x","Spec":{"Name":"acme_api"}}`))
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	c, err := New("unix://" + sock)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := c.ServiceInspect(ctx, "acme_api")
	if err != nil || svc.Name() != "acme_api" {
		t.Fatalf("got %+v %v", svc, err)
	}
}
