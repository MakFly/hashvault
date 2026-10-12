package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These are CLI bridge security tests, not browser or frontend tests.
func TestUIBridgeKeepsBearerPrivateAndEnforcesOrigin(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "vault.sock")
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("private-session"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("console"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/status" {
			if r.Header.Get("Authorization") != "" {
				t.Error("status kept the idle vault open")
			}
		} else if r.Header.Get("Authorization") != "Bearer private-session" {
			t.Error("bridge lost or accepted a browser bearer")
		}
		if r.Header.Get("Cookie") != "" {
			t.Error("browser cookie reached vault")
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	})}
	go func() { _ = hs.Serve(l) }()
	t.Cleanup(func() { _ = hs.Close() })
	c := &client{io: IO{Getenv: func(key string) string {
		if key == "HASHVAULT_SOCKET" {
			return sock
		}
		if key == "HASHVAULT_TOKEN_FILE" {
			return token
		}
		return ""
	}}}
	origin, _ := url.Parse("http://127.0.0.1:8822")
	h, closeAssets, err := c.uiHandler(dir, origin, "launch-nonce", "browser-cookie")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeAssets)
	call := func(method, path, body, requestOrigin, host string, cookie bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, origin.String()+path, strings.NewReader(body))
		r.Host = host
		r.Header.Set("Origin", requestOrigin)
		r.Header.Set("Authorization", "Bearer attacker")
		if cookie {
			r.AddCookie(&http.Cookie{Name: "hv_ui", Value: "browser-cookie"})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/v1/auth/session", "", "", origin.Host, false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "/session", `{"nonce":"launch-nonce"}`, "https://attacker.invalid", origin.Host, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	w := call("POST", "/session", `{"nonce":"launch-nonce"}`, origin.String(), origin.Host, false)
	if w.Code != 204 || len(w.Result().Cookies()) != 1 || !w.Result().Cookies()[0].HttpOnly {
		t.Fatal(w.Code, w.Header())
	}
	if w := call("POST", "/session", `{"nonce":"launch-nonce"}`, origin.String(), origin.Host, false); w.Code != 403 {
		t.Fatal("nonce reused")
	}
	for _, path := range []string{"/api/v1/sys/status", "/api/v1/auth/session"} {
		w := call("GET", path, "", "", origin.Host, true)
		if w.Code != 200 || strings.Contains(w.Body.String(), "private-session") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if w := call("POST", "/api/v1/sys/seal", "", "https://attacker.invalid", origin.Host, true); w.Code != 403 {
		t.Fatal("CSRF accepted")
	}
	if w := call("GET", "/api/v1/auth/session", "", "", "attacker.invalid:8822", true); w.Code != 403 {
		t.Fatal("DNS rebinding accepted")
	}
	if w := call("POST", "/api/v1/auth/login", "", origin.String(), origin.Host, true); w.Code != 403 {
		t.Fatal("browser authentication allowed")
	}
	if w := call("GET", "/secrets", "", "", origin.Host, false); w.Code != 200 || w.Body.String() != "console" {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("GET", "/missing.js", "", "", origin.Host, false); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w := call("PUT", "/", "", "", origin.Host, false); w.Code != 405 {
		t.Fatal(w.Code)
	}
}

type launchWriter struct{ messages chan string }

func (w launchWriter) Write(raw []byte) (int, error) { w.messages <- string(raw); return len(raw), nil }

func TestUIBridgeCommandClosesItsListenerOnCancellation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("assets"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	messages := make(chan string, 1)
	done := make(chan error, 1)
	c := &client{io: IO{Context: ctx, Stderr: launchWriter{messages: messages}}}
	go func() { done <- c.ui([]string{"--assets", dir, "--listen", "127.0.0.1:0"}) }()
	var message string
	select {
	case message = <-messages:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("CLI bridge never became ready")
	}
	launch := strings.Fields(message)[1]
	base, _, _ := strings.Cut(launch, "/#")
	resp, err := http.Get(base + "/api/v1/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("bridge opened without handshake")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bridge did not stop")
	}
	if resp, err := http.Get(base); err == nil {
		_ = resp.Body.Close()
		t.Fatal("task-owned listener still running")
	}
}

func TestUIRejectsPublicListenersAndMissingAssets(t *testing.T) {
	var out strings.Builder
	c := &client{io: IO{Stderr: &out}}
	if err := c.ui([]string{"--listen", "0.0.0.0:8822"}); err == nil {
		t.Fatal("public listener accepted")
	}
	if err := c.ui([]string{"--assets", t.TempDir()}); err == nil {
		t.Fatal("missing assets accepted")
	}
}

func TestUIDevelopmentProxyKeepsHostAndOriginChecks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("console"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &client{}
	origin, _ := url.Parse("http://127.0.0.1:8822")
	browser := "http://127.0.0.1:4322"
	h, closeAssets, err := c.uiHandlerForBrowser(dir, origin, browser, "fixture-nonce", "fixture-cookie")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeAssets)
	call := func(host, requestOrigin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", origin.String()+"/session", strings.NewReader(`{"nonce":"fixture-nonce"}`))
		r.Host = host
		r.Header.Set("Origin", requestOrigin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, requestOrigin := range []string{"https://attacker.invalid", origin.String(), "http://127.0.0.1:4323", ""} {
		if w := call(origin.Host, requestOrigin); w.Code != 403 {
			t.Fatal("unregistered browser origin accepted", requestOrigin, w.Code)
		}
	}
	if w := call("attacker.invalid:8822", browser); w.Code != 403 {
		t.Fatal("proxy weakened Host validation", w.Code)
	}
	if w := call(origin.Host, browser); w.Code != 204 {
		t.Fatal("development handshake failed", w.Code)
	}
	if w := call(origin.Host, browser); w.Code != 403 {
		t.Fatal("development nonce reused", w.Code)
	}
	for _, raw := range []string{"https://127.0.0.1:4322", "http://localhost:4322", "http://0.0.0.0:4322", "http://127.0.0.1:0", "http://127.0.0.1:4322/", "http://127.0.0.1:4322?x=y", "http://127.0.0.1:4322#launch=fixture", "http://user@127.0.0.1:4322"} {
		if validUIBrowserOrigin(raw, "127.0.0.1") {
			t.Fatal("invalid development origin accepted", raw)
		}
	}
	if !validUIBrowserOrigin(browser, "127.0.0.1") {
		t.Fatal("numeric loopback origin rejected")
	}
}

func TestUIDevelopmentSessionOpensRootWithoutNonceAndKeepsReleaseLocked(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "vault.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	vault := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/status" || r.Header.Get("Authorization") != "" {
			t.Error("development status changed authentication or routing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"vault":"fixture","version":"test","sealed":true}`)
	})}
	go func() { _ = vault.Serve(l) }()
	t.Cleanup(func() { _ = vault.Close() })
	c := &client{io: IO{Getenv: func(key string) string {
		if key == "HASHVAULT_SOCKET" {
			return socket
		}
		return ""
	}}}
	origin, _ := url.Parse("http://127.0.0.1:8822")
	browser := "http://127.0.0.1:4322"
	for _, development := range []bool{false, true} {
		h, closeAssets, err := c.uiHandlerWithSession(dir, origin, browser, "fixture-nonce", "fixture-cookie", development)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(closeAssets)
		session := func(requestOrigin string) *httptest.ResponseRecorder {
			r := httptest.NewRequest("POST", origin.String()+"/session", strings.NewReader(`{}`))
			r.Header.Set("Origin", requestOrigin)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			return w
		}
		if w := session("https://attacker.invalid"); w.Code != 403 {
			t.Fatal("automatic session accepted a foreign origin", w.Code)
		}
		w := session(browser)
		if !development {
			if w.Code != 403 {
				t.Fatal("release mode accepted an empty nonce", w.Code)
			}
			continue
		}
		if w.Code != 204 || len(w.Result().Cookies()) != 1 || !w.Result().Cookies()[0].HttpOnly {
			t.Fatal("development session failed", w.Code)
		}
		request := httptest.NewRequest("GET", origin.String()+"/api/v1/sys/status", nil)
		request.AddCookie(w.Result().Cookies()[0])
		result := httptest.NewRecorder()
		h.ServeHTTP(result, request)
		if result.Code != 200 || result.Header().Get("Content-Type") != "application/json" || !strings.Contains(result.Body.String(), `"sealed":true`) {
			t.Fatal("development API did not return vault JSON", result.Code)
		}
		if w := session(browser); w.Code != 204 {
			t.Fatal("development refresh required a nonce", w.Code)
		}
	}
	if err := c.ui([]string{"--dev-session"}); err == nil {
		t.Fatal("automatic session accepted without an explicit origin")
	}
}
