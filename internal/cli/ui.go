package cli

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// ui serves release assets and bridges the browser to the existing Unix
// socket. The SSHSIG bearer remains in the CLI; the browser gets a distinct,
// process-local cookie after a one-use launch handshake.
func (c *client) ui(args []string) error {
	fs := newFlags("ui", c.io)
	listen := fs.String("listen", "127.0.0.1:8822", "loopback address only")
	assets := fs.String("assets", "", "directory containing the released UI")
	browser := fs.String("browser-origin", "", "numeric loopback origin of a development UI proxy")
	devSession := fs.Bool("dev-session", false, "automatic same-origin browser session for development")
	if err := fs.Parse(args); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("ui: listen must be a numeric loopback address")
	}
	if *browser != "" && !validUIBrowserOrigin(*browser, host) {
		return errors.New("ui: browser-origin must be an HTTP loopback origin on the same numeric host")
	}
	if *devSession && *browser == "" {
		return errors.New("ui: dev-session requires an explicit browser-origin")
	}
	if *assets == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		*assets = filepath.Join(filepath.Dir(exe), "..", "share", "hashvault", "ui")
	}
	if _, err := os.Stat(filepath.Join(*assets, "index.html")); err != nil {
		return errors.New("ui: released assets are missing; use --assets to select their directory")
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer l.Close()
	origin := "http://" + l.Addr().String()
	browserOrigin := origin
	if *browser != "" {
		browserOrigin = *browser
	}
	u, _ := url.Parse(origin)
	nonce, cookie := randomUIKey(), randomUIKey()
	h, closeAssets, err := c.uiHandlerWithSession(*assets, u, browserOrigin, nonce, cookie, *devSession)
	if err != nil {
		return err
	}
	defer closeAssets()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 15 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	parent := c.io.Context
	stop := func() {}
	if parent == nil {
		parent, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	}
	defer stop()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if *devSession {
		fmt.Fprintf(c.io.Stderr, "Open %s/\nDevelopment browser session enabled. Vault access uses the CLI session token.\n", browserOrigin)
	} else {
		fmt.Fprintf(c.io.Stderr, "Open %s/#launch=%s\nAuthenticate with hashvault login through the SSH tunnel. Close this process to end the browser session.\n", browserOrigin, nonce)
	}
	err = srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func randomUIKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *client) uiHandler(assets string, origin *url.URL, nonce, cookie string) (http.Handler, func(), error) {
	return c.uiHandlerForBrowser(assets, origin, origin.String(), nonce, cookie)
}

func validUIBrowserOrigin(raw, host string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Hostname() != host || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	return err == nil && port > 0 && port <= 65535 && raw == u.Scheme+"://"+u.Host
}

func (c *client) uiHandlerForBrowser(assets string, origin *url.URL, browserOrigin, nonce, cookie string) (http.Handler, func(), error) {
	return c.uiHandlerWithSession(assets, origin, browserOrigin, nonce, cookie, false)
}

func (c *client) uiHandlerWithSession(assets string, origin *url.URL, browserOrigin, nonce, cookie string, devSession bool) (http.Handler, func(), error) {
	root, err := os.OpenRoot(assets)
	if err != nil {
		return nil, nil, err
	}
	var used atomic.Bool
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", c.socket())
	}}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = "http", "hashvault"
			pr.Out.URL.Path = strings.TrimPrefix(pr.In.URL.Path, "/api")
			pr.Out.Host = "hashvault"
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Del("Authorization")
			if pr.Out.URL.Path != "/v1/sys/status" {
				if raw, err := os.ReadFile(c.tokenFile()); err == nil {
					pr.Out.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(raw)))
					clear(raw)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "The vault connection is unavailable.", http.StatusBadGateway)
		},
	}
	files := http.FileServer(http.FS(root.FS()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.Host != origin.Host || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != browserOrigin) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/session" {
			if r.Method != http.MethodPost || r.Header.Get("Origin") != browserOrigin {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			var req struct {
				Nonce string `json:"nonce"`
			}
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req) != nil {
				http.Error(w, "invalid session request", http.StatusBadRequest)
				return
			}
			// Development's automatic bootstrap is confined to the explicit
			// loopback browser origin. Release mode keeps its one-use nonce.
			if devSession && req.Nonce == "" {
				used.Store(true)
			} else if subtle.ConstantTimeCompare([]byte(req.Nonce), []byte(nonce)) != 1 || !used.CompareAndSwap(false, true) {
				http.Error(w, "launch link expired", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "hv_ui", Value: cookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode}) // #nosec G124 -- loopback HTTP only; strict Host/Origin, release nonce or explicit dev bootstrap; bearer never reaches the browser
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			ck, err := r.Cookie("hv_ui")
			if err != nil || !used.Load() || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(cookie)) != 1 {
				http.Error(w, "Open the link printed by hashvault ui.", http.StatusUnauthorized)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("Origin") != browserOrigin {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			// Authentication is owned by the CLI, so browser input cannot
			// enroll a session or inject a different bearer into the bridge.
			if r.URL.Path == "/api/v1/auth/login" || r.URL.Path == "/api/v1/auth/challenge" {
				http.Error(w, "Use hashvault login in your terminal.", http.StatusForbidden)
				return
			}
			proxy.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.Path, "\\") {
			http.NotFound(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "."
		}
		st, err := root.Stat(path)
		if err != nil || st.IsDir() {
			if filepath.Ext(r.URL.Path) != "" {
				http.NotFound(w, r)
				return
			}
			r.URL.Path = "/"
		}
		files.ServeHTTP(w, r)
	}), func() { transport.CloseIdleConnections(); _ = root.Close() }, nil
}
