package openbao_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MakFly/hashvault/internal/envelope"
	"github.com/MakFly/hashvault/internal/openbao"
	"github.com/MakFly/hashvault/internal/openbao/baotest"
)

var ctx = context.Background()

func TestNewRefusesUnknownAddresses(t *testing.T) {
	for _, addr := range []string{"", "tcp://127.0.0.1:8200", "unix://relative.sock", "127.0.0.1:8200"} {
		if _, err := openbao.New(openbao.Config{Address: addr}); err == nil {
			t.Errorf("address %q accepted", addr)
		}
	}
}

func fakeServer(t *testing.T, status int, body string) *openbao.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok" {
			t.Errorf("token header missing")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c, err := openbao.New(openbao.Config{Address: srv.URL, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestErrorsAreDecoded(t *testing.T) {
	if _, err := fakeServer(t, 404, ``).KVGet(ctx, "hv", "a", 0); !errors.Is(err, openbao.ErrNotFound) {
		t.Fatalf("404: got %v", err)
	}
	cas := `{"errors":["check-and-set parameter did not match the current version"]}`
	if _, err := fakeServer(t, 400, cas).KVPut(ctx, "hv", "a", nil, 0); !errors.Is(err, openbao.ErrCASMismatch) {
		t.Fatalf("cas: got %v", err)
	}
	var apiErr *openbao.APIError
	if err := fakeServer(t, 403, `{"errors":["permission denied"]}`).Mount(ctx, "x", "kv", nil); !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("403: got %v", err)
	}
	if err := fakeServer(t, 500, `not json`).Mount(ctx, "x", "kv", nil); !errors.As(err, &apiErr) || apiErr.Status != 500 {
		t.Fatalf("500: got %v", err)
	}
	if _, err := fakeServer(t, 200, `{"data":`).SealStatus(ctx); err == nil {
		t.Fatal("a truncated body must fail to decode")
	}
}

func TestOversizedResponsesAreRefused(t *testing.T) {
	big := `{"data":{"x":"` + strings.Repeat("a", 9<<20) + `"}}`
	if _, err := fakeServer(t, 200, big).SealStatus(ctx); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}

func TestUnixSocketTransport(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "bao.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/seal-status" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"initialized":true,"sealed":true,"t":1,"n":1}`))
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close(); _ = os.Remove(sock) })
	c, err := openbao.New(openbao.Config{Address: "unix://" + sock})
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.SealStatus(ctx)
	if err != nil || !st.Sealed || !st.Initialized {
		t.Fatalf("got %+v, %v", st, err)
	}
}

// ---- Against a real OpenBao ---------------------------------------------

func binding() envelope.Binding {
	return envelope.Binding{Resource: "hv:test:secret/acme-api/DB", Env: "test", Version: 1}
}

func TestTransitWrapperSealsAndOpensThroughOpenBao(t *testing.T) {
	srv := baotest.Start(t)
	w := openbao.NewTransitWrapper(srv.Client, baotest.TransitMount, baotest.KEK)

	rec, err := envelope.Seal(ctx, w, binding(), []byte("s3cr3t"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.KEKID != baotest.KEK || rec.KEKVersion != 1 || !bytes.HasPrefix(rec.WrappedDEK, []byte("vault:v1:")) {
		t.Fatalf("unexpected wrapped key: %s v%d %q", rec.KEKID, rec.KEKVersion, rec.WrappedDEK)
	}
	got, err := envelope.Open(ctx, w, binding(), rec)
	if err != nil || string(got) != "s3cr3t" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestTransitRotationRewrapAndRetirement(t *testing.T) {
	srv := baotest.Start(t)
	w := openbao.NewTransitWrapper(srv.Client, baotest.TransitMount, baotest.KEK)
	rec, err := envelope.Seal(ctx, w, binding(), []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Client.TransitRotate(ctx, baotest.TransitMount, baotest.KEK); err != nil {
		t.Fatal(err)
	}
	next, err := envelope.Rewrap(ctx, w, rec)
	if err != nil {
		t.Fatal(err)
	}
	if next.KEKVersion != 2 || !bytes.HasPrefix(next.WrappedDEK, []byte("vault:v2:")) {
		t.Fatalf("rewrap gave v%d %q", next.KEKVersion, next.WrappedDEK)
	}
	if err := srv.Client.TransitSetMinDecryptionVersion(ctx, baotest.TransitMount, baotest.KEK, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Open(ctx, w, binding(), rec); err == nil {
		t.Fatal("a record under the retired KEK version still opened")
	}
	if got, err := envelope.Open(ctx, w, binding(), next); err != nil || string(got) != "v" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestTransitWrapperRefusesInconsistentRecords(t *testing.T) {
	srv := baotest.Start(t)
	w := openbao.NewTransitWrapper(srv.Client, baotest.TransitMount, baotest.KEK)
	rec, err := envelope.Seal(ctx, w, binding(), []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	lying := rec
	lying.KEKVersion = 2 // the ciphertext says v1
	if _, err := envelope.Open(ctx, w, binding(), lying); err == nil {
		t.Fatal("a record misreporting its KEK version opened")
	}
	other := openbao.NewTransitWrapper(srv.Client, baotest.TransitMount, "hv-kek-other")
	if _, err := envelope.Open(ctx, other, binding(), rec); err == nil {
		t.Fatal("a wrapper holding another KEK opened the record")
	}
	notTransit := rec
	notTransit.WrappedDEK = []byte("not a transit ciphertext")
	if _, err := envelope.Open(ctx, w, binding(), notTransit); err == nil {
		t.Fatal("a non-transit wrapped key was sent to OpenBao")
	}
}

func TestKVRoundTripAndDestroy(t *testing.T) {
	srv := baotest.Start(t)
	c := srv.Client
	if _, err := c.KVGet(ctx, baotest.KVMount, "a/b", 0); !errors.Is(err, openbao.ErrNotFound) {
		t.Fatalf("missing entry: got %v", err)
	}
	if v, err := c.KVPut(ctx, baotest.KVMount, "a/b", map[string]string{"k": "1"}, 0); err != nil || v != 1 {
		t.Fatalf("put: %d %v", v, err)
	}
	if _, err := c.KVPut(ctx, baotest.KVMount, "a/b", map[string]string{"k": "x"}, 0); !errors.Is(err, openbao.ErrCASMismatch) {
		t.Fatalf("cas=0 on an existing entry: got %v", err)
	}
	if v, err := c.KVPut(ctx, baotest.KVMount, "a/b", map[string]string{"k": "2"}, 1); err != nil || v != 2 {
		t.Fatalf("put v2: %d %v", v, err)
	}
	e, err := c.KVGet(ctx, baotest.KVMount, "a/b", 1)
	if err != nil || e.Data["k"] != "1" || e.Version != 1 {
		t.Fatalf("get v1: %+v %v", e, err)
	}
	keys, err := c.KVList(ctx, baotest.KVMount, "a")
	if err != nil || len(keys) != 1 || keys[0] != "b" {
		t.Fatalf("list: %v %v", keys, err)
	}
	if keys, err := c.KVList(ctx, baotest.KVMount, "nothing/here"); err != nil || keys != nil {
		t.Fatalf("list of nothing: %v %v", keys, err)
	}
	if err := c.KVDestroy(ctx, baotest.KVMount, "a/b", []int{1}); err != nil {
		t.Fatal(err)
	}
	md, err := c.KVMetadata(ctx, baotest.KVMount, "a/b")
	if err != nil || md.CurrentVersion != 2 || len(md.Live) != 1 || md.Live[0] != 2 {
		t.Fatalf("metadata after destroy: %+v %v", md, err)
	}
	e, err = c.KVGet(ctx, baotest.KVMount, "a/b", 1)
	if err != nil || !e.Destroyed || len(e.Data) != 0 {
		t.Fatalf("destroyed version: %+v %v", e, err)
	}
}

func TestBadTokenIsRefused(t *testing.T) {
	srv := baotest.Start(t)
	c, err := openbao.New(openbao.Config{Address: srv.Address, Token: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	var apiErr *openbao.APIError
	if _, err := c.KVGet(ctx, baotest.KVMount, "a", 0); !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("got %v", err)
	}
	c.SetToken(srv.Token)
	if _, err := c.KVGet(ctx, baotest.KVMount, "a", 0); !errors.Is(err, openbao.ErrNotFound) {
		t.Fatalf("after SetToken: got %v", err)
	}
}

func TestTransitErrorsPropagate(t *testing.T) {
	srv := baotest.Start(t)
	missing := openbao.NewTransitWrapper(srv.Client, baotest.TransitMount, "no-such-key")
	if _, _, err := missing.GenerateDEK(ctx); err == nil {
		t.Fatal("a data key was generated under a missing KEK")
	}
	w := openbao.NewTransitWrapper(srv.Client, baotest.TransitMount, baotest.KEK)
	forged := envelope.WrappedKey{KEKID: baotest.KEK, KEKVersion: 1, Ciphertext: []byte("vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}
	if _, err := w.RewrapDEK(ctx, forged); err == nil {
		t.Fatal("a forged wrapped key was rewrapped")
	}
	if _, err := w.UnwrapDEK(ctx, forged); err == nil {
		t.Fatal("a forged wrapped key was unwrapped")
	}
	if err := srv.Client.TransitRotate(ctx, baotest.TransitMount, "no-such-key"); err == nil {
		t.Fatal("rotating a missing key succeeded")
	}
	if err := srv.Client.KVDestroy(ctx, baotest.KVMount, "a", nil); err != nil {
		t.Fatalf("destroying no version must be a no-op: %v", err)
	}
	if _, err := srv.Client.KVMetadata(ctx, baotest.KVMount, "missing"); !errors.Is(err, openbao.ErrNotFound) {
		t.Fatalf("metadata of a missing entry: %v", err)
	}
}

func TestLifecycleErrorPaths(t *testing.T) {
	down := fakeServer(t, 500, `{"errors":["internal"]}`)
	if _, err := down.Init(ctx, 1, 1); err == nil {
		t.Error("init")
	}
	if _, err := down.Unseal(ctx, "k"); err == nil {
		t.Error("unseal")
	}
	if err := down.Seal(ctx); err == nil {
		t.Error("seal")
	}
	if err := down.EnableAuth(ctx, "approle", "approle"); err == nil {
		t.Error("enable auth")
	}
	if err := down.PutACLPolicy(ctx, "p", "path \"x\" {}"); err == nil {
		t.Error("policy")
	}
	if err := down.AppRoleWrite(ctx, "approle", "r", nil); err == nil {
		t.Error("role write")
	}
	if _, err := down.AppRoleRoleID(ctx, "approle", "r"); err == nil {
		t.Error("role id")
	}
	if _, err := down.AppRoleSecretID(ctx, "approle", "r"); err == nil {
		t.Error("secret id")
	}
	if _, err := down.AppRoleLogin(ctx, "approle", "a", "b"); err == nil {
		t.Error("login")
	}
	if _, err := down.RenewSelf(ctx); err == nil {
		t.Error("renew")
	}
	if err := down.WaitActive(ctx, 300*time.Millisecond); err == nil {
		t.Error("wait active on a failing server")
	}
	empty := fakeServer(t, 200, `{}`)
	if _, err := empty.AppRoleLogin(ctx, "approle", "a", "b"); err == nil {
		t.Error("a login without a token was accepted")
	}
	if _, err := empty.RenewSelf(ctx); err == nil {
		t.Error("a renewal without auth was accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := down.WaitActive(cancelled, time.Minute); err == nil {
		t.Error("wait active ignored a cancelled context")
	}
	// Last: revoking clears the client's token.
	if err := down.RevokeSelf(ctx); err == nil {
		t.Error("revoke")
	}
}

func TestLifecycleAgainstARealServer(t *testing.T) {
	srv := baotest.StartUninitialized(t)
	c := srv.Client
	res, err := c.Init(ctx, 1, 1)
	if err != nil || len(res.KeysB64) != 1 || res.RootToken == "" {
		t.Fatalf("%+v %v", res, err)
	}
	if st, err := c.Unseal(ctx, res.KeysB64[0]); err != nil || st.Sealed {
		t.Fatalf("%+v %v", st, err)
	}
	if err := c.WaitActive(ctx, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	c.SetToken(res.RootToken)
	if err := c.EnableAuth(ctx, "approle", "approle"); err != nil {
		t.Fatal(err)
	}
	if err := c.PutACLPolicy(ctx, "self", `path "auth/token/renew-self" { capabilities = ["update"] }`); err != nil {
		t.Fatal(err)
	}
	if err := c.AppRoleWrite(ctx, "approle", "r", map[string]any{"token_policies": []string{"self"}, "token_period": "1h"}); err != nil {
		t.Fatal(err)
	}
	roleID, err := c.AppRoleRoleID(ctx, "approle", "r")
	if err != nil {
		t.Fatal(err)
	}
	secretID, err := c.AppRoleSecretID(ctx, "approle", "r")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeSelf(ctx); err != nil {
		t.Fatal(err)
	}
	if ttl, err := c.AppRoleLogin(ctx, "approle", roleID, secretID); err != nil || ttl <= 0 {
		t.Fatalf("login %v %v", ttl, err)
	}
	if ttl, err := c.RenewSelf(ctx); err != nil || ttl <= 0 {
		t.Fatalf("renew %v %v", ttl, err)
	}
	if err := c.Seal(ctx); err == nil {
		t.Fatal("a token without sudo on sys/seal sealed the server")
	}
}
