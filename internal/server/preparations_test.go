package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/MakFly/hashvault/internal/registry"
	"github.com/MakFly/hashvault/internal/target"
)

func TestPreparationPinsVersionsWithoutRestartAndConfirmsWithCAS(t *testing.T) {
	f := newFixture(t, true)
	token := f.login("human/admin", f.admin)
	tg := map[string]any{"name": "ssh-web-01", "kind": "ssh", "env": "prod", "config": map[string]any{"agent": "web-01", "recipient": f.recipient, "transport": map[string]any{"type": "ssh"}}}
	if code, out := f.do(token, "PUT", "/v1/targets/ssh-web-01", tg); code != 200 {
		t.Fatal(code, out)
	}
	f.do(token, "PUT", "/v1/secrets/prod/acme-api/DATABASE_URL", b64("first-secret-value"))
	f.do(token, "PUT", "/v1/secrets/prod/acme-api/DATABASE_URL", b64("second-secret-value"))
	code, out := f.do(token, "POST", "/v1/preparations", map[string]any{"target": "ssh-web-01", "manifest": manifest(), "versions": map[string]int{"DATABASE_URL": 1}})
	if code != 201 || f.cons.runs != 0 {
		t.Fatal(code, out, f.cons.runs)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "secret-value") {
		t.Fatal("descriptor leaks plaintext")
	}
	var p target.Preparation
	if err := json.Unmarshal(raw, &p); err != nil || p.Items["DATABASE_URL"].Version != 1 {
		t.Fatal(err, p)
	}
	if _, err := f.reg.GetPublication(bg, p.Target, p.App); err != registry.ErrNotFound {
		t.Fatal("preparation marked active", err)
	}
	if code, _ := f.do(token, "GET", "/v1/preparations/"+p.ID, nil); code != 200 {
		t.Fatal(code)
	}
	if code, out := f.do(token, "GET", "/v1/preparations?target=ssh-web-01&app=acme-api", nil); code != 200 || len(out["preparations"].([]any)) != 1 {
		t.Fatal(code, out)
	}
	confirm := "/v1/preparations/" + p.ID + "/confirm"
	if code, _ := f.do(token, "POST", confirm, map[string]string{"release": "release-one", "previous": ""}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := f.do(token, "POST", confirm, map[string]string{"release": "release-one", "previous": ""}); code != 200 {
		t.Fatal("retry not idempotent", code)
	}
	if code, _ := f.do(token, "POST", confirm, map[string]string{"release": "stale-release", "previous": ""}); code != 409 {
		t.Fatal("stale confirmation accepted", code)
	}
	pub, err := f.reg.GetPublication(bg, p.Target, p.App)
	if err != nil || pub.PreparationID != p.ID || pub.Versions["DATABASE_URL"] != 1 {
		t.Fatal(pub, err)
	}
	if code, _ := f.do(token, "POST", "/v1/preparations", map[string]any{"target": "ssh-web-01", "manifest": manifest(), "versions": map[string]int{"OTHER": 1}}); code != 400 {
		t.Fatal(code)
	}
	if f.cons.runs != 0 {
		t.Fatal("preparation or confirmation restarted services")
	}
}

func TestPreparationRequiresPermissionForEveryKeyAndTarget(t *testing.T) {
	f := newFixture(t, true)
	admin := f.login("human/admin", f.admin)
	f.do(admin, "PUT", "/v1/policies/publisher", []byte(publisher))
	// Existing machine authentication is deliberately reused: no caller can
	// manufacture signed-plan approval context through this new endpoint.
	if code, _ := f.do(admin, "POST", "/v1/preparations", map[string]any{"target": "missing", "manifest": manifest()}); code != 404 {
		t.Fatal(code)
	}
	key := f.admin
	if err := f.reg.PutPrincipal(bg, registry.Principal{Name: "human/no-permission", SSHKey: key.Line}); err != nil {
		t.Fatal(err)
	}
	token := f.login("human/no-permission", key)
	tg := map[string]any{"name": "ssh-web-01", "kind": "ssh", "env": "prod", "config": map[string]any{"agent": "web-01", "recipient": f.recipient, "transport": map[string]any{"type": "ssh"}}}
	f.do(admin, "PUT", "/v1/targets/ssh-web-01", tg)
	if code, out := f.do(token, "POST", "/v1/preparations", map[string]any{"target": "ssh-web-01", "manifest": manifest()}); code != 403 {
		t.Fatal(fmt.Sprint(code, out))
	}
	if f.cons.runs != 0 {
		t.Fatal("unauthorized caller touched consumers")
	}
}
