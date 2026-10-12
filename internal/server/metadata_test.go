package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MakFly/hashvault/internal/authn/authntest"
	"github.com/MakFly/hashvault/internal/registry"
)

func TestConsoleMetadataNeverDecryptsValues(t *testing.T) {
	f := newFixture(t, true)
	token := f.login("human/admin", f.admin)
	for _, value := range []string{"first", "second"} {
		if code, _ := f.do(token, "PUT", "/v1/secrets/prod/acme-api/KEY", b64(value)); code != 200 {
			t.Fatal(code)
		}
	}
	if code, _ := f.do(token, "DELETE", "/v1/secrets/prod/acme-api/KEY/versions/1", nil); code != 200 {
		t.Fatal(code)
	}
	code, out := f.do(token, "GET", "/v1/secrets/prod/acme-api/KEY/versions", nil)
	if code != 200 || len(out["versions"].([]any)) != 2 || !out["versions"].([]any)[0].(map[string]any)["destroyed"].(bool) {
		t.Fatal(code, out)
	}
	if code, _ := f.do(token, "GET", "/v1/secrets/prod/acme-api/KEY?version=1", nil); code != 410 {
		t.Fatal("destroyed value was readable")
	}
	if code, _ := f.do(token, "GET", "/v1/secrets/prod/acme-api/KEY/versions", nil); code != 200 {
		t.Fatal(code)
	}
	if code, out := f.do(token, "GET", "/v1/auth/session", nil); code != 200 || out["principal"] != "human/admin" || out["token"] != nil {
		t.Fatal(code, out)
	}
	if code, out := f.do(token, "GET", "/v1/principals", nil); code != 200 || len(out["principals"].([]any)) != 1 {
		t.Fatal(code, out)
	}
	if code, out := f.do(token, "GET", "/v1/policies", nil); code != 200 || len(out["policies"].([]any)) != 1 {
		t.Fatal(code, out)
	}
	f.do(token, "PUT", "/v1/targets/swarm-main", map[string]any{"name": "swarm-main", "kind": "swarm", "env": "prod", "config": map[string]any{"stack": "acme"}})
	if code, out := f.do(token, "GET", "/v1/targets/swarm-main", nil); code != 200 || out["env"] != "prod" {
		t.Fatal(code, out)
	}
	if code, out := f.do(token, "GET", "/v1/publications/swarm-main/acme-api", nil); code != 200 || out["publication"] != nil {
		t.Fatal(code, out)
	}
	if code, out := f.do(token, "GET", "/v1/secrets/prod/missing/KEY/versions", nil); code != 200 || len(out["versions"].([]any)) != 0 {
		t.Fatal(code, out)
	}
	if code, _ := f.do(token, "GET", "/v1/targets/missing", nil); code != 404 {
		t.Fatal(code)
	}
	if code, _ := f.do(token, "GET", "/v1/secrets/INVALID/acme-api/KEY/versions", nil); code != 400 {
		t.Fatal(code)
	}
}

func TestMachineCanPrepareButCannotReadOrChangeValues(t *testing.T) {
	f := newFixture(t, true)
	admin := f.login("human/admin", f.admin)
	f.do(admin, "PUT", "/v1/policies/publisher", []byte(publisher))
	bot := authntest.Ed25519()
	if err := f.reg.PutPrincipal(bg, registry.Principal{Name: "machine/deployer", SSHKey: bot.Line}); err != nil {
		t.Fatal(err)
	}
	f.do(admin, "POST", "/v1/principals/machine/deployer/attach", map[string]any{"policy": "publisher"})
	target := map[string]any{"name": "ssh-web-01", "kind": "ssh", "env": "prod", "config": map[string]any{"agent": "web-01", "recipient": f.recipient, "transport": map[string]any{"type": "ssh"}}}
	f.do(admin, "PUT", "/v1/targets/ssh-web-01", target)
	f.do(admin, "PUT", "/v1/secrets/prod/acme-api/DATABASE_URL", b64("private-value"))
	token := f.login("machine/deployer", bot)
	code, out := f.do(token, "POST", "/v1/preparations", map[string]any{"target": "ssh-web-01", "manifest": manifest()})
	if code != 201 || f.cons.runs != 0 {
		t.Fatal(code, out)
	}
	id := out["id"].(string)
	code, out = f.do(token, "GET", "/v1/preparations/"+id, nil)
	raw, _ := json.Marshal(out)
	if code != 200 || strings.Contains(string(raw), "private-value") {
		t.Fatal(code, out)
	}
	for _, path := range []string{"/v1/secrets/prod/acme-api/DATABASE_URL", "/v1/principals", "/v1/policies", "/v1/targets/ssh-web-01"} {
		if code, _ := f.do(token, "GET", path, nil); code != 403 {
			t.Fatal("machine read exposed", code, path)
		}
	}
	if code, _ := f.do(token, "PUT", "/v1/secrets/prod/acme-api/DATABASE_URL", b64("changed")); code != 403 {
		t.Fatal(code)
	}
	if code, _ := f.do(token, "POST", "/v1/preparations/"+id+"/confirm", map[string]string{"release": "release-one", "previous": ""}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := f.do(token, "GET", "/v1/publications/ssh-web-01/acme-api", nil); code != 200 {
		t.Fatal(code)
	}
	if code, _ := f.do(token, "POST", "/v1/preparations/"+id+"/confirm", map[string]string{"release": "bad\nrelease"}); code != 400 {
		t.Fatal(code)
	}
	if code, _ := f.do(token, "GET", "/v1/preparations/../missing", nil); code == 200 {
		t.Fatal("invalid preparation id accepted")
	}
}
