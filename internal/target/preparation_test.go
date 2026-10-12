package target

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderPreservesOwnersTargetsAndImmutablePaths(t *testing.T) {
	m, err := ParseManifest([]byte(`{"version":"hv-manifest-1","app":"acme-api","items":{"KEY":{"expose":"env","services":["api"],"uid":"1000","gid":"1000"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	p := Preparation{Version: PreparationVersion, ID: NewPreparationID(), Kind: Swarm, App: m.App, Target: "swarm-main", Env: "prod", PreparedResources: PreparedResources{Items: map[string]PreparedItem{"KEY": {Version: 3, Spec: m.Items["KEY"], ObjectName: "hv_acme-api_key_v3", ObjectID: "object"}}}}
	var out bytes.Buffer
	if err := Render(&out, p, "stack", ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"target":"key"`) || !strings.Contains(out.String(), `"uid":"1000"`) || !strings.Contains(out.String(), `"external":true`) {
		t.Fatal(out.String())
	}
	p.Kind = Docker
	p.Services = map[string]ServiceFiles{"api": {Directory: "/run/hashvault/.generations/" + p.ID + "/acme-api/api", Dotenv: "/run/hashvault/.generations/" + p.ID + "/acme-api/api/.env", Credentials: map[string]string{"KEY": "/etc/credstore.encrypted/.generations/" + p.ID + "/acme-api.KEY"}}}
	out.Reset()
	if err := Render(&out, p, "compose", ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"read_only":true`) {
		t.Fatal(out.String())
	}
	p.Kind = SSH
	out.Reset()
	if err := Render(&out, p, "systemd", "api"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "LoadCredentialEncrypted=acme-api.KEY:") {
		t.Fatal(out.String())
	}
	files := p.Services["api"]
	files.Directory = "/run/hashvault/current/api"
	p.Services["api"] = files
	if err := p.Validate(); err == nil {
		t.Fatal("mutable paths accepted")
	}
}
