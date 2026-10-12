package cli

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MakFly/hashvault/internal/target"
)

func TestDeploymentCLIExportsPinnedReferencesAndConfirms(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "api.sock")
	tokenFile := filepath.Join(dir, "token")
	manifestFile := filepath.Join(dir, "hashvault.json")
	manifest := `{"version":"hv-manifest-1","app":"acme-api","items":{"KEY":{"expose":"env","services":["api"],"uid":"1000","gid":"1000"}}}`
	_ = os.WriteFile(manifestFile, []byte(manifest), 0o600)
	_ = os.WriteFile(tokenFile, []byte("session"), 0o600)
	m, err := target.ParseManifest([]byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	p := target.Preparation{Version: target.PreparationVersion, ID: target.NewPreparationID(), Target: "swarm-main", Kind: target.Swarm, Env: "prod", App: m.App, PreparedResources: target.PreparedResources{Items: map[string]target.PreparedItem{"KEY": {Version: 3, Spec: m.Items["KEY"], ObjectName: "hv_acme-api_key_v3", ObjectID: "object"}}}}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer session" {
			t.Error("missing machine/operator session")
		}
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/preparations":
			var req struct {
				Target   string            `json:"target"`
				Versions map[string]uint64 `json:"versions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Target != "swarm-main" || req.Versions["KEY"] != 3 {
				t.Error("version pin lost")
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(p)
		case strings.HasSuffix(r.URL.Path, "/confirm"):
			var req map[string]string
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["release"] != "release-one" || req["previous"] != "" {
				t.Error("confirmation changed")
			}
			_, _ = io.WriteString(w, `{"release":"release-one"}`)
		case r.URL.Path == "/v1/preparations":
			if r.URL.Query().Get("app") != "acme-api" {
				t.Error("list scope lost")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"preparations": []target.Preparation{p}})
		case strings.HasPrefix(r.URL.Path, "/v1/publications/"):
			_, _ = io.WriteString(w, `{"publication":null}`)
		default:
			_ = json.NewEncoder(w).Encode(p)
		}
	})}
	go func() { _ = hs.Serve(l) }()
	t.Cleanup(func() { _ = hs.Close() })
	e := env{t: t, dir: dir, sock: sock, tokenFile: tokenFile}
	output := filepath.Join(dir, "preparation.json")
	if out := e.must("", "prepare", "--target", "swarm-main", "--manifest", manifestFile, "--version", "KEY=3", "--output", output); !strings.Contains(out, p.ID) {
		t.Fatal(out)
	}
	for _, args := range [][]string{{"preparation", "get", p.ID}, {"preparation", "list", "--target", "swarm-main", "--app", "acme-api"}, {"publication", "--target", "swarm-main", "--app", "acme-api"}, {"confirm", p.ID, "--release", "release-one"}, {"render", output, "--format", "stack"}} {
		e.must("", args...)
	}
	for _, args := range [][]string{{"prepare"}, {"prepare", "--target", "swarm-main", "--manifest", manifestFile, "--version", "KEY=0"}, {"preparation", "get", "../x"}, {"preparation", "list"}, {"confirm", p.ID}, {"publication"}, {"render"}, {"render", output, "--format", "unknown"}} {
		if code, _, _ := e.run("", args...); code == 0 {
			t.Fatal("invalid invocation accepted", args)
		}
	}
}
