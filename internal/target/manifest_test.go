package target

import (
	"errors"
	"strings"
	"testing"
)

const goodManifest = `{
  "version": "hv-manifest-1",
  "app": "acme-api",
  "items": {
    "DATABASE_URL": {"expose": "file", "services": ["api", "worker"]},
    "OPENAI_API_KEY": {"expose": "env", "services": ["api"]},
    "TLS_KEY": {"expose": "file", "target": "tls_key", "services": ["api"], "uid": "1000", "gid": "1000", "mode": "0440"}
  }
}`

func TestParseManifestFillsDefaults(t *testing.T) {
	m, err := ParseManifest([]byte(goodManifest))
	if err != nil {
		t.Fatal(err)
	}
	db := m.Items["DATABASE_URL"]
	if db.Target != "database_url" || db.UID != "0" || db.GID != "0" || db.Mode != "0400" || db.FileMode() != 0o400 {
		t.Fatalf("defaults not applied: %+v", db)
	}
	if got := strings.Join(m.Keys(), ","); got != "DATABASE_URL,OPENAI_API_KEY,TLS_KEY" {
		t.Fatalf("keys %s", got)
	}
	if m.Items["TLS_KEY"].FileMode() != 0o440 {
		t.Fatal("explicit mode lost")
	}
}

// Each refusal is a contract mistake that would otherwise surface in
// production, often weeks later.
func TestParseManifestRefusesContractMistakes(t *testing.T) {
	item := func(spec string) string {
		return `{"version":"hv-manifest-1","app":"acme-api","items":{"KEY":` + spec + `}}`
	}
	cases := map[string]string{
		"not json":              `{`,
		"trailing data":         goodManifest + `{}`,
		"wrong version":         strings.Replace(goodManifest, "hv-manifest-1", "1", 1),
		"bad app":               strings.Replace(goodManifest, "acme-api", "Acme", 1),
		"no items":              `{"version":"hv-manifest-1","app":"a","items":{}}`,
		"misspelled field":      item(`{"expose":"file","taget":"x","services":["api"]}`),
		"lowercase key":         `{"version":"hv-manifest-1","app":"a","items":{"key":{"expose":"file","services":["api"]}}}`,
		"bad expose":            item(`{"expose":"volume","services":["api"]}`),
		"uppercase target":      item(`{"expose":"file","target":"KEY","services":["api"]}`),
		"target with a slash":   item(`{"expose":"file","target":"a/b","services":["api"]}`),
		"env with other target": item(`{"expose":"env","target":"other","services":["api"]}`),
		"no service":            item(`{"expose":"file","services":[]}`),
		"bad service":           item(`{"expose":"file","services":["a b"]}`),
		"non numeric uid":       item(`{"expose":"file","services":["api"],"uid":"root"}`),
		"world readable write":  item(`{"expose":"file","services":["api"],"mode":"0666"}`),
		"executable":            item(`{"expose":"file","services":["api"],"mode":"0500"}`),
		"three digit mode":      item(`{"expose":"file","services":["api"],"mode":"400"}`),
		"two keys one mount": `{"version":"hv-manifest-1","app":"a","items":{
			"A":{"expose":"file","target":"same","services":["api"]},
			"B":{"expose":"file","target":"same","services":["api"]}}}`,
		"oversized": strings.Repeat(" ", maxManifestSize+1),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseManifest([]byte(doc)); !errors.Is(err, ErrContract) {
				t.Fatalf("want ErrContract, got %v", err)
			}
		})
	}
}

func TestTheSameTargetInTwoServicesIsFine(t *testing.T) {
	doc := `{"version":"hv-manifest-1","app":"a","items":{
		"A":{"expose":"file","target":"same","services":["api"]},
		"B":{"expose":"file","target":"same","services":["worker"]}}}`
	if _, err := ParseManifest([]byte(doc)); err != nil {
		t.Fatal(err)
	}
}

func TestDesiredValidate(t *testing.T) {
	spec := ItemSpec{Expose: File, Target: "k", Services: []string{"api"}, UID: "0", GID: "0", Mode: "0400"}
	if err := (Desired{App: "a", Items: []Item{{Key: "K", Version: 0, Spec: spec}}}).Validate(); !errors.Is(err, ErrContract) {
		t.Fatalf("version 0: %v", err)
	}
	if err := (Desired{App: "A", Items: nil}).Validate(); !errors.Is(err, ErrContract) {
		t.Fatalf("bad app: %v", err)
	}
	if err := (Desired{App: "a", Items: []Item{{Key: "K", Version: 1, Spec: spec}}}).Validate(); err != nil {
		t.Fatal(err)
	}
	if !(Plan{}).Empty() || (Plan{Create: []string{"x"}}).Empty() {
		t.Fatal("Plan.Empty")
	}
}
