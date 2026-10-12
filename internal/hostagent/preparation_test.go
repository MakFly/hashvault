package hostagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MakFly/hashvault/internal/target"
)

func TestPreparedGenerationsAreIsolatedAndRestoredAtBoot(t *testing.T) {
	e := newEnv(t)
	first := mkBatch(item("KEY", 1, "old", target.Env, "api"))
	if r := e.agent.Apply(ctx, first); r.Status != Applied {
		t.Fatal(r)
	}
	b := mkBatch(item("KEY", 2, "new", target.Env, "api"))
	b.Preparation = target.NewPreparationID()
	r := e.agent.Apply(ctx, b)
	if r.Status != Applied || r.Resources == nil || e.consumers.calls != 1 {
		t.Fatalf("preparation restarted consumers: %+v", r)
	}
	if got := read(t, filepath.Join(e.cfg.RuntimeDir, b.App, "api", "key")); got != "old" {
		t.Fatal("active release changed")
	}
	files := r.Resources.Services["api"]
	if read(t, filepath.Join(files.Directory, "key")) != "new" || read(t, files.Dotenv) != "KEY='new'\n" {
		t.Fatal("snapshot missing")
	}
	b.Items[0].Value = []byte("overwrite")
	if replay := e.agent.Apply(ctx, b); replay.Status != Refused {
		t.Fatal("immutable snapshot overwritten")
	}
	if read(t, filepath.Join(files.Directory, "key")) != "new" {
		t.Fatal("replay changed snapshot")
	}
	if err := os.RemoveAll(e.cfg.RuntimeDir); err != nil {
		t.Fatal(err)
	}
	if err := e.agent.MaterializeAll(ctx); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(files.Directory, "key")) != "new" || e.consumers.calls != 1 {
		t.Fatal("boot needs vault or restarts services")
	}
	sealed, err := os.ReadFile(files.Credentials["KEY"])
	if err != nil || strings.Contains(string(sealed), "new") {
		t.Fatal("generation persisted plaintext")
	}
}

func TestPreparationRefusesConsumersAndPathTraversal(t *testing.T) {
	e := newEnv(t)
	b := mkBatch(item("KEY", 1, "value", target.Env, "api"))
	b.Preparation = "../../outside"
	if r := e.agent.Apply(ctx, b); r.Status != Refused {
		t.Fatal(r)
	}
	b.Preparation = target.NewPreparationID()
	b.Consumers.Reload = [][]string{{"/bin/true"}}
	if r := e.agent.Apply(ctx, b); r.Status != Refused {
		t.Fatal(r)
	}
	if e.consumers.calls != 0 {
		t.Fatal("refused preparation touched service")
	}
}
