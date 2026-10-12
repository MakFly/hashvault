package swarm_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MakFly/hashvault/internal/dockerapi"
	"github.com/MakFly/hashvault/internal/dockerapi/dindtest"
	"github.com/MakFly/hashvault/internal/target"
	"github.com/MakFly/hashvault/internal/target/swarm"
)

var (
	ctx    = context.Background()
	daemon *dindtest.Daemon
)

// One swarm daemon for the package: starting dind costs seconds. Tests use
// distinct app and service names so they do not interfere.
func TestMain(m *testing.M) {
	if ok, why := dindtest.Available(); ok {
		var err error
		daemon, err = dindtest.Start(ctx, dindtest.Options{Swarm: true, PullTestImage: true})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else if os.Getenv("HASHVAULT_REQUIRE_INTEGRATION") == "1" {
		fmt.Fprintln(os.Stderr, "dind required:", why)
		os.Exit(1)
	}
	code := m.Run()
	if daemon != nil {
		daemon.Stop()
	}
	os.Exit(code)
}

func requireDaemon(t *testing.T) *dockerapi.Client {
	t.Helper()
	if daemon == nil {
		t.Skip("dind unavailable")
	}
	return daemon.Client
}

func adapter(t *testing.T, stack string) *swarm.Adapter {
	t.Helper()
	a, err := swarm.New(requireDaemon(t), swarm.Config{Name: "swarm-test", Stack: stack, VerifyTimeout: 90 * time.Second, PollInterval: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// service creates a busybox service. With guardFile set, the task exits
// unless /run/secrets/<guardFile> (when present) contains "ok": a bad value
// makes the rolling update fail and Swarm roll back.
func service(t *testing.T, name, guardFile string, mounts []map[string]any) {
	t.Helper()
	cmd := []string{"sleep", "3600"}
	if guardFile != "" {
		f := "/run/secrets/" + guardFile
		cmd = []string{"sh", "-c", fmt.Sprintf(`if [ -f %s ] && [ "$(cat %s)" != ok ]; then exit 1; fi; exec sleep 3600`, f, f)}
	}
	cs := map[string]any{"Image": dindtest.TestImage + ":" + dindtest.TestImageTag, "Command": cmd}
	if mounts != nil {
		cs["Secrets"] = mounts
	}
	spec := map[string]any{
		"Name":           name,
		"TaskTemplate":   map[string]any{"ContainerSpec": cs, "RestartPolicy": map[string]any{"Condition": "none"}},
		"Mode":           map[string]any{"Replicated": map[string]any{"Replicas": 1}},
		"UpdateConfig":   map[string]any{"Parallelism": 1, "FailureAction": "rollback", "Monitor": int64(3 * time.Second), "Order": "stop-first"},
		"RollbackConfig": map[string]any{"Parallelism": 1, "Monitor": int64(2 * time.Second)},
	}
	id, err := daemon.Client.ServiceCreate(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	// Publish only once the first task runs: an update racing the initial
	// deployment is not what these tests are about.
	deadline := time.Now().Add(60 * time.Second)
	for {
		tasks, err := daemon.Client.TaskList(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(tasks) > 0 && tasks[0].Status.State == "running" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("service %s did not start: %+v", name, tasks)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func item(key string, version uint64, value string, services ...string) target.Item {
	spec := target.ItemSpec{Expose: target.File, Target: strings.ToLower(key), Services: services, UID: "0", GID: "0", Mode: "0400"}
	return target.Item{Key: key, Version: version, Resource: "hv:prod:secret/x/" + key, Value: []byte(value), Spec: spec}
}

func mounted(t *testing.T, name string) map[string]string {
	t.Helper()
	svc, err := daemon.Client.ServiceInspect(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	cs := svc.Spec["TaskTemplate"].(map[string]any)["ContainerSpec"].(map[string]any)
	out := map[string]string{}
	refs, _ := cs["Secrets"].([]any)
	for _, r := range refs {
		m := r.(map[string]any)
		out[m["File"].(map[string]any)["Name"].(string)] = m["SecretName"].(string)
	}
	return out
}

func publish(t *testing.T, a *swarm.Adapter, d target.Desired) target.Receipt {
	t.Helper()
	r, err := a.Apply(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(ctx, r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCheckAcceptsAManager(t *testing.T) {
	p, err := adapter(t, "").Check(ctx)
	if err != nil || p.Details["manager"] != "true" {
		t.Fatalf("got %+v, %v", p, err)
	}
}

func TestCheckRefusesANodeOutsideASwarm(t *testing.T) {
	requireDaemon(t)
	plain, err := dindtest.Start(ctx, dindtest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Stop()
	a, err := swarm.New(plain.Client, swarm.Config{Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Check(ctx); !errors.Is(err, target.ErrPosture) {
		t.Fatalf("want ErrPosture, got %v", err)
	}
}

func TestPublishRotateInventoryAndGC(t *testing.T) {
	a := adapter(t, "shop")
	service(t, "shop_api", "", nil)
	service(t, "shop_worker", "", nil)

	d := target.Desired{App: "shop", Env: "prod", Items: []target.Item{
		item("DATABASE_URL", 1, "postgres://v1", "api", "worker"),
		item("API_TOKEN", 1, "tok-v1", "api"),
	}}
	plan, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Create) != 2 || len(plan.Changes) != 2 {
		t.Fatalf("plan %+v", plan)
	}
	publish(t, a, d)
	if got := mounted(t, "shop_api"); got["database_url"] != "hv_shop_database_url_v1" || got["api_token"] != "hv_shop_api_token_v1" {
		t.Fatalf("api mounts %v", got)
	}
	if got := mounted(t, "shop_worker"); len(got) != 1 || got["database_url"] != "hv_shop_database_url_v1" {
		t.Fatalf("worker mounts %v", got)
	}
	if again, err := a.Plan(ctx, d); err != nil || !again.Empty() {
		t.Fatalf("republishing the same versions must be a no-op: %+v %v", again, err)
	}

	d.Items[0] = item("DATABASE_URL", 2, "postgres://v2", "api", "worker")
	r := publish(t, a, d)
	if !slices.Equal(r.Created, []string{"hv_shop_database_url_v2"}) {
		t.Fatalf("created %v", r.Created)
	}
	if got := mounted(t, "shop_worker"); got["database_url"] != "hv_shop_database_url_v2" {
		t.Fatalf("rotation not applied: %v", got)
	}

	inv, err := a.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var shop []string
	for _, p := range inv {
		if p.App == "shop" {
			shop = append(shop, fmt.Sprintf("%s:%v", p.ObjectName, p.InUse))
		}
	}
	want := []string{"hv_shop_api_token_v1:true", "hv_shop_database_url_v1:false", "hv_shop_database_url_v2:true"}
	if !slices.Equal(shop, want) {
		t.Fatalf("inventory %v", shop)
	}
	removed, err := a.GC(ctx, time.Hour, time.Now())
	if err != nil || len(removed) != 0 {
		t.Fatalf("GC within the retention window removed %v, %v", removed, err)
	}
	removed, err = a.GC(ctx, 0, time.Now())
	if err != nil || !slices.Equal(removed, []string{"hv_shop_database_url_v1"}) {
		t.Fatalf("GC removed %v, %v", removed, err)
	}
}

// The migration path: a hand-made secret on a managed file name is replaced,
// foreign mounts on other names are kept.
func TestForeignMountOnAManagedFileIsReplacedOthersKept(t *testing.T) {
	a := adapter(t, "legacy")
	c := requireDaemon(t)
	oldID, err := c.SecretCreate(ctx, "legacy_db_v1", nil, []byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	keepID, err := c.SecretCreate(ctx, "legacy_other_v1", nil, []byte("other"))
	if err != nil {
		t.Fatal(err)
	}
	ref := func(id, name, file string) map[string]any {
		return map[string]any{"SecretID": id, "SecretName": name, "File": map[string]any{"Name": file, "UID": "0", "GID": "0", "Mode": 0o400}}
	}
	service(t, "legacy_api", "", []map[string]any{ref(oldID, "legacy_db_v1", "database_url"), ref(keepID, "legacy_other_v1", "other")})

	d := target.Desired{App: "legacy", Env: "prod", Items: []target.Item{item("DATABASE_URL", 1, "new", "api")}}
	publish(t, a, d)
	got := mounted(t, "legacy_api")
	if got["database_url"] != "hv_legacy_database_url_v1" || got["other"] != "legacy_other_v1" || len(got) != 2 {
		t.Fatalf("mounts %v", got)
	}
}

func TestFailedRolloutIsReportedAndRolledBack(t *testing.T) {
	a := adapter(t, "guarded")
	service(t, "guarded_api", "token", nil)
	good := target.Desired{App: "guarded", Env: "prod", Items: []target.Item{item("TOKEN", 1, "ok", "api")}}
	publish(t, a, good)

	bad := target.Desired{App: "guarded", Env: "prod", Items: []target.Item{item("TOKEN", 2, "bad", "api")}}
	r, err := a.Apply(ctx, bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(ctx, r); !errors.Is(err, target.ErrVerify) {
		t.Fatalf("want ErrVerify, got %v", err)
	}
	if err := a.Rollback(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got := mounted(t, "guarded_api"); got["token"] != "hv_guarded_token_v1" {
		t.Fatalf("after rollback: %v", got)
	}
}

func TestAnObjectWithForeignCoordinatesIsRefused(t *testing.T) {
	a := adapter(t, "spoof")
	c := requireDaemon(t)
	service(t, "spoof_api", "", nil)
	labels := map[string]string{swarm.LabelManaged: "true", swarm.LabelApp: "spoof", swarm.LabelResource: "hv:prod:secret/other/KEY", swarm.LabelVersion: "1"}
	if _, err := c.SecretCreate(ctx, "hv_spoof_key_v1", labels, []byte("planted")); err != nil {
		t.Fatal(err)
	}
	d := target.Desired{App: "spoof", Env: "prod", Items: []target.Item{item("KEY", 1, "real", "api")}}
	if _, err := a.Plan(ctx, d); !errors.Is(err, target.ErrContract) {
		t.Fatalf("plan: want ErrContract, got %v", err)
	}
	if _, err := a.Apply(ctx, d); !errors.Is(err, target.ErrContract) {
		t.Fatalf("apply: want ErrContract, got %v", err)
	}
}

func TestPlanRefusesWhatSwarmCannotHold(t *testing.T) {
	a := adapter(t, "")
	big := target.Desired{App: "big", Env: "prod", Items: []target.Item{item("BLOB", 1, strings.Repeat("x", swarm.MaxValueSize+1), "api")}}
	if _, err := a.Plan(ctx, big); !errors.Is(err, target.ErrContract) {
		t.Fatalf("oversized value: %v", err)
	}
	long := target.Desired{App: strings.Repeat("a", 60), Env: "prod", Items: []target.Item{item("KEY", 1, "v", "api")}}
	if _, err := a.Plan(ctx, long); !errors.Is(err, target.ErrContract) {
		t.Fatalf("name over 64 chars: %v", err)
	}
	if _, err := a.Plan(ctx, target.Desired{App: "x", Env: "prod", Items: []target.Item{item("KEY", 1, "v", "missing")}}); err == nil {
		t.Fatal("a missing service was accepted")
	}
}

func TestObjectNameAndConfig(t *testing.T) {
	if got := swarm.ObjectName("acme-api", "database_url", 12); got != "hv_acme-api_database_url_v12" {
		t.Fatal(got)
	}
	if _, err := swarm.New(nil, swarm.Config{}); err == nil {
		t.Fatal("a nameless target was accepted")
	}
}
