package swarm_test

import (
	"testing"
	"time"

	"github.com/MakFly/hashvault/internal/target"
)

func TestPrepareCreatesSecretsBeforeServicesExist(t *testing.T) {
	a := adapter(t, "prepare-first")
	d := target.Desired{App: "prepare-first", Env: "prod", Items: []target.Item{item("KEY", 3, "value", "api")}}
	r, err := a.Prepare(ctx, d, target.NewPreparationID())
	if err != nil || r.Items["KEY"].ObjectName != "hv_prepare-first_key_v3" || r.Items["KEY"].ObjectID == "" {
		t.Fatal(r, err)
	}
	if _, err := daemon.Client.ServiceInspect(ctx, "prepare-first_api"); err == nil {
		t.Fatal("preparation created a service")
	}
	again, err := a.Prepare(ctx, d, target.NewPreparationID())
	if err != nil || again.Items["KEY"].ObjectID != r.Items["KEY"].ObjectID {
		t.Fatal("existing version not reused", again, err)
	}
	removed, err := a.GC(ctx, 0, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range removed {
		if name == r.Items["KEY"].ObjectName {
			t.Fatal("prepared rollback object was collected")
		}
	}
}

func TestPreparationRetainsAnAlreadyPublishedVersion(t *testing.T) {
	a := adapter(t, "prepare-reuse")
	service(t, "prepare-reuse_api", "", nil)
	d := target.Desired{App: "prepare-reuse", Env: "prod", Items: []target.Item{item("KEY", 1, "value", "api")}}
	_ = publish(t, a, d)
	p, err := a.Prepare(ctx, d, target.NewPreparationID())
	if err != nil {
		t.Fatal(err)
	}
	s, err := daemon.Client.SecretInspect(ctx, p.Items["KEY"].ObjectID)
	if err != nil || s.Spec.Labels["hv.prepared"] != "true" {
		t.Fatal(s, err)
	}
	if _, err := a.Prepare(ctx, d, "../invalid"); err == nil {
		t.Fatal("invalid generation accepted")
	}
}
