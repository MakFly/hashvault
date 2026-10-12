package host

import (
	"testing"

	"github.com/MakFly/hashvault/internal/target"
)

func TestPrepareUsesSignedAgentDeliveryWithoutConsumers(t *testing.T) {
	for _, kind := range []target.Kind{target.Docker, target.SSH} {
		t.Run(string(kind), func(t *testing.T) {
			f := newFixture(t)
			a := f.adapter(t, kind)
			r, err := a.Prepare(ctx, desired(3, "value", "api"), target.NewPreparationID())
			if err != nil || r.Items["DATABASE_URL"].Version != 3 || r.Services["api"].Directory == "" {
				t.Fatal(r, err)
			}
			if len(f.transport.consumers.seen) != 0 {
				t.Fatal("preparation restarted release")
			}
		})
	}
}
