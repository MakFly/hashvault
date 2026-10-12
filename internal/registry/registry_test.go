package registry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/MakFly/hashvault/internal/openbao/baotest"
	"github.com/MakFly/hashvault/internal/target"
)

var ctx = context.Background()

func reg(t *testing.T) *Registry {
	t.Helper()
	srv := baotest.Start(t)
	return New(srv.Client, baotest.KVMount)
}

func edKey(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func skKey(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	blob := ssh.Marshal(struct {
		Type   string
		PubKey []byte
		App    string
	}{ssh.KeyAlgoSKED25519, pub, "ssh:"})
	k, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

const opsPolicy = `{"Version":"hv-1","Statement":[{"Effect":"Allow","Action":"secret:*","Resource":"hv:*"}]}`

func TestPrincipalsLifecycle(t *testing.T) {
	r := reg(t)
	alice := Principal{Name: "human/alice", SSHKey: skKey(t), Policies: []string{"ops"}, Tags: map[string]string{"team": "core"}}
	if err := r.PutPrincipal(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if err := r.PutPrincipal(ctx, alice); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a principal was replaced: %v", err)
	}
	bot := Principal{Name: "machine/deployer", SSHKey: edKey(t)}
	if err := r.PutPrincipal(ctx, bot); err != nil {
		t.Fatal(err)
	}
	names, err := r.ListPrincipals(ctx)
	if err != nil || !slices.Equal(names, []string{"human/alice", "machine/deployer"}) {
		t.Fatalf("%v %v", names, err)
	}
	got, err := r.GetPrincipal(ctx, "human/alice")
	if err != nil || got.Type() != "human" || got.CreatedAt.IsZero() || got.Tags["team"] != "core" {
		t.Fatalf("%+v %v", got, err)
	}
	a, err := got.Authn()
	if err != nil || a.Type != "human" || a.Key.Type() != ssh.KeyAlgoSKED25519 {
		t.Fatalf("%+v %v", a, err)
	}
	if err := r.UpdatePrincipal(ctx, "human/alice", func(p *Principal) error { p.Disabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.GetPrincipal(ctx, "human/alice"); !got.Disabled {
		t.Fatal("disable lost")
	}
	if err := r.UpdatePrincipal(ctx, "human/alice", func(p *Principal) error { p.SSHKey = skKey(t); return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a key was swapped in place: %v", err)
	}
	if err := r.UpdatePrincipal(ctx, "human/nobody", func(*Principal) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update of a missing principal: %v", err)
	}
	if _, err := r.GetPrincipal(ctx, "../etc"); !errors.Is(err, ErrNotFound) {
		t.Fatal("an invalid name was looked up")
	}
}

func TestPrincipalValidation(t *testing.T) {
	r := reg(t)
	for name, p := range map[string]Principal{
		"no type":         {Name: "alice", SSHKey: edKey(t)},
		"bad type":        {Name: "robot/x", SSHKey: edKey(t)},
		"human soft key":  {Name: "human/bob", SSHKey: edKey(t)},
		"bad key":         {Name: "machine/x", SSHKey: "ssh-ed25519 AAAA"},
		"bad policy name": {Name: "machine/x", SSHKey: edKey(t), Policies: []string{"Ops Team"}},
		"bad tag":         {Name: "machine/x", SSHKey: edKey(t), Tags: map[string]string{"a b": "c"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := r.PutPrincipal(ctx, p); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestPoliciesAndPolicySet(t *testing.T) {
	r := reg(t)
	if err := r.PutPolicy(ctx, "ops", []byte(opsPolicy)); err != nil {
		t.Fatal(err)
	}
	if err := r.PutPolicy(ctx, "ops", []byte(opsPolicy)); err != nil {
		t.Fatalf("updating a policy: %v", err)
	}
	if err := r.PutPolicy(ctx, "broken", []byte(`{"Version":"hv-1","Statement":[{"Effect":"Allow","Action":"secret:Publsh","Resource":"*"}]}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a policy with a typo was stored: %v", err)
	}
	if err := r.PutPolicy(ctx, "Bad Name", []byte(opsPolicy)); !errors.Is(err, ErrInvalid) {
		t.Fatal("bad policy name accepted")
	}
	names, _ := r.ListPolicies(ctx)
	if !slices.Equal(names, []string{"ops"}) {
		t.Fatalf("policies %v", names)
	}
	p := Principal{Name: "machine/x", SSHKey: edKey(t), Policies: []string{"ops"}, Boundary: []string{"ops"}}
	set, err := r.PolicySet(ctx, p)
	if err != nil || len(set.Identity) != 1 || len(set.Boundary) != 1 || !set.HasBoundary {
		t.Fatalf("%+v %v", set, err)
	}
	p.Policies = append(p.Policies, "missing")
	if _, err := r.PolicySet(ctx, p); err == nil {
		t.Fatal("a missing policy must fail the set, not shrink it")
	}
	p.Policies, p.Boundary = []string{"ops"}, []string{"gone"}
	if _, err := r.PolicySet(ctx, p); err == nil {
		t.Fatal("a missing boundary must fail the set")
	}
	if _, _, err := r.GetPolicy(ctx, "Bad"); !errors.Is(err, ErrNotFound) {
		t.Fatal("invalid name lookup")
	}
}

func TestTargetsAndPublications(t *testing.T) {
	r := reg(t)
	tg := Target{Name: "swarm-main", Kind: target.Swarm, Env: "prod", Config: json.RawMessage(`{"docker":"unix:///var/run/docker.sock","stack":"acme"}`)}
	if err := r.PutTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	if err := r.PutTarget(ctx, tg); err != nil {
		t.Fatalf("update: %v", err)
	}
	for name, bad := range map[string]Target{
		"bad name":   {Name: "Swarm", Kind: target.Swarm, Env: "prod", Config: json.RawMessage(`{}`)},
		"bad kind":   {Name: "x", Kind: "nomad", Env: "prod", Config: json.RawMessage(`{}`)},
		"bad env":    {Name: "x", Kind: target.Swarm, Env: "Prod", Config: json.RawMessage(`{}`)},
		"bad config": {Name: "x", Kind: target.Swarm, Env: "prod", Config: json.RawMessage(`{`)},
	} {
		if err := r.PutTarget(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	got, err := r.GetTarget(ctx, "swarm-main")
	if err != nil || got.Kind != target.Swarm || got.Env != "prod" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := r.GetTarget(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if names, _ := r.ListTargets(ctx); !slices.Equal(names, []string{"swarm-main"}) {
		t.Fatalf("%v", names)
	}

	pub := Publication{Target: "swarm-main", App: "acme-api", Versions: map[string]uint64{"DB": 3}, By: "human/alice", At: time.Now().UTC()}
	if err := r.RecordPublication(ctx, pub); err != nil {
		t.Fatal(err)
	}
	pub.Versions["DB"] = 4
	if err := r.RecordPublication(ctx, pub); err != nil {
		t.Fatal(err)
	}
	got2, err := r.GetPublication(ctx, "swarm-main", "acme-api")
	if err != nil || got2.Versions["DB"] != 4 {
		t.Fatalf("%+v %v", got2, err)
	}
	if _, err := r.GetPublication(ctx, "swarm-main", "other"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
