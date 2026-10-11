package iam

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func mustParse(t testing.TB, doc string) Policy {
	t.Helper()
	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func example(t *testing.T, name string) NamedPolicy {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "policies", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return NamedPolicy{Name: name, Policy: mustParse(t, string(data))}
}

func identity(p ...NamedPolicy) PolicySet { return PolicySet{Identity: p} }

func TestEvaluateRefusesUnauthenticatedUnknownAndInvalidRequests(t *testing.T) {
	allowAll := NamedPolicy{Name: "all", Policy: mustParse(t, `{"Version":"hv-1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)}
	cases := map[string]Request{
		"unauthenticated":  {Action: "secret:Read", Resource: "hv:prod:secret/a"},
		"unknown action":   {Principal: "human/a", Action: "secret:Steal", Resource: "hv:prod:secret/a"},
		"glob action":      {Principal: "human/a", Action: "secret:*", Resource: "hv:prod:secret/a"},
		"foreign resource": {Principal: "human/a", Action: "secret:Read", Resource: "arn:aws:s3:::b"},
		"space resource":   {Principal: "human/a", Action: "secret:Read", Resource: "hv:prod secret"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Evaluate(identity(allowAll), req); got.Decision != ImplicitDeny {
				t.Fatalf("want ImplicitDeny, got %s (%s)", got.Decision, got.Reason)
			}
		})
	}
	dup := PolicySet{Identity: []NamedPolicy{allowAll}, Boundary: []NamedPolicy{allowAll}, HasBoundary: true}
	if got := Evaluate(dup, Request{Principal: "human/a", Action: "secret:Read", Resource: "hv:prod:secret/a"}); got.Decision != ImplicitDeny {
		t.Fatalf("a policy name attached twice must deny, got %s", got.Decision)
	}
}

// The five documented policies, as a decision table.
func TestExamplePolicies(t *testing.T) {
	type tc struct {
		name   string
		policy string
		req    Request
		want   Decision
	}
	human := func(action, resource string, ctx map[string][]string) Request {
		return Request{Principal: "human/alice", Action: action, Resource: resource, Context: ctx}
	}
	fresh := map[string][]string{"hv:MfaAgeSeconds": {"120"}, "hv:SourceChannel": {"tunnel"}}
	stale := map[string][]string{"hv:MfaAgeSeconds": {"3600"}, "hv:SourceChannel": {"tunnel"}}
	socket := map[string][]string{"hv:MfaAgeSeconds": {"120"}, "hv:SourceChannel": {"socket"}}
	approvedSwarm := map[string][]string{"hv:PlanAction": {"secrets-hashvault"}, "hv:TargetKind": {"swarm"}, "hv:Approved": {"true"}}
	unapproved := map[string][]string{"hv:PlanAction": {"secrets-hashvault"}, "hv:TargetKind": {"swarm"}, "hv:Approved": {"false"}}
	mainRef := map[string][]string{"hv:PrincipalTag/ref": {"refs/heads/main"}}
	pod := map[string][]string{"hv:TargetKind": {"k8s"}, "hv:Namespace": {"acme"}, "hv:PublishMode": {"pull"}}
	glass := func(now string) map[string][]string {
		return map[string][]string{"hv:CurrentTime": {now}, "hv:PrincipalType": {"breakglass"}}
	}

	cases := []tc{
		{"ops reads with fresh mfa", "ops-human", human("secret:Read", "hv:prod:secret/acme-api/DB", fresh), Allowed},
		{"ops with stale mfa", "ops-human", human("secret:Read", "hv:prod:secret/acme-api/DB", stale), ImplicitDeny},
		{"ops outside the tunnel", "ops-human", human("secret:Read", "hv:prod:secret/acme-api/DB", socket), ImplicitDeny},
		{"ops without context", "ops-human", human("secret:Read", "hv:prod:secret/acme-api/DB", nil), ImplicitDeny},
		{"ops cannot edit policies", "ops-human", human("policy:Put", "hv:policy/ops", fresh), ImplicitDeny},

		{"bot publishes approved swarm", "deploy-bot", Request{Principal: "machine/shuttle", Action: "secret:Publish", Resource: "hv:prod:secret/acme-api/DB", Context: approvedSwarm}, Allowed},
		{"bot publish unapproved", "deploy-bot", Request{Principal: "machine/shuttle", Action: "secret:Publish", Resource: "hv:prod:secret/acme-api/DB", Context: unapproved}, ImplicitDeny},
		{"bot publish to another target", "deploy-bot", Request{Principal: "machine/shuttle", Action: "secret:Publish", Resource: "hv:prod:target/k3s-lab", Context: approvedSwarm}, ImplicitDeny},
		{"bot never reads", "deploy-bot", Request{Principal: "machine/shuttle", Action: "secret:Read", Resource: "hv:prod:secret/acme-api/DB", Context: approvedSwarm}, ExplicitDeny},
		{"bot never edits policies", "deploy-bot", Request{Principal: "machine/shuttle", Action: "policy:Put", Resource: "hv:policy/x"}, ExplicitDeny},

		{"ci publishes preprod from main", "ci-preprod", Request{Principal: "ci/github/acme", Action: "secret:Publish", Resource: "hv:preprod:secret/acme-api/DB", Context: mainRef}, Allowed},
		{"ci from a branch", "ci-preprod", Request{Principal: "ci/github/acme", Action: "secret:Publish", Resource: "hv:preprod:secret/acme-api/DB", Context: map[string][]string{"hv:PrincipalTag/ref": {"refs/heads/feat"}}}, ImplicitDeny},
		{"ci touches prod", "ci-preprod", Request{Principal: "ci/github/acme", Action: "secret:List", Resource: "hv:prod:secret/acme-api/DB", Context: mainRef}, ExplicitDeny},

		{"pod pulls its own secret", "workload-pull", Request{Principal: "workload/k8s/lab/acme/api", Action: "secret:Read", Resource: "hv:prod:secret/acme-api/DB", Context: pod}, Allowed},
		{"pod pulls another app", "workload-pull", Request{Principal: "workload/k8s/lab/acme/api", Action: "secret:Read", Resource: "hv:prod:secret/billing/DB", Context: pod}, ImplicitDeny},
		{"pod in another namespace", "workload-pull", Request{Principal: "workload/k8s/lab/other/api", Action: "secret:Read", Resource: "hv:prod:secret/acme-api/DB", Context: map[string][]string{"hv:TargetKind": {"k8s"}, "hv:Namespace": {"other"}, "hv:PublishMode": {"pull"}}}, ImplicitDeny},

		{"break glass before expiry", "break-glass", Request{Principal: "breakglass/1", Action: "sys:Unseal", Resource: "hv:sys:unseal", Context: glass("2026-11-01T00:00:00Z")}, Allowed},
		{"break glass after expiry", "break-glass", Request{Principal: "breakglass/1", Action: "sys:Unseal", Resource: "hv:sys:unseal", Context: glass("2027-01-01T00:00:00Z")}, ImplicitDeny},
		{"break glass cannot write", "break-glass", Request{Principal: "breakglass/1", Action: "secret:Write", Resource: "hv:prod:secret/a", Context: glass("2026-11-01T00:00:00Z")}, ImplicitDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(identity(example(t, c.policy)), c.req)
			if got.Decision != c.want {
				t.Fatalf("want %s, got %s (%s)", c.want, got.Decision, got.Reason)
			}
		})
	}
}

func TestNegatedOperatorsHoldWhenTheKeyIsAbsent(t *testing.T) {
	set := identity(
		NamedPolicy{Name: "allow", Policy: mustParse(t, `{"Version":"hv-1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)},
		NamedPolicy{Name: "deny", Policy: mustParse(t, `{"Version":"hv-1","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
		  "Condition":{"StringNotEquals":{"hv:SourceChannel":"tunnel"}}}]}`)},
	)
	req := Request{Principal: "human/a", Action: "secret:Read", Resource: "hv:prod:secret/a"}
	if got := Evaluate(set, req); got.Decision != ExplicitDeny {
		t.Fatalf("a missing channel must trigger the deny, got %s", got.Decision)
	}
	req.Context = map[string][]string{"hv:SourceChannel": {"tunnel"}}
	if got := Evaluate(set, req); got.Decision != Allowed {
		t.Fatalf("the tunnel must pass, got %s", got.Decision)
	}
}

func TestBoundaryRestricts(t *testing.T) {
	allowAll := NamedPolicy{Name: "all", Policy: mustParse(t, `{"Version":"hv-1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)}
	readOnly := NamedPolicy{Name: "ro", Policy: mustParse(t, `{"Version":"hv-1","Statement":[{"Effect":"Allow","Action":"secret:Read","Resource":"*"}]}`)}
	set := PolicySet{Identity: []NamedPolicy{allowAll}, Boundary: []NamedPolicy{readOnly}, HasBoundary: true}
	read := Request{Principal: "human/a", Action: "secret:Read", Resource: "hv:prod:secret/a"}
	write := Request{Principal: "human/a", Action: "secret:Write", Resource: "hv:prod:secret/a"}
	if got := Evaluate(set, read); got.Decision != Allowed {
		t.Fatalf("read: got %s", got.Decision)
	}
	if got := Evaluate(set, write); got.Decision != ImplicitDeny {
		t.Fatalf("write: got %s", got.Decision)
	}
	empty := PolicySet{Identity: []NamedPolicy{allowAll}, HasBoundary: true}
	if got := Evaluate(empty, read); got.Decision != ImplicitDeny {
		t.Fatalf("an empty boundary must deny everything, got %s", got.Decision)
	}
}

func TestSimulateTracesEveryStatement(t *testing.T) {
	set := identity(example(t, "deploy-bot"))
	req := Request{Principal: "machine/shuttle", Action: "secret:Read", Resource: "hv:prod:secret/a"}
	res := Simulate(set, req)
	if res.Decision != ExplicitDeny || len(res.Trace) != 2 {
		t.Fatalf("got %s with %d traced statements", res.Decision, len(res.Trace))
	}
	if res.Trace[0].ActionMatch || res.Trace[0].Applies {
		t.Fatal("the publish statement must not match a read")
	}
	if !res.Trace[1].Applies || res.Trace[1].Sid != "DeployBotNeverReads" {
		t.Fatalf("the deny statement must be the one that applied: %+v", res.Trace[1])
	}
	if len(res.Matched) != 1 || res.Matched[0].Sid != "DeployBotNeverReads" {
		t.Fatalf("matched: %+v", res.Matched)
	}
	if Evaluate(set, req).Trace != nil {
		t.Fatal("Evaluate must not build a trace")
	}
}

// ---- Properties ----------------------------------------------------------

var (
	propActions   = []string{"*", "secret:*", "secret:Read", "secret:Publish", "sys:Unseal", "policy:*"}
	propResources = []string{"*", "hv:*", "hv:prod:*", "hv:prod:secret/a/*", "hv:preprod:secret/*", "hv:prod:secret/a/K"}
	propReqAct    = []string{"secret:Read", "secret:Publish", "sys:Unseal", "policy:Put"}
	propReqRes    = []string{"hv:prod:secret/a/K", "hv:prod:secret/b/K", "hv:preprod:secret/a/K", "hv:sys:unseal"}
)

func genStatement(r *rand.Rand, sid string) Statement {
	s := Statement{
		Sid:      sid,
		Effect:   []Effect{Allow, Allow, Deny}[r.IntN(3)],
		Action:   StringList{propActions[r.IntN(len(propActions))]},
		Resource: StringList{propResources[r.IntN(len(propResources))]},
	}
	switch r.IntN(4) {
	case 0:
		s.Condition = map[string]map[string]ValueList{"StringEquals": {"hv:Env": {[]string{"prod", "preprod"}[r.IntN(2)]}}}
	case 1:
		s.Condition = map[string]map[string]ValueList{"StringNotEquals": {"hv:SourceChannel": {"tunnel"}}}
	case 2:
		s.Condition = map[string]map[string]ValueList{"NumericLessThanEquals": {"hv:MfaAgeSeconds": {"900"}}}
	}
	return s
}

func genPolicy(r *rand.Rand, name string) NamedPolicy {
	n := 1 + r.IntN(3)
	p := Policy{Version: PolicyVersion}
	for i := range n {
		p.Statement = append(p.Statement, genStatement(r, fmt.Sprintf("%sS%d", name, i)))
	}
	return NamedPolicy{Name: name, Policy: p}
}

func genSet(r *rand.Rand) PolicySet {
	var set PolicySet
	for i := range r.IntN(4) {
		set.Identity = append(set.Identity, genPolicy(r, fmt.Sprintf("I%d", i)))
	}
	if r.IntN(3) == 0 {
		set.HasBoundary = true
		for i := range r.IntN(3) {
			set.Boundary = append(set.Boundary, genPolicy(r, fmt.Sprintf("B%d", i)))
		}
	}
	return set
}

func genRequest(r *rand.Rand) Request {
	ctx := map[string][]string{}
	if r.IntN(2) == 0 {
		ctx["hv:Env"] = []string{[]string{"prod", "preprod"}[r.IntN(2)]}
	}
	if r.IntN(2) == 0 {
		ctx["hv:SourceChannel"] = []string{[]string{"tunnel", "socket"}[r.IntN(2)]}
	}
	if r.IntN(2) == 0 {
		ctx["hv:MfaAgeSeconds"] = []string{[]string{"60", "3600"}[r.IntN(2)]}
	}
	return Request{
		Principal: "human/p",
		Action:    propReqAct[r.IntN(len(propReqAct))],
		Resource:  propReqRes[r.IntN(len(propReqRes))],
		Context:   ctx,
	}
}

const propRuns = 20000

func forAll(t *testing.T, seed uint64, check func(r *rand.Rand, set PolicySet, req Request)) {
	t.Helper()
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	for range propRuns {
		set := genSet(r)
		for _, np := range append(slices.Clone(set.Identity), set.Boundary...) {
			if err := np.Policy.Validate(); err != nil {
				t.Fatalf("generator produced an invalid policy: %v", err)
			}
		}
		check(r, set, genRequest(r))
	}
}

func TestPropertyDefaultDeny(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 7))
	for range propRuns {
		if got := Evaluate(PolicySet{}, genRequest(r)); got.Decision != ImplicitDeny {
			t.Fatalf("no policy must mean ImplicitDeny, got %s", got.Decision)
		}
	}
}

func TestPropertyAddingADenyNeverGrants(t *testing.T) {
	forAll(t, 11, func(r *rand.Rand, set PolicySet, req Request) {
		before := Evaluate(set, req).Decision
		deny := genStatement(r, "X")
		deny.Effect = Deny
		more := set
		more.Identity = append(slices.Clone(set.Identity), NamedPolicy{Name: "extra", Policy: Policy{Version: PolicyVersion, Statement: []Statement{deny}}})
		after := Evaluate(more, req).Decision
		if after == Allowed && before != Allowed {
			t.Fatalf("adding a Deny turned %s into Allow", before)
		}
	})
}

func TestPropertyAddingAnAllowNeverDenies(t *testing.T) {
	forAll(t, 13, func(r *rand.Rand, set PolicySet, req Request) {
		before := Evaluate(set, req).Decision
		allow := genStatement(r, "X")
		allow.Effect = Allow
		more := set
		more.Identity = append(slices.Clone(set.Identity), NamedPolicy{Name: "extra", Policy: Policy{Version: PolicyVersion, Statement: []Statement{allow}}})
		if before == Allowed && Evaluate(more, req).Decision != Allowed {
			t.Fatal("adding an identity Allow revoked an Allow")
		}
	})
}

func TestPropertyBoundaryOnlyRestricts(t *testing.T) {
	forAll(t, 17, func(_ *rand.Rand, set PolicySet, req Request) {
		with := Evaluate(set, req).Decision
		without := set
		without.Boundary, without.HasBoundary = nil, false
		if with == Allowed && Evaluate(without, req).Decision != Allowed {
			t.Fatal("a boundary granted something the identity policies alone do not")
		}
	})
}

func TestPropertyExplicitDenyWins(t *testing.T) {
	forAll(t, 19, func(_ *rand.Rand, set PolicySet, req Request) {
		res := Evaluate(set, req)
		anyDeny := slices.ContainsFunc(res.Matched, func(m StatementRef) bool { return m.Effect == Deny })
		if anyDeny != (res.Decision == ExplicitDeny) {
			t.Fatalf("decision %s does not follow the matched statements %+v", res.Decision, res.Matched)
		}
	})
}

func TestPropertyOrderDoesNotMatter(t *testing.T) {
	forAll(t, 23, func(r *rand.Rand, set PolicySet, req Request) {
		want := Evaluate(set, req)
		shuffled := PolicySet{HasBoundary: set.HasBoundary}
		for _, group := range []struct {
			in  []NamedPolicy
			out *[]NamedPolicy
		}{{set.Identity, &shuffled.Identity}, {set.Boundary, &shuffled.Boundary}} {
			for _, np := range group.in {
				p := np.Policy
				p.Statement = slices.Clone(p.Statement)
				r.Shuffle(len(p.Statement), func(i, j int) { p.Statement[i], p.Statement[j] = p.Statement[j], p.Statement[i] })
				*group.out = append(*group.out, NamedPolicy{Name: np.Name, Policy: p})
			}
			r.Shuffle(len(*group.out), func(i, j int) { (*group.out)[i], (*group.out)[j] = (*group.out)[j], (*group.out)[i] })
		}
		got := Evaluate(shuffled, req)
		if got.Decision != want.Decision {
			t.Fatalf("shuffling changed the decision: %s then %s", want.Decision, got.Decision)
		}
		sids := func(refs []StatementRef) []string {
			var out []string
			for _, m := range refs {
				out = append(out, m.Set+"/"+m.Policy+"/"+m.Sid)
			}
			slices.Sort(out)
			return out
		}
		if !slices.Equal(sids(got.Matched), sids(want.Matched)) {
			t.Fatalf("shuffling changed the matched statements: %v then %v", sids(want.Matched), sids(got.Matched))
		}
	})
}
