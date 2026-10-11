package iam

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

const validPolicy = `{
  "Version": "hv-1",
  "Statement": [{
    "Sid": "A",
    "Effect": "Allow",
    "Action": "secret:Read",
    "Resource": "hv:prod:secret/*",
    "Condition": {"NumericLessThanEquals": {"hv:MfaAgeSeconds": [900, "60"]}, "Bool": {"hv:Approved": true}}
  }]
}`

func TestParseAcceptsStringsArraysNumbersAndBooleans(t *testing.T) {
	p, err := Parse([]byte(validPolicy))
	if err != nil {
		t.Fatal(err)
	}
	s := p.Statement[0]
	if got := s.Condition["NumericLessThanEquals"]["hv:MfaAgeSeconds"]; !slices.Equal(got, ValueList{"900", "60"}) {
		t.Fatalf("numbers must be kept as their JSON text, got %v", got)
	}
	if got := s.Condition["Bool"]["hv:Approved"]; !slices.Equal(got, ValueList{"true"}) {
		t.Fatalf("booleans must be kept as text, got %v", got)
	}
	if !slices.Equal(s.Action, StringList{"secret:Read"}) {
		t.Fatalf("a single action string must become a one-element list, got %v", s.Action)
	}
}

// Every refusal below is a policy that would otherwise grant or deny less (or
// more) than its author meant. Refusing at parse time is the point.
func TestParseRefusesWhatWouldSilentlyMisbehave(t *testing.T) {
	stmt := func(body string) string {
		return `{"Version":"hv-1","Statement":[{` + body + `}]}`
	}
	base := `"Effect":"Allow","Action":"secret:Read","Resource":"hv:*"`
	cases := map[string]string{
		"not json":              `nope`,
		"trailing data":         validPolicy + `{}`,
		"unknown top field":     `{"Version":"hv-1","Statement":[{` + base + `}],"Extra":1}`,
		"unknown stmt field":    stmt(base + `,"NotAction":"x"`),
		"wrong version":         strings.Replace(stmt(base), "hv-1", "2012-10-17", 1),
		"no statement":          `{"Version":"hv-1","Statement":[]}`,
		"bad effect":            stmt(`"Effect":"allow","Action":"secret:Read","Resource":"hv:*"`),
		"typo in action":        stmt(`"Effect":"Allow","Action":"secret:Publsh","Resource":"hv:*"`),
		"unknown service":       stmt(`"Effect":"Allow","Action":"kms:*","Resource":"hv:*"`),
		"malformed action":      stmt(`"Effect":"Allow","Action":"secret","Resource":"hv:*"`),
		"no action":             stmt(`"Effect":"Allow","Action":[],"Resource":"hv:*"`),
		"aws resource":          stmt(`"Effect":"Allow","Action":"secret:Read","Resource":"arn:aws:s3:::b"`),
		"space in resource":     stmt(`"Effect":"Allow","Action":"secret:Read","Resource":"hv:prod secret"`),
		"no resource":           stmt(`"Effect":"Allow","Action":"secret:Read","Resource":[]`),
		"unknown operator":      stmt(base + `,"Condition":{"StringEqualsIgnoreCase":{"hv:Env":"prod"}}`),
		"unknown key":           stmt(base + `,"Condition":{"StringEquals":{"hv:Enviroment":"prod"}}`),
		"key type mismatch":     stmt(base + `,"Condition":{"StringEquals":{"hv:MfaAgeSeconds":"900"}}`),
		"bad number":            stmt(base + `,"Condition":{"NumericLessThanEquals":{"hv:MfaAgeSeconds":"15min"}}`),
		"bad date":              stmt(base + `,"Condition":{"DateLessThan":{"hv:CurrentTime":"tomorrow"}}`),
		"bad bool":              stmt(base + `,"Condition":{"Bool":{"hv:Approved":"yes"}}`),
		"empty string value":    stmt(base + `,"Condition":{"StringEquals":{"hv:Env":""}}`),
		"object value":          stmt(base + `,"Condition":{"StringEquals":{"hv:Env":{"a":1}}}`),
		"no values":             stmt(base + `,"Condition":{"StringEquals":{"hv:Env":[]}}`),
		"operator without keys": stmt(base + `,"Condition":{"StringEquals":{}}`),
		"bad tag name":          stmt(base + `,"Condition":{"StringEquals":{"hv:PrincipalTag/a b":"x"}}`),
		"target kubernetes":     stmt(base + `,"Condition":{"StringEquals":{"hv:TargetKind":"kubernetes"}}`),
		"target systemd":        stmt(base + `,"Condition":{"StringEquals":{"hv:TargetKind":"systemd"}}`),
		"target like nothing":   stmt(base + `,"Condition":{"StringLike":{"hv:TargetKind":"kube*"}}`),
		"unknown publish mode":  stmt(base + `,"Condition":{"StringEquals":{"hv:PublishMode":"pushed"}}`),
		"bad sid":               stmt(`"Sid":"not ok",` + base),
		"duplicate sid":         `{"Version":"hv-1","Statement":[{"Sid":"A",` + base + `},{"Sid":"A",` + base + `}]}`,
		"oversized":             `{"Version":"hv-1","Statement":[` + strings.Repeat(" ", maxPolicySize) + `]}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("want ErrInvalidPolicy, got %v", err)
			}
		})
	}
}

func TestParseAcceptsPrincipalTagsAndNegatedOperators(t *testing.T) {
	doc := `{"Version":"hv-1","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
	  "Condition":{"StringNotEquals":{"hv:SourceChannel":"tunnel"},"StringLike":{"hv:PrincipalTag/ref":"refs/heads/*"}}}]}`
	if _, err := Parse([]byte(doc)); err != nil {
		t.Fatal(err)
	}
}

// The five publication targets, as the operator names them.
func TestParseAcceptsEveryTargetKind(t *testing.T) {
	for _, kind := range []string{"docker", "ssh", "swarm", "k3s", "k8s"} {
		doc := `{"Version":"hv-1","Statement":[{"Effect":"Allow","Action":"secret:Publish","Resource":"hv:*",
		  "Condition":{"StringEquals":{"hv:TargetKind":"` + kind + `"}}}]}`
		if _, err := Parse([]byte(doc)); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	both := `{"Version":"hv-1","Statement":[{"Effect":"Allow","Action":"secret:Publish","Resource":"hv:*",
	  "Condition":{"StringLike":{"hv:TargetKind":"k?s"}}}]}`
	p, err := Parse([]byte(both))
	if err != nil {
		t.Fatal(err)
	}
	for kind, want := range map[string]Decision{"k3s": Allowed, "k8s": Allowed, "swarm": ImplicitDeny, "ssh": ImplicitDeny} {
		req := Request{Principal: "machine/a", Action: "secret:Publish", Resource: "hv:prod:secret/a/K",
			Context: map[string][]string{"hv:TargetKind": {kind}}}
		if got := Evaluate(PolicySet{Identity: []NamedPolicy{{Name: "p", Policy: p}}}, req); got.Decision != want {
			t.Fatalf("%s: want %s, got %s", kind, want, got.Decision)
		}
	}
}

func TestExpandActionCoversOnlyCatalogActions(t *testing.T) {
	if got := ExpandAction("sys:*"); !slices.Equal(got, []string{"sys:Seal", "sys:Unseal"}) {
		t.Fatalf("got %v", got)
	}
	if got := ExpandAction("*"); len(got) != len(Actions) {
		t.Fatalf("* must cover the whole catalog, got %d of %d", len(got), len(Actions))
	}
	if got := ExpandAction("SECRET:read"); !slices.Equal(got, []string{"secret:Read"}) {
		t.Fatalf("actions are case-insensitive, got %v", got)
	}
}

func TestCatalogIsSortedAndUnique(t *testing.T) {
	if !slices.IsSorted(Actions) {
		t.Fatal("keep Actions sorted: reviews and diffs rely on it")
	}
	if len(slices.Compact(slices.Clone(Actions))) != len(Actions) {
		t.Fatal("duplicate action in the catalog")
	}
	for _, a := range Actions {
		if !actionPattern.MatchString(a) {
			t.Fatalf("catalog action %q does not match the action syntax", a)
		}
	}
	keys := ConditionKeys()
	if !slices.Contains(keys, "hv:PrincipalTag/<name>") || !slices.IsSorted(keys) {
		t.Fatalf("unexpected condition key listing %v", keys)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(validPolicy))
	f.Add([]byte(`{"Version":"hv-1","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			return
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("a parsed policy no longer validates: %v", err)
		}
		// A parsed policy must be safe to evaluate.
		Evaluate(PolicySet{Identity: []NamedPolicy{{Name: "p", Policy: p}}},
			Request{Principal: "human/a", Action: "secret:Read", Resource: "hv:prod:secret/x"})
	})
}
