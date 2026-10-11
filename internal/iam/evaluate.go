package iam

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Decision is the outcome of an evaluation.
type Decision string

const (
	// Allowed: an identity Allow applies, no Deny applies, and the
	// permission boundary (if any) allows too.
	Allowed Decision = "Allow"
	// ExplicitDeny: a Deny statement applies. Nothing overrides it.
	ExplicitDeny Decision = "ExplicitDeny"
	// ImplicitDeny: nothing allows the request. This is the default.
	ImplicitDeny Decision = "ImplicitDeny"
)

// NamedPolicy is a policy attached to a principal under a unique name.
type NamedPolicy struct {
	Name   string
	Policy Policy
}

// PolicySet is everything that applies to one principal.
type PolicySet struct {
	// Identity policies grant and deny.
	Identity []NamedPolicy
	// Boundary policies only restrict: with HasBoundary set, a request must
	// also be allowed by a boundary statement. An empty boundary with
	// HasBoundary set denies everything.
	Boundary    []NamedPolicy
	HasBoundary bool
}

// Request is one authorization question.
type Request struct {
	// Principal is the authenticated principal. Empty means the caller is
	// not authenticated, and the answer is always ImplicitDeny.
	Principal string
	// Action is a concrete catalog action, for example "secret:Publish".
	Action string
	// Resource is a concrete resource, for example
	// "hv:prod:secret/acme-api/DATABASE_URL".
	Resource string
	// Context holds the condition keys known for this request. A key may
	// carry several values (principal tags).
	Context map[string][]string
}

// StatementRef points at one statement.
type StatementRef struct {
	Set    string // "identity" or "boundary"
	Policy string
	Index  int
	Sid    string
	Effect Effect
}

// ConditionTrace is the outcome of one operator and key.
type ConditionTrace struct {
	Operator string
	Key      string
	Met      bool
}

// StatementTrace explains why a statement applied or not.
type StatementTrace struct {
	StatementRef
	ActionMatch   bool
	ResourceMatch bool
	Conditions    []ConditionTrace
	Applies       bool
}

// Result is the decision and the statements that produced it.
type Result struct {
	Decision Decision
	// Reason is a one-line explanation for logs and the simulator.
	Reason string
	// Matched lists the statements that applied, in a canonical order
	// (identity before boundary, then policy name, then index).
	Matched []StatementRef
	// Trace is filled by Simulate only: every statement, applied or not.
	Trace []StatementTrace
}

// Evaluate answers a request. It has no side effect and its answer does not
// depend on the order of policies or statements.
func Evaluate(set PolicySet, req Request) Result {
	return evaluate(set, req, false)
}

// Simulate is Evaluate plus a trace of every statement, for
// `hashvault iam simulate`.
func Simulate(set PolicySet, req Request) Result {
	return evaluate(set, req, true)
}

func evaluate(set PolicySet, req Request, trace bool) Result {
	if req.Principal == "" {
		return Result{Decision: ImplicitDeny, Reason: "request is not authenticated"}
	}
	if !slices.Contains(Actions, req.Action) {
		return Result{Decision: ImplicitDeny, Reason: fmt.Sprintf("unknown action %q", req.Action)}
	}
	// A request names one concrete resource: wildcards there would let a
	// caller ask about a pattern instead of an object.
	if err := validateResourceText(req.Resource); err != nil || !strings.HasPrefix(req.Resource, "hv:") ||
		strings.ContainsAny(req.Resource, "*?") {
		return Result{Decision: ImplicitDeny, Reason: fmt.Sprintf("invalid resource %q", req.Resource)}
	}
	if dup := duplicateName(set.Identity, set.Boundary); dup != "" {
		return Result{Decision: ImplicitDeny, Reason: fmt.Sprintf("policy name %q is attached twice", dup)}
	}

	var res Result
	identity := scan("identity", set.Identity, req, trace, &res)
	boundary := scan("boundary", set.Boundary, req, trace, &res)

	switch {
	case identity.deny || boundary.deny:
		res.Decision, res.Reason = ExplicitDeny, "an explicit Deny applies"
	case !identity.allow:
		res.Decision, res.Reason = ImplicitDeny, "no identity statement allows the request"
	case set.HasBoundary && !boundary.allow:
		res.Decision, res.Reason = ImplicitDeny, "the permission boundary does not allow the request"
	default:
		res.Decision, res.Reason = Allowed, "allowed by an identity statement"
	}
	return res
}

type scanResult struct{ allow, deny bool }

func scan(setName string, policies []NamedPolicy, req Request, trace bool, res *Result) scanResult {
	sorted := slices.Clone(policies)
	slices.SortFunc(sorted, func(a, b NamedPolicy) int { return cmp.Compare(a.Name, b.Name) })

	var out scanResult
	action := strings.ToLower(req.Action)
	for _, np := range sorted {
		for i, s := range np.Policy.Statement {
			ref := StatementRef{Set: setName, Policy: np.Name, Index: i, Sid: s.Sid, Effect: s.Effect}
			st := StatementTrace{StatementRef: ref}
			st.ActionMatch = slices.ContainsFunc(s.Action, func(a string) bool { return matchGlob(strings.ToLower(a), action) })
			st.ResourceMatch = slices.ContainsFunc(s.Resource, func(r string) bool { return matchGlob(r, req.Resource) })
			conditionsMet := true
			if st.ActionMatch && st.ResourceMatch {
				st.Conditions = conditions(s, req.Context)
				for _, c := range st.Conditions {
					conditionsMet = conditionsMet && c.Met
				}
			}
			st.Applies = st.ActionMatch && st.ResourceMatch && conditionsMet
			if st.Applies {
				res.Matched = append(res.Matched, ref)
				if s.Effect == Deny {
					out.deny = true
				} else {
					out.allow = true
				}
			}
			if trace {
				res.Trace = append(res.Trace, st)
			}
		}
	}
	return out
}

// conditions evaluates every operator and key of a statement, in a stable
// order. All must hold (AND); within one key, any value may match (OR).
func conditions(s Statement, ctx map[string][]string) []ConditionTrace {
	ops := make([]string, 0, len(s.Condition))
	for op := range s.Condition {
		ops = append(ops, op)
	}
	slices.Sort(ops)
	var out []ConditionTrace
	for _, op := range ops {
		keys := make([]string, 0, len(s.Condition[op]))
		for k := range s.Condition[op] {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, key := range keys {
			out = append(out, ConditionTrace{
				Operator: op,
				Key:      key,
				Met:      conditionMet(operators[op], ctx[key], s.Condition[op][key]),
			})
		}
	}
	return out
}

// conditionMet applies one operator. A positive operator needs the key to be
// present and some context value to match some policy value. A negated
// operator holds when the key is absent or no pair matches.
func conditionMet(o operator, contextValues []string, policyValues ValueList) bool {
	matched := false
	for _, c := range contextValues {
		for _, p := range policyValues {
			if o.match(c, p) {
				matched = true
			}
		}
	}
	if o.negated {
		return !matched
	}
	return matched
}

func duplicateName(groups ...[]NamedPolicy) string {
	seen := map[string]bool{}
	for _, g := range groups {
		for _, np := range g {
			if seen[np.Name] {
				return np.Name
			}
			seen[np.Name] = true
		}
	}
	return ""
}
