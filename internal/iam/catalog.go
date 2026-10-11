package iam

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Actions is the closed catalog of actions. A policy naming an action outside
// it is refused at parse time: a typo must not silently grant or deny nothing.
var Actions = []string{
	"approval:Grant",
	"audit:Read",
	"policy:Attach",
	"policy:Get",
	"policy:Put",
	"policy:Simulate",
	"secret:Delete",
	"secret:List",
	"secret:Publish",
	"secret:Read",
	"secret:Rotate",
	"secret:Write",
	"sys:Seal",
	"sys:Unseal",
	"target:List",
	"target:Register",
	"target:Remove",
}

// keyType is the value type of a condition key.
type keyType int

const (
	typeString keyType = iota + 1
	typeNumeric
	typeDate
	typeBool
)

func (t keyType) String() string {
	switch t {
	case typeString:
		return "string"
	case typeNumeric:
		return "numeric"
	case typeDate:
		return "date"
	case typeBool:
		return "bool"
	}
	return "unknown"
}

// conditionKeys is the closed catalog of condition keys and their types.
var conditionKeys = map[string]keyType{
	"hv:ApprovalCount": typeNumeric,
	"hv:Approved":      typeBool,
	"hv:CurrentTime":   typeDate,
	"hv:Env":           typeString,
	"hv:MfaAgeSeconds": typeNumeric,
	"hv:Namespace":     typeString,
	"hv:PlanAction":    typeString,
	"hv:PrincipalType": typeString,
	"hv:PublishMode":   typeString,
	"hv:SourceChannel": typeString,
	"hv:TargetKind":    typeString,
	"hv:TargetName":    typeString,
}

// enumValues closes the value set of some string keys, so that a policy
// conditioned on "hv:TargetKind": "kubernetes" (instead of "k8s") is refused
// rather than never matching. With StringLike and StringNotLike, a pattern
// must match at least one allowed value.
var enumValues = map[string][]string{
	"hv:PrincipalType": {"breakglass", "ci", "human", "machine", "workload"},
	"hv:PublishMode":   {"pull", "push"},
	"hv:SourceChannel": {"agent", "socket", "tunnel"},
	// Publication targets: Docker without Swarm, classic deployment over SSH,
	// Docker Swarm, k3s, and any other Kubernetes distribution.
	"hv:TargetKind": {"docker", "k3s", "k8s", "ssh", "swarm"},
}

func validEnumValue(key, op, v string) bool {
	allowed, ok := enumValues[key]
	if !ok {
		return true
	}
	like := op == "StringLike" || op == "StringNotLike"
	for _, a := range allowed {
		if v == a || like && matchGlob(v, a) {
			return true
		}
	}
	return false
}

// principalTagPrefix introduces free-form tags: hv:PrincipalTag/ref, ...
const principalTagPrefix = "hv:PrincipalTag/"

func lookupKey(key string) (keyType, bool) {
	if t, ok := conditionKeys[key]; ok {
		return t, true
	}
	if tag, ok := strings.CutPrefix(key, principalTagPrefix); ok && validTagName(tag) {
		return typeString, true
	}
	return 0, false
}

func validTagName(tag string) bool {
	if tag == "" || len(tag) > 64 {
		return false
	}
	for _, r := range tag {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// ConditionKeys returns the catalog keys, sorted, for documentation and the
// CLI. Principal tags are listed by their prefix.
func ConditionKeys() []string {
	out := make([]string, 0, len(conditionKeys)+1)
	for k := range conditionKeys {
		out = append(out, k)
	}
	out = append(out, principalTagPrefix+"<name>")
	sort.Strings(out)
	return out
}

// operator describes a condition operator.
type operator struct {
	keyType keyType
	// negated operators hold when the key is absent, and when no context
	// value matches any policy value.
	negated bool
	match   func(contextValue, policyValue string) bool
}

var operators = map[string]operator{
	"StringEquals":             {keyType: typeString, match: func(c, p string) bool { return c == p }},
	"StringNotEquals":          {keyType: typeString, negated: true, match: func(c, p string) bool { return c == p }},
	"StringLike":               {keyType: typeString, match: func(c, p string) bool { return matchGlob(p, c) }},
	"StringNotLike":            {keyType: typeString, negated: true, match: func(c, p string) bool { return matchGlob(p, c) }},
	"NumericLessThanEquals":    {keyType: typeNumeric, match: numeric(func(c, p float64) bool { return c <= p })},
	"NumericGreaterThanEquals": {keyType: typeNumeric, match: numeric(func(c, p float64) bool { return c >= p })},
	"DateLessThan":             {keyType: typeDate, match: date(func(c, p time.Time) bool { return c.Before(p) })},
	"DateGreaterThan":          {keyType: typeDate, match: date(func(c, p time.Time) bool { return c.After(p) })},
	"Bool":                     {keyType: typeBool, match: boolean},
}

func parseNumber(s string) (float64, bool) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

func parseDate(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

func numeric(cmp func(c, p float64) bool) func(string, string) bool {
	return func(c, p string) bool {
		cv, ok1 := parseNumber(c)
		pv, ok2 := parseNumber(p)
		return ok1 && ok2 && cmp(cv, pv)
	}
}

func date(cmp func(c, p time.Time) bool) func(string, string) bool {
	return func(c, p string) bool {
		cv, ok1 := parseDate(c)
		pv, ok2 := parseDate(p)
		return ok1 && ok2 && cmp(cv, pv)
	}
}

func boolean(c, p string) bool {
	cv, err1 := strconv.ParseBool(c)
	pv, err2 := strconv.ParseBool(p)
	return err1 == nil && err2 == nil && cv == pv
}

// validValue reports whether a policy value is usable for a key type, so
// that "NumericLessThanEquals": {"hv:MfaAgeSeconds": "15min"} is refused at
// parse time instead of never matching.
func validValue(t keyType, v string) bool {
	switch t {
	case typeNumeric:
		_, ok := parseNumber(v)
		return ok
	case typeDate:
		_, ok := parseDate(v)
		return ok
	case typeBool:
		_, err := strconv.ParseBool(v)
		return err == nil
	}
	return v != "" && len(v) <= 1024
}
