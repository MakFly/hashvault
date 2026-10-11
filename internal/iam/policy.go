// Package iam implements the hashvault policy language and its evaluator.
//
// Policies are JSON documents in the spirit of AWS IAM: statements with an
// Effect, Actions, Resources and Conditions. Evaluation denies by default,
// an explicit Deny always wins, and a permission boundary can only restrict.
// The specification lives in docs/iam-spec.md.
package iam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// PolicyVersion is the only accepted value of a policy's "Version".
const PolicyVersion = "hv-1"

const (
	maxPolicySize   = 64 << 10
	maxStatements   = 64
	maxListSize     = 64
	maxResourceSize = 1024
)

// Effect is Allow or Deny.
type Effect string

const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// ErrInvalidPolicy wraps every parse and validation error.
var ErrInvalidPolicy = errors.New("iam: invalid policy")

var (
	sidPattern    = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
	actionPattern = regexp.MustCompile(`^(\*|[a-z]+:[A-Za-z*?]+)$`)
)

// StringList accepts a JSON string or an array of strings.
type StringList []string

// UnmarshalJSON implements json.Unmarshaler.
func (l *StringList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*l = StringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("expected a string or an array of strings")
	}
	*l = many
	return nil
}

// ValueList accepts a JSON string, number or boolean, or an array of them,
// and keeps each value as its JSON text (without quotes for strings).
type ValueList []string

// UnmarshalJSON implements json.Unmarshaler.
func (l *ValueList) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		raw = []json.RawMessage{data}
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		v, err := scalar(r)
		if err != nil {
			return err
		}
		out = append(out, v)
	}
	*l = out
	return nil
}

func scalar(r json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(r, &s); err == nil {
		return s, nil
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(r))
	dec.UseNumber()
	if err := dec.Decode(&n); err == nil {
		return n.String(), nil
	}
	var b bool
	if err := json.Unmarshal(r, &b); err == nil {
		return strconv.FormatBool(b), nil
	}
	return "", errors.New("condition values must be strings, numbers or booleans")
}

// Statement is one rule of a policy.
type Statement struct {
	Sid       string                          `json:"Sid,omitempty"`
	Effect    Effect                          `json:"Effect"`
	Action    StringList                      `json:"Action"`
	Resource  StringList                      `json:"Resource"`
	Condition map[string]map[string]ValueList `json:"Condition,omitempty"`
}

// Policy is a parsed and validated policy document.
type Policy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Parse decodes and validates a policy document. Unknown fields, actions,
// condition operators and condition keys are refused.
func Parse(data []byte) (Policy, error) {
	if len(data) > maxPolicySize {
		return Policy{}, fmt.Errorf("%w: document larger than %d bytes", ErrInvalidPolicy, maxPolicySize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	if dec.More() {
		return Policy{}, fmt.Errorf("%w: trailing data", ErrInvalidPolicy)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Validate checks a policy built in code or decoded by Parse.
func (p Policy) Validate() error {
	if p.Version != PolicyVersion {
		return fmt.Errorf("%w: Version must be %q", ErrInvalidPolicy, PolicyVersion)
	}
	if len(p.Statement) == 0 || len(p.Statement) > maxStatements {
		return fmt.Errorf("%w: 1 to %d statements required", ErrInvalidPolicy, maxStatements)
	}
	sids := map[string]bool{}
	for i, s := range p.Statement {
		if err := s.validate(); err != nil {
			return fmt.Errorf("%w: statement %d: %v", ErrInvalidPolicy, i, err)
		}
		if s.Sid != "" {
			if sids[s.Sid] {
				return fmt.Errorf("%w: duplicate Sid %q", ErrInvalidPolicy, s.Sid)
			}
			sids[s.Sid] = true
		}
	}
	return nil
}

func (s Statement) validate() error {
	if s.Sid != "" && !sidPattern.MatchString(s.Sid) {
		return fmt.Errorf("statement id %q must be 1 to 64 letters or digits", s.Sid)
	}
	if s.Effect != Allow && s.Effect != Deny {
		return fmt.Errorf("effect must be %q or %q", Allow, Deny)
	}
	if len(s.Action) == 0 || len(s.Action) > maxListSize {
		return fmt.Errorf("1 to %d actions required", maxListSize)
	}
	for _, a := range s.Action {
		if err := validateActionPattern(a); err != nil {
			return err
		}
	}
	if len(s.Resource) == 0 || len(s.Resource) > maxListSize {
		return fmt.Errorf("1 to %d resources required", maxListSize)
	}
	for _, r := range s.Resource {
		if err := validateResourcePattern(r); err != nil {
			return err
		}
	}
	for op, keys := range s.Condition {
		o, ok := operators[op]
		if !ok {
			return fmt.Errorf("unknown condition operator %q", op)
		}
		if len(keys) == 0 {
			return fmt.Errorf("operator %q has no key", op)
		}
		for key, values := range keys {
			t, ok := lookupKey(key)
			if !ok {
				return fmt.Errorf("unknown condition key %q", key)
			}
			if t != o.keyType {
				return fmt.Errorf("operator %q expects a %s key, %q is %s", op, o.keyType, key, t)
			}
			if len(values) == 0 || len(values) > maxListSize {
				return fmt.Errorf("%s %s: 1 to %d values required", op, key, maxListSize)
			}
			for _, v := range values {
				if !validValue(t, v) {
					return fmt.Errorf("%s %s: %q is not a valid %s value", op, key, v, t)
				}
				if !validEnumValue(key, op, v) {
					return fmt.Errorf("%s %s: %q is none of %v", op, key, v, enumValues[key])
				}
			}
		}
	}
	return nil
}

// validateActionPattern requires a pattern to cover at least one catalog
// action, which turns a typo such as "secret:Publsh" into a parse error.
func validateActionPattern(a string) error {
	if !actionPattern.MatchString(a) {
		return fmt.Errorf("action %q must be \"*\" or service:Name", a)
	}
	for _, known := range Actions {
		if matchGlob(strings.ToLower(a), strings.ToLower(known)) {
			return nil
		}
	}
	return fmt.Errorf("action %q matches no known action", a)
}

func validateResourcePattern(r string) error {
	if r == "*" {
		return nil
	}
	if err := validateResourceText(r); err != nil {
		return err
	}
	if !strings.HasPrefix(r, "hv:") {
		return fmt.Errorf("resource %q must be \"*\" or start with \"hv:\"", r)
	}
	return nil
}

func validateResourceText(r string) error {
	if r == "" || len(r) > maxResourceSize {
		return fmt.Errorf("resource must be 1 to %d bytes", maxResourceSize)
	}
	for _, c := range r {
		if unicode.IsControl(c) || unicode.IsSpace(c) || c == unicode.ReplacementChar {
			return fmt.Errorf("resource %q contains a control, space or invalid character", r)
		}
	}
	return nil
}

// ExpandAction returns the catalog actions a pattern covers, sorted.
func ExpandAction(pattern string) []string {
	var out []string
	for _, known := range Actions {
		if matchGlob(strings.ToLower(pattern), strings.ToLower(known)) {
			out = append(out, known)
		}
	}
	sort.Strings(out)
	return out
}
