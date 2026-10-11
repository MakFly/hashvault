package iam

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true},
		{"*", "hv:prod:secret/a/B", true},
		{"", "", true},
		{"", "a", false},
		{"hv:prod:secret/*", "hv:prod:secret/acme/KEY", true},
		{"hv:prod:secret/*", "hv:preprod:secret/acme/KEY", false},
		{"hv:*:secret/acme/*", "hv:prod:secret/acme/KEY", true},
		{"hv:pro?:*", "hv:prod:x", true},
		{"hv:pro?:*", "hv:pro:x", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"**", "abc", true},
		{"a*", "A", false},
		{"é?", "éà", true},
	}
	for _, c := range cases {
		if got := matchGlob(c.pattern, c.s); got != c.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

// A pathological pattern must stay fast: no exponential backtracking.
func TestMatchGlobHasNoExponentialBlowup(t *testing.T) {
	pattern := strings.Repeat("*a", 500) + "*b"
	s := strings.Repeat("a", 1000)
	if matchGlob(pattern, s) {
		t.Fatal("must not match")
	}
}

func globReference(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString(`(?s)\A`)
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString(`\z`)
	return regexp.MustCompile(b.String())
}

// Differential fuzzing against the regexp package as a reference.
func FuzzMatchGlob(f *testing.F) {
	f.Add("hv:*:secret/?", "hv:prod:secret/a")
	f.Add("a*b?c", "aXbYc")
	f.Add("*", "")
	f.Fuzz(func(t *testing.T, pattern, s string) {
		if !utf8.ValidString(pattern) || !utf8.ValidString(s) || len(pattern) > 64 || len(s) > 256 {
			return
		}
		want := globReference(pattern).MatchString(s)
		if got := matchGlob(pattern, s); got != want {
			t.Fatalf("matchGlob(%q, %q) = %v, regexp says %v", pattern, s, got, want)
		}
	})
}
