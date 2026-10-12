// Package dotenv parses .env files for `hashvault import dotenv`, the
// migration path of servers deployed over SSH.
//
// It understands what Laravel, Symfony, Node and Rails files contain:
// KEY=value, an optional "export " prefix, comments, single quotes (literal),
// double quotes (with \n, \", \\ escapes) and unquoted values with trailing
// " # comments". It never expands ${VARIABLES}: a value that references
// another one is reported, so the operator decides rather than the parser.
package dotenv

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

var keyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// Entry is one variable.
type Entry struct {
	Key   string
	Value []byte
	Line  int
	// References reports a ${VAR} or $VAR in an unquoted or double-quoted
	// value: dotenv loaders would expand it, hashvault stores it literally.
	References bool
}

// Parse reads a .env file. Duplicate keys and malformed lines are errors
// that name the line, never the value.
func Parse(data []byte) ([]Entry, error) {
	var out []Entry
	seen := map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, rest, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !keyPattern.MatchString(key) {
			return nil, fmt.Errorf("dotenv: line %d is not KEY=value", n)
		}
		if prev, dup := seen[key]; dup {
			return nil, fmt.Errorf("dotenv: %s is set twice (lines %d and %d)", key, prev, n)
		}
		seen[key] = n
		value, refs, err := parseValue(strings.TrimLeft(rest, " \t"))
		if err != nil {
			return nil, fmt.Errorf("dotenv: line %d (%s): %w", n, key, err)
		}
		out = append(out, Entry{Key: key, Value: value, Line: n, References: refs})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("dotenv: %w", err)
	}
	return out, nil
}

var reference = regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*`)

func parseValue(v string) ([]byte, bool, error) {
	switch {
	case strings.HasPrefix(v, "'"):
		end := strings.Index(v[1:], "'")
		if end < 0 {
			return nil, false, fmt.Errorf("unterminated single quote")
		}
		if err := trailing(v[end+2:]); err != nil {
			return nil, false, err
		}
		return []byte(v[1 : end+1]), false, nil
	case strings.HasPrefix(v, `"`):
		var out []byte
		for i := 1; i < len(v); i++ {
			switch c := v[i]; c {
			case '\\':
				if i+1 >= len(v) {
					return nil, false, fmt.Errorf("dangling escape")
				}
				i++
				switch v[i] {
				case 'n':
					out = append(out, '\n')
				case 'r':
					out = append(out, '\r')
				case 't':
					out = append(out, '\t')
				default:
					out = append(out, v[i])
				}
			case '"':
				if err := trailing(v[i+1:]); err != nil {
					return nil, false, err
				}
				return out, reference.Match(out), nil
			default:
				out = append(out, c)
			}
		}
		return nil, false, fmt.Errorf("unterminated double quote")
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	return []byte(v), reference.MatchString(v), nil
}

func trailing(rest string) error {
	rest = strings.TrimSpace(rest)
	if rest != "" && !strings.HasPrefix(rest, "#") {
		return fmt.Errorf("unexpected text after the closing quote")
	}
	return nil
}
