package dotenv

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	data := `# Laravel
APP_NAME=Acme
export APP_KEY=base64:abc==
DB_PASSWORD='p@ss$word #not a comment'
MAIL_FROM="Acme <no-reply@example.com>"
MULTI="line1\nline2 \"quoted\" back\\slash"
URL=https://example.com # a comment
EMPTY=
SPACED =  value with spaces  
REF=${APP_NAME}-suffix
QREF="$APP_NAME"
`
	got, err := Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"APP_NAME":    "Acme",
		"APP_KEY":     "base64:abc==",
		"DB_PASSWORD": "p@ss$word #not a comment",
		"MAIL_FROM":   "Acme <no-reply@example.com>",
		"MULTI":       "line1\nline2 \"quoted\" back\\slash",
		"URL":         "https://example.com",
		"EMPTY":       "",
		"SPACED":      "value with spaces",
		"REF":         "${APP_NAME}-suffix",
		"QREF":        "$APP_NAME",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries", len(got))
	}
	for _, e := range got {
		if string(e.Value) != want[e.Key] {
			t.Errorf("%s = %q, want %q", e.Key, e.Value, want[e.Key])
		}
		wantRef := e.Key == "REF" || e.Key == "QREF"
		if e.References != wantRef {
			t.Errorf("%s references=%v", e.Key, e.References)
		}
	}
	if got[2].Line != 4 {
		t.Fatalf("line numbers: %d", got[2].Line)
	}
}

func TestParseRefusalsNeverEchoValues(t *testing.T) {
	for name, data := range map[string]string{
		"no equals":         "JUSTAKEY\n",
		"bad key":           "1KEY=x\n",
		"duplicate":         "A=1\nA=s3cr3t\n",
		"open single quote": "A='s3cr3t\n",
		"open double quote": "A=\"s3cr3t\n",
		"dangling escape":   "A=\"s3cr3t\\",
		"junk after quote":  "A='x' s3cr3t\n",
		"junk after dquote": "A=\"x\" s3cr3t\n",
		"line too long":     "A=" + strings.Repeat("x", 2<<20) + "\n",
	} {
		_, err := Parse([]byte(data))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%s: the error echoes the value: %v", name, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("A=1\nB='x'\nC=\"y\\n\"\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := Parse(data)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, e := range entries {
			if seen[e.Key] {
				t.Fatalf("duplicate key %s accepted", e.Key)
			}
			seen[e.Key] = true
		}
	})
}
