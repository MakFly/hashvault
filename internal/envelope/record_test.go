package envelope_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/MakFly/hashvault/internal/envelope"
	"github.com/MakFly/hashvault/internal/envelope/envelopetest"
)

func sealed(t *testing.T) (*envelopetest.Wrapper, envelope.Record) {
	t.Helper()
	w := envelopetest.New("hv-kek-prod")
	rec, err := envelope.Seal(ctx, w, binding(), []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	return w, rec
}

func TestRecordRoundTripsThroughJSON(t *testing.T) {
	w, rec := sealed(t)
	data, err := envelope.MarshalRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	again, err := envelope.MarshalRecord(rec)
	if err != nil || !bytes.Equal(data, again) {
		t.Fatal("the same record must always encode to the same bytes")
	}
	parsed, err := envelope.ParseRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := envelope.Open(ctx, w, binding(), parsed)
	if err != nil || string(got) != "value" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestParseRecordRefusesMalformedInput(t *testing.T) {
	_, rec := sealed(t)
	data, err := envelope.MarshalRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(data)
	cases := map[string]string{
		"not json":         "nope",
		"unknown field":    strings.Replace(valid, `{"v":1`, `{"v":1,"extra":true`, 1),
		"trailing object":  valid + `{}`,
		"future version":   strings.Replace(valid, `"v":1`, `"v":2`, 1),
		"short nonce":      `{"v":1,"kek_id":"k","kek_version":1,"wrapped_dek":"AQ==","nonce":"AAAA","ct":"AAAAAAAAAAAAAAAAAAAAAA=="}`,
		"short ciphertext": `{"v":1,"kek_id":"k","kek_version":1,"wrapped_dek":"AQ==","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ct":"AA=="}`,
		"no kek id":        `{"v":1,"kek_id":"","kek_version":1,"wrapped_dek":"AQ==","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ct":"AAAAAAAAAAAAAAAAAAAAAA=="}`,
		"oversized":        strings.Repeat(" ", 3<<20),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := envelope.ParseRecord([]byte(input)); !errors.Is(err, envelope.ErrInvalidRecord) {
				t.Fatalf("want ErrInvalidRecord, got %v", err)
			}
		})
	}
}

func TestMarshalRecordRefusesAnInvalidRecord(t *testing.T) {
	if _, err := envelope.MarshalRecord(envelope.Record{V: 1}); !errors.Is(err, envelope.ErrInvalidRecord) {
		t.Fatalf("want ErrInvalidRecord, got %v", err)
	}
}

// Parsing arbitrary bytes never panics, and whatever parses re-encodes to an
// equivalent record. Opening a parsed record with an unrelated KEK never
// succeeds.
func FuzzParseRecord(f *testing.F) {
	w := envelopetest.New("hv-kek-prod")
	rec, err := envelope.Seal(ctx, w, binding(), []byte("value"))
	if err != nil {
		f.Fatal(err)
	}
	data, err := envelope.MarshalRecord(rec)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{"v":1}`))
	f.Add([]byte(`[]`))
	other := envelopetest.New("hv-kek-prod")
	f.Fuzz(func(t *testing.T, input []byte) {
		parsed, err := envelope.ParseRecord(input)
		if err != nil {
			return
		}
		out, err := envelope.MarshalRecord(parsed)
		if err != nil {
			t.Fatalf("a parsed record does not re-encode: %v", err)
		}
		again, err := envelope.ParseRecord(out)
		if err != nil || !bytes.Equal(again.Ciphertext, parsed.Ciphertext) || again.KEKVersion != parsed.KEKVersion {
			t.Fatalf("re-encoding changed the record: %v", err)
		}
		if _, err := envelope.Open(ctx, other, binding(), parsed); err == nil {
			t.Fatal("a record opened under an unrelated kek")
		}
		_, _ = envelope.Open(ctx, w, binding(), parsed)
	})
}
