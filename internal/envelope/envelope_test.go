package envelope_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/MakFly/hashvault/internal/envelope"
	"github.com/MakFly/hashvault/internal/envelope/envelopetest"
)

var ctx = context.Background()

func binding() envelope.Binding {
	return envelope.Binding{Resource: "hv:prod:secret/acme-api/DATABASE_URL", Env: "prod", Version: 3}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The primitive itself, against draft-irtf-cfrg-xchacha appendix A.3.1. If a
// dependency update ever swapped the construction, this fails before any
// hashvault logic is involved.
func TestXChaCha20Poly1305MatchesTheDraftVector(t *testing.T) {
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex(t, "404142434445464748494a4b4c4d4e4f5051525354555657")
	aad := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	plaintext := mustHex(t, "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
	want := mustHex(t, "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49")

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	if got := aead.Seal(nil, nonce, plaintext, aad); !bytes.Equal(got, want) {
		t.Fatalf("ciphertext mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestSealThenOpenReturnsTheValue(t *testing.T) {
	w := envelopetest.New("hv-kek-prod")
	value := []byte("postgres://acme:s3cr3t@db:5432/acme")

	rec, err := envelope.Seal(ctx, w, binding(), value)
	if err != nil {
		t.Fatal(err)
	}
	got, err := envelope.Open(ctx, w, binding(), rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("got %q, want %q", got, value)
	}
	if bytes.Contains(rec.Ciphertext, value) {
		t.Fatal("ciphertext contains the plaintext")
	}
}

func TestSealAcceptsAnEmptyValue(t *testing.T) {
	w := envelopetest.New("hv-kek-prod")
	rec, err := envelope.Seal(ctx, w, binding(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := envelope.Open(ctx, w, binding(), rec)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v", got, err)
	}
}

// The point of the associated data: a valid ciphertext moved to other
// coordinates must not open.
func TestOpenRefusesACiphertextMovedToOtherCoordinates(t *testing.T) {
	w := envelopetest.New("hv-kek-prod")
	rec, err := envelope.Seal(ctx, w, binding(), []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	moved := map[string]envelope.Binding{
		"resource": {Resource: "hv:prod:secret/acme-api/STRIPE_KEY", Env: "prod", Version: 3},
		"env":      {Resource: binding().Resource, Env: "preprod", Version: 3},
		"version":  {Resource: binding().Resource, Env: "prod", Version: 2},
	}
	for name, b := range moved {
		t.Run(name, func(t *testing.T) {
			if _, err := envelope.Open(ctx, w, b, rec); !errors.Is(err, envelope.ErrAuthentication) {
				t.Fatalf("want ErrAuthentication, got %v", err)
			}
		})
	}
}

func TestOpenRefusesAnyFlippedBit(t *testing.T) {
	w := envelopetest.New("hv-kek-prod")
	rec, err := envelope.Seal(ctx, w, binding(), []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]func(r *envelope.Record) []byte{
		"ciphertext": func(r *envelope.Record) []byte { return r.Ciphertext },
		"nonce":      func(r *envelope.Record) []byte { return r.Nonce },
		"wrappedDEK": func(r *envelope.Record) []byte { return r.WrappedDEK },
	}
	for name, field := range fields {
		for i := range len(field(&rec)) * 8 {
			tampered := rec
			tampered.Ciphertext = bytes.Clone(rec.Ciphertext)
			tampered.Nonce = bytes.Clone(rec.Nonce)
			tampered.WrappedDEK = bytes.Clone(rec.WrappedDEK)
			field(&tampered)[i/8] ^= 1 << (i % 8)
			if _, err := envelope.Open(ctx, w, binding(), tampered); err == nil {
				t.Fatalf("%s: bit %d flipped and Open still succeeded", name, i)
			}
		}
	}
}

func TestOpenRefusesARecordUnderAnotherKEKID(t *testing.T) {
	w := envelopetest.New("hv-kek-prod")
	rec, err := envelope.Seal(ctx, w, binding(), []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	rec.KEKID = "hv-kek-other"
	if _, err := envelope.Open(ctx, w, binding(), rec); err == nil {
		t.Fatal("a record relabelled to another kek id opened")
	}
}

func TestEverySealUsesAFreshDEKAndNonce(t *testing.T) {
	w := envelopetest.New("hv-kek-prod")
	a, err := envelope.Seal(ctx, w, binding(), []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := envelope.Seal(ctx, w, binding(), []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Nonce, b.Nonce) || bytes.Equal(a.WrappedDEK, b.WrappedDEK) || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("two seals of the same value share a nonce, a dek or a ciphertext")
	}
}

func TestSealAndOpenWipeTheDEK(t *testing.T) {
	w := envelopetest.New("hv-kek-prod")
	w.RetainDEKs = true
	rec, err := envelope.Seal(ctx, w, binding(), []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Open(ctx, w, binding(), rec); err != nil {
		t.Fatal(err)
	}
	issued := w.Issued()
	if len(issued) != 2 {
		t.Fatalf("expected 2 deks handed out, got %d", len(issued))
	}
	for i, dek := range issued {
		if !bytes.Equal(dek, make([]byte, len(dek))) {
			t.Fatalf("dek %d was not wiped", i)
		}
	}
}

func TestRewrapKeepsTheValueOpenableAfterKEKRotation(t *testing.T) {
	w := envelopetest.New("hv-kek-prod")
	rec, err := envelope.Seal(ctx, w, binding(), []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	w.Rotate()
	rewrapped, err := envelope.Rewrap(ctx, w, rec)
	if err != nil {
		t.Fatal(err)
	}
	if rewrapped.KEKVersion != 2 {
		t.Fatalf("want kek version 2, got %d", rewrapped.KEKVersion)
	}
	if !bytes.Equal(rewrapped.Ciphertext, rec.Ciphertext) || !bytes.Equal(rewrapped.Nonce, rec.Nonce) {
		t.Fatal("rewrap must not touch the value ciphertext")
	}
	w.SetMinDecryptionVersion(2)
	if _, err := envelope.Open(ctx, w, binding(), rec); err == nil {
		t.Fatal("the record under the retired kek version still opened")
	}
	got, err := envelope.Open(ctx, w, binding(), rewrapped)
	if err != nil || string(got) != "value" {
		t.Fatalf("got %q, %v", got, err)
	}
}

type relabellingRewrapper struct{ inner *envelopetest.Wrapper }

func (r relabellingRewrapper) RewrapDEK(c context.Context, wk envelope.WrappedKey) (envelope.WrappedKey, error) {
	next, err := r.inner.RewrapDEK(c, wk)
	next.KEKID = "hv-kek-other"
	return next, err
}

func TestRewrapRefusesAKEKIDChange(t *testing.T) {
	w := envelopetest.New("hv-kek-prod")
	rec, err := envelope.Seal(ctx, w, binding(), []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Rewrap(ctx, relabellingRewrapper{w}, rec); err == nil {
		t.Fatal("a rewrap that changes the kek id was accepted")
	}
}

func TestSealRefusesInvalidInputs(t *testing.T) {
	w := envelopetest.New("hv-kek-prod")
	cases := map[string]envelope.Binding{
		"empty resource":   {Resource: "", Env: "prod", Version: 1},
		"space":            {Resource: "hv:prod:secret/a b", Env: "prod", Version: 1},
		"control":          {Resource: "hv:prod:secret/a\nb", Env: "prod", Version: 1},
		"invalid utf8":     {Resource: "hv:\xff", Env: "prod", Version: 1},
		"long resource":    {Resource: "hv:" + string(bytes.Repeat([]byte("a"), 1024)), Env: "prod", Version: 1},
		"uppercase env":    {Resource: "hv:prod:secret/a", Env: "Prod", Version: 1},
		"empty env":        {Resource: "hv:prod:secret/a", Env: "", Version: 1},
		"version zero":     {Resource: "hv:prod:secret/a", Env: "prod", Version: 0},
		"env with a colon": {Resource: "hv:prod:secret/a", Env: "pr:od", Version: 1},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := envelope.Seal(ctx, w, b, []byte("v")); !errors.Is(err, envelope.ErrInvalidBinding) {
				t.Fatalf("want ErrInvalidBinding, got %v", err)
			}
		})
	}
	if _, err := envelope.Seal(ctx, w, binding(), make([]byte, envelope.MaxPlaintextSize+1)); !errors.Is(err, envelope.ErrPlaintextTooLarge) {
		t.Fatalf("want ErrPlaintextTooLarge, got %v", err)
	}
}

type badWrapper struct {
	dek     []byte
	wrapped envelope.WrappedKey
}

func (b badWrapper) GenerateDEK(context.Context) ([]byte, envelope.WrappedKey, error) {
	return b.dek, b.wrapped, nil
}

func (b badWrapper) UnwrapDEK(context.Context, envelope.WrappedKey) ([]byte, error) {
	return b.dek, nil
}

func TestSealRefusesAMisbehavingKeyWrapper(t *testing.T) {
	good := envelope.WrappedKey{KEKID: "k", KEKVersion: 1, Ciphertext: []byte{1}}
	cases := map[string]badWrapper{
		"short dek":       {dek: make([]byte, 16), wrapped: good},
		"no kek id":       {dek: make([]byte, 32), wrapped: envelope.WrappedKey{KEKVersion: 1, Ciphertext: []byte{1}}},
		"kek version 0":   {dek: make([]byte, 32), wrapped: envelope.WrappedKey{KEKID: "k", Ciphertext: []byte{1}}},
		"empty wrapped":   {dek: make([]byte, 32), wrapped: envelope.WrappedKey{KEKID: "k", KEKVersion: 1}},
		"bad kek id char": {dek: make([]byte, 32), wrapped: envelope.WrappedKey{KEKID: "k/1", KEKVersion: 1, Ciphertext: []byte{1}}},
	}
	for name, w := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := envelope.Seal(ctx, w, binding(), []byte("v")); err == nil {
				t.Fatal("seal accepted a misbehaving key wrapper")
			}
		})
	}
}

func TestOpenRefusesAShortDEKFromTheWrapper(t *testing.T) {
	w := envelopetest.New("hv-kek-prod")
	rec, err := envelope.Seal(ctx, w, binding(), []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Open(ctx, badWrapper{dek: make([]byte, 16)}, binding(), rec); !errors.Is(err, envelope.ErrAuthentication) {
		t.Fatalf("want ErrAuthentication, got %v", err)
	}
}

func TestWrapperErrorsPropagate(t *testing.T) {
	w := envelopetest.New("hv-kek-prod")
	rec, err := envelope.Seal(ctx, w, binding(), []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("transit unavailable")
	w.FailGenerate, w.FailUnwrap = boom, boom
	if _, err := envelope.Seal(ctx, w, binding(), []byte("v")); !errors.Is(err, boom) {
		t.Fatalf("seal: want %v, got %v", boom, err)
	}
	if _, err := envelope.Open(ctx, w, binding(), rec); !errors.Is(err, boom) {
		t.Fatalf("open: want %v, got %v", boom, err)
	}
}

// Property: the associated data encoding is injective. Inputs are drawn from
// a tiny alphabet so that concatenation ambiguities ("a"+"bc" vs "ab"+"c")
// actually occur.
func TestAssociatedDataIsInjective(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	word := func() string {
		const alphabet = "ab:"
		b := make([]byte, r.IntN(4))
		for i := range b {
			b[i] = alphabet[r.IntN(len(alphabet))]
		}
		return string(b)
	}
	seen := map[string]string{}
	for range 20000 {
		b := envelope.Binding{Resource: word(), Env: word(), Version: uint64(r.IntN(3))}
		kek := word()
		key := b.Resource + "\x00" + b.Env + "\x00" + string(rune(b.Version)) + "\x00" + kek
		aad := string(envelope.AssociatedData(b, kek))
		if prev, ok := seen[aad]; ok && prev != key {
			t.Fatalf("two inputs share associated data: %q and %q", prev, key)
		}
		seen[aad] = key
	}
}
