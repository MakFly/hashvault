// Package envelope implements the hashvault envelope format "hv1".
//
// Every secret version gets its own 256-bit data encryption key (DEK). The
// value is sealed with XChaCha20-Poly1305 under that DEK, and the associated
// data binds the ciphertext to its coordinates (resource, environment,
// version, key encryption key id). A ciphertext copied to another secret,
// another environment or another version therefore fails to open. The DEK is
// stored only in wrapped form, wrapped by a key encryption key (KEK) that a
// KeyWrapper holds: OpenBao Transit in production, never this process.
//
// The specification lives in docs/crypto-spec.md. Any change to the AAD
// encoding or to the record layout is a new format version, never an edit of
// this one.
package envelope

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"regexp"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"
)

// FormatVersion is the record version this package writes and reads.
const FormatVersion = 1

// Limits enforced on both Seal and Open.
const (
	DEKSize             = chacha20poly1305.KeySize
	NonceSize           = chacha20poly1305.NonceSizeX
	MaxPlaintextSize    = 1 << 20
	MaxWrappedKeySize   = 4096
	maxResourceSize     = 1024
	maxKEKIDSize        = 128
	maxCiphertextLength = MaxPlaintextSize + chacha20poly1305.Overhead
)

// aadDomain separates hv1 associated data from any other use of the same
// primitives.
const aadDomain = "hv1"

var (
	// ErrAuthentication is the only error Open returns once the inputs are
	// well formed: a wrong key, a moved ciphertext and a flipped bit are
	// indistinguishable on purpose.
	ErrAuthentication = errors.New("envelope: authentication failed")
	// ErrInvalidRecord reports a record that is malformed before any
	// cryptography runs.
	ErrInvalidRecord = errors.New("envelope: invalid record")
	// ErrInvalidBinding reports coordinates that cannot name a secret.
	ErrInvalidBinding = errors.New("envelope: invalid binding")
	// ErrPlaintextTooLarge reports a value above MaxPlaintextSize.
	ErrPlaintextTooLarge = errors.New("envelope: plaintext too large")
)

var (
	envPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	kekIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// Binding names the secret version a ciphertext belongs to. Every field is
// part of the associated data.
type Binding struct {
	// Resource is the IAM resource of the secret, for example
	// "hv:prod:secret/acme-api/DATABASE_URL".
	Resource string
	// Env is the environment, for example "prod".
	Env string
	// Version is the secret version, starting at 1.
	Version uint64
}

// Validate reports whether the binding can name a secret version.
func (b Binding) Validate() error {
	if b.Resource == "" || len(b.Resource) > maxResourceSize {
		return fmt.Errorf("%w: resource must be 1 to %d bytes", ErrInvalidBinding, maxResourceSize)
	}
	if !utf8.ValidString(b.Resource) {
		return fmt.Errorf("%w: resource is not valid UTF-8", ErrInvalidBinding)
	}
	for _, r := range b.Resource {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("%w: resource contains a control or space character", ErrInvalidBinding)
		}
	}
	if !envPattern.MatchString(b.Env) {
		return fmt.Errorf("%w: env must match %s", ErrInvalidBinding, envPattern)
	}
	if b.Version == 0 {
		return fmt.Errorf("%w: version starts at 1", ErrInvalidBinding)
	}
	return nil
}

// WrappedKey is a DEK wrapped by a versioned KEK.
type WrappedKey struct {
	KEKID      string
	KEKVersion uint32
	Ciphertext []byte
}

func (w WrappedKey) validate() error {
	if err := validateKEKID(w.KEKID); err != nil {
		return err
	}
	if w.KEKVersion == 0 {
		return fmt.Errorf("%w: kek version starts at 1", ErrInvalidRecord)
	}
	if len(w.Ciphertext) == 0 || len(w.Ciphertext) > MaxWrappedKeySize {
		return fmt.Errorf("%w: wrapped key must be 1 to %d bytes", ErrInvalidRecord, MaxWrappedKeySize)
	}
	return nil
}

func validateKEKID(id string) error {
	if len(id) == 0 || len(id) > maxKEKIDSize || !kekIDPattern.MatchString(id) {
		return fmt.Errorf("%w: kek id must match %s and be at most %d bytes", ErrInvalidRecord, kekIDPattern, maxKEKIDSize)
	}
	return nil
}

// KeyWrapper holds the KEK. Implementations never expose it.
type KeyWrapper interface {
	// GenerateDEK returns a fresh DEK of DEKSize bytes and its wrapped form.
	// The caller owns the plaintext DEK and wipes it.
	GenerateDEK(ctx context.Context) (dek []byte, wrapped WrappedKey, err error)
	// UnwrapDEK returns the plaintext DEK. The caller wipes it.
	UnwrapDEK(ctx context.Context, wrapped WrappedKey) ([]byte, error)
}

// Rewrapper re-encrypts a wrapped DEK under the latest version of the same
// KEK without exposing the DEK to the caller.
type Rewrapper interface {
	RewrapDEK(ctx context.Context, wrapped WrappedKey) (WrappedKey, error)
}

// Record is one sealed secret version, as stored.
type Record struct {
	V          int    `json:"v"`
	KEKID      string `json:"kek_id"`
	KEKVersion uint32 `json:"kek_version"`
	WrappedDEK []byte `json:"wrapped_dek"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ct"`
}

func (r Record) wrapped() WrappedKey {
	return WrappedKey{KEKID: r.KEKID, KEKVersion: r.KEKVersion, Ciphertext: r.WrappedDEK}
}

// Validate checks the record layout. It runs no cryptography.
func (r Record) Validate() error {
	if r.V != FormatVersion {
		return fmt.Errorf("%w: unsupported format version %d", ErrInvalidRecord, r.V)
	}
	if err := r.wrapped().validate(); err != nil {
		return err
	}
	if len(r.Nonce) != NonceSize {
		return fmt.Errorf("%w: nonce must be %d bytes", ErrInvalidRecord, NonceSize)
	}
	if len(r.Ciphertext) < chacha20poly1305.Overhead || len(r.Ciphertext) > maxCiphertextLength {
		return fmt.Errorf("%w: ciphertext length out of range", ErrInvalidRecord)
	}
	return nil
}

// AssociatedData returns the hv1 associated data for a binding and a KEK id.
//
// Layout: "hv1" | u32 len | resource | u32 len | env | u64 version |
// u32 len | kek id, integers big-endian. Length prefixes make the encoding
// injective: no two distinct inputs share an output. The KEK version is left
// out on purpose, so that a rewrap does not touch the value ciphertext.
func AssociatedData(b Binding, kekID string) []byte {
	out := make([]byte, 0, len(aadDomain)+4+len(b.Resource)+4+len(b.Env)+8+4+len(kekID))
	out = append(out, aadDomain...)
	out = appendString(out, b.Resource)
	out = appendString(out, b.Env)
	out = binary.BigEndian.AppendUint64(out, b.Version)
	out = appendString(out, kekID)
	return out
}

// appendString writes a length-prefixed field. Callers pass validated
// bindings, whose fields are far below the 4 GiB a u32 prefix can describe;
// a longer field is a programming error, not an input to encode.
func appendString(out []byte, s string) []byte {
	if uint64(len(s)) > math.MaxUint32 {
		panic("envelope: associated data field longer than 4 GiB")
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(s))) // #nosec G115 -- bounded just above
	return append(out, s...)
}

// Seal encrypts plaintext for the given binding under a fresh DEK.
func Seal(ctx context.Context, w KeyWrapper, b Binding, plaintext []byte) (Record, error) {
	if err := b.Validate(); err != nil {
		return Record{}, err
	}
	if len(plaintext) > MaxPlaintextSize {
		return Record{}, ErrPlaintextTooLarge
	}
	dek, wrapped, err := w.GenerateDEK(ctx)
	defer wipe(dek)
	if err != nil {
		return Record{}, fmt.Errorf("envelope: generate dek: %w", err)
	}
	if len(dek) != DEKSize {
		return Record{}, fmt.Errorf("envelope: key wrapper returned a %d-byte dek", len(dek))
	}
	if err := wrapped.validate(); err != nil {
		return Record{}, fmt.Errorf("envelope: key wrapper returned an unusable wrapped key: %w", err)
	}
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return Record{}, fmt.Errorf("envelope: %w", err)
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return Record{}, fmt.Errorf("envelope: nonce: %w", err)
	}
	return Record{
		V:          FormatVersion,
		KEKID:      wrapped.KEKID,
		KEKVersion: wrapped.KEKVersion,
		WrappedDEK: wrapped.Ciphertext,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, AssociatedData(b, wrapped.KEKID)),
	}, nil
}

// Open decrypts a record for the given binding. The caller wipes the result.
func Open(ctx context.Context, w KeyWrapper, b Binding, r Record) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	dek, err := w.UnwrapDEK(ctx, r.wrapped())
	defer wipe(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: unwrap dek: %w", err)
	}
	if len(dek) != DEKSize {
		return nil, ErrAuthentication
	}
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, ErrAuthentication
	}
	plaintext, err := aead.Open(nil, r.Nonce, r.Ciphertext, AssociatedData(b, r.KEKID))
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// Rewrap moves a record to the latest version of its KEK. The value
// ciphertext and nonce are untouched; only the wrapped DEK changes.
func Rewrap(ctx context.Context, rw Rewrapper, r Record) (Record, error) {
	if err := r.Validate(); err != nil {
		return Record{}, err
	}
	next, err := rw.RewrapDEK(ctx, r.wrapped())
	if err != nil {
		return Record{}, fmt.Errorf("envelope: rewrap dek: %w", err)
	}
	if err := next.validate(); err != nil {
		return Record{}, fmt.Errorf("envelope: rewrapper returned an unusable wrapped key: %w", err)
	}
	// The KEK id is bound into the associated data: changing it would make
	// the value unopenable.
	if next.KEKID != r.KEKID {
		return Record{}, fmt.Errorf("envelope: rewrap changed the kek id from %q to %q", r.KEKID, next.KEKID)
	}
	out := r
	out.KEKVersion = next.KEKVersion
	out.WrappedDEK = next.Ciphertext
	return out, nil
}

// wipe zeroes key material. Go may have copied it before (stack growth,
// escape to the heap); this narrows exposure, it does not guarantee none.
func wipe(b []byte) {
	clear(b)
}
