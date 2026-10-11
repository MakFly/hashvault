// Package envelopetest provides an in-memory KeyWrapper for tests. It mimics
// the parts of OpenBao Transit that hashvault relies on (versioned KEK,
// rotation, rewrap, minimum decryption version) and must never be used
// outside tests: its KEKs live in process memory.
package envelopetest

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/MakFly/hashvault/internal/envelope"
)

// Wrapper is a versioned in-memory KEK.
type Wrapper struct {
	mu            sync.Mutex
	id            string
	keys          [][]byte // keys[i] is version i+1
	minDecryption uint32
	issued        [][]byte

	// RetainDEKs keeps the plaintext DEK slices handed to callers, so a test
	// can check that the caller wiped them.
	RetainDEKs bool
	// FailGenerate and FailUnwrap inject errors.
	FailGenerate error
	FailUnwrap   error
}

// New returns a wrapper whose KEK has one version.
func New(id string) *Wrapper {
	w := &Wrapper{id: id, minDecryption: 1}
	w.Rotate()
	return w
}

// Rotate adds a KEK version and makes it the one new DEKs use.
func (w *Wrapper) Rotate() {
	w.mu.Lock()
	defer w.mu.Unlock()
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	w.keys = append(w.keys, key)
}

// SetMinDecryptionVersion refuses to unwrap anything older than v.
func (w *Wrapper) SetMinDecryptionVersion(v uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.minDecryption = v
}

// Issued returns the plaintext DEKs handed out, when RetainDEKs is set.
func (w *Wrapper) Issued() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.issued
}

func (w *Wrapper) latest() (uint32, []byte) {
	n := len(w.keys)
	if n > math.MaxUint32 {
		panic("envelopetest: too many kek versions")
	}
	return uint32(n), w.keys[n-1] // #nosec G115 -- bounded just above
}

func (w *Wrapper) aad(version uint32) []byte {
	return fmt.Appendf(nil, "envelopetest|%s|%d", w.id, version)
}

func (w *Wrapper) wrap(version uint32, kek, dek []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, dek, w.aad(version)), nil
}

func (w *Wrapper) unwrap(wrapped envelope.WrappedKey) ([]byte, error) {
	if wrapped.KEKID != w.id {
		return nil, fmt.Errorf("envelopetest: unknown kek %q", wrapped.KEKID)
	}
	if wrapped.KEKVersion < w.minDecryption || int64(wrapped.KEKVersion) > int64(len(w.keys)) {
		return nil, fmt.Errorf("envelopetest: kek version %d not available", wrapped.KEKVersion)
	}
	if len(wrapped.Ciphertext) < chacha20poly1305.NonceSizeX {
		return nil, errors.New("envelopetest: wrapped key too short")
	}
	aead, err := chacha20poly1305.NewX(w.keys[wrapped.KEKVersion-1])
	if err != nil {
		return nil, err
	}
	nonce, ct := wrapped.Ciphertext[:chacha20poly1305.NonceSizeX], wrapped.Ciphertext[chacha20poly1305.NonceSizeX:]
	return aead.Open(nil, nonce, ct, w.aad(wrapped.KEKVersion))
}

// GenerateDEK implements envelope.KeyWrapper.
func (w *Wrapper) GenerateDEK(_ context.Context) ([]byte, envelope.WrappedKey, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.FailGenerate != nil {
		return nil, envelope.WrappedKey{}, w.FailGenerate
	}
	dek := make([]byte, envelope.DEKSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, envelope.WrappedKey{}, err
	}
	version, kek := w.latest()
	ct, err := w.wrap(version, kek, dek)
	if err != nil {
		return nil, envelope.WrappedKey{}, err
	}
	if w.RetainDEKs {
		w.issued = append(w.issued, dek)
	}
	return dek, envelope.WrappedKey{KEKID: w.id, KEKVersion: version, Ciphertext: ct}, nil
}

// UnwrapDEK implements envelope.KeyWrapper.
func (w *Wrapper) UnwrapDEK(_ context.Context, wrapped envelope.WrappedKey) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.FailUnwrap != nil {
		return nil, w.FailUnwrap
	}
	dek, err := w.unwrap(wrapped)
	if err != nil {
		return nil, err
	}
	if w.RetainDEKs {
		w.issued = append(w.issued, dek)
	}
	return dek, nil
}

// RewrapDEK implements envelope.Rewrapper.
func (w *Wrapper) RewrapDEK(_ context.Context, wrapped envelope.WrappedKey) (envelope.WrappedKey, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	dek, err := w.unwrap(wrapped)
	if err != nil {
		return envelope.WrappedKey{}, err
	}
	defer clear(dek)
	version, kek := w.latest()
	ct, err := w.wrap(version, kek, dek)
	if err != nil {
		return envelope.WrappedKey{}, err
	}
	return envelope.WrappedKey{KEKID: w.id, KEKVersion: version, Ciphertext: ct}, nil
}
