package openbao

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	"github.com/MakFly/hashvault/internal/envelope"
)

// transitCiphertext is the Transit ciphertext layout: "vault:v<N>:<base64>".
// OpenBao kept the Vault prefix for compatibility.
var transitCiphertext = regexp.MustCompile(`^vault:v([1-9][0-9]{0,9}):[A-Za-z0-9+/=]+$`)

// TransitCreateKey creates a non-exportable key of the given type
// ("chacha20-poly1305" for hashvault KEKs).
func (c *Client) TransitCreateKey(ctx context.Context, mount, name, keyType string) error {
	return c.do(ctx, http.MethodPost, mount+"/keys/"+name, nil, map[string]any{"type": keyType}, nil)
}

// TransitRotate adds a key version; new data keys use it.
func (c *Client) TransitRotate(ctx context.Context, mount, name string) error {
	return c.do(ctx, http.MethodPost, mount+"/keys/"+name+"/rotate", nil, nil, nil)
}

// TransitSetMinDecryptionVersion refuses to decrypt anything older than v.
func (c *Client) TransitSetMinDecryptionVersion(ctx context.Context, mount, name string, v int) error {
	return c.do(ctx, http.MethodPost, mount+"/keys/"+name+"/config", nil, map[string]any{"min_decryption_version": v}, nil)
}

type transitData struct {
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext"`
	KeyVersion int    `json:"key_version"`
}

// TransitWrapper is an envelope.KeyWrapper and envelope.Rewrapper backed by a
// Transit key. The key name is the envelope KEK id.
type TransitWrapper struct {
	client *Client
	mount  string
	name   string
}

// NewTransitWrapper wraps data keys with the Transit key mount/name.
func NewTransitWrapper(c *Client, mount, name string) *TransitWrapper {
	return &TransitWrapper{client: c, mount: mount, name: name}
}

var (
	_ envelope.KeyWrapper = (*TransitWrapper)(nil)
	_ envelope.Rewrapper  = (*TransitWrapper)(nil)
)

// GenerateDEK asks Transit for a fresh 256-bit data key.
func (w *TransitWrapper) GenerateDEK(ctx context.Context) ([]byte, envelope.WrappedKey, error) {
	var out response[transitData]
	err := w.client.do(ctx, http.MethodPost, w.mount+"/datakey/plaintext/"+w.name, nil, map[string]any{"bits": 256}, &out)
	if err != nil {
		return nil, envelope.WrappedKey{}, err
	}
	dek, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, envelope.WrappedKey{}, fmt.Errorf("openbao: data key is not base64")
	}
	wrapped, err := w.wrapped(out.Data.Ciphertext, out.Data.KeyVersion)
	if err != nil {
		clear(dek)
		return nil, envelope.WrappedKey{}, err
	}
	return dek, wrapped, nil
}

// UnwrapDEK decrypts a data key. The Transit ciphertext must carry the key
// version the record claims, so a record cannot misreport its KEK version.
func (w *TransitWrapper) UnwrapDEK(ctx context.Context, wrapped envelope.WrappedKey) ([]byte, error) {
	if err := w.check(wrapped); err != nil {
		return nil, err
	}
	var out response[transitData]
	body := map[string]any{"ciphertext": string(wrapped.Ciphertext)}
	if err := w.client.do(ctx, http.MethodPost, w.mount+"/decrypt/"+w.name, nil, body, &out); err != nil {
		return nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("openbao: data key is not base64")
	}
	return dek, nil
}

// RewrapDEK re-encrypts a data key under the latest Transit key version,
// inside OpenBao.
func (w *TransitWrapper) RewrapDEK(ctx context.Context, wrapped envelope.WrappedKey) (envelope.WrappedKey, error) {
	if err := w.check(wrapped); err != nil {
		return envelope.WrappedKey{}, err
	}
	var out response[transitData]
	body := map[string]any{"ciphertext": string(wrapped.Ciphertext)}
	if err := w.client.do(ctx, http.MethodPost, w.mount+"/rewrap/"+w.name, nil, body, &out); err != nil {
		return envelope.WrappedKey{}, err
	}
	return w.wrapped(out.Data.Ciphertext, out.Data.KeyVersion)
}

func (w *TransitWrapper) wrapped(ciphertext string, keyVersion int) (envelope.WrappedKey, error) {
	m := transitCiphertext.FindStringSubmatch(ciphertext)
	if m == nil {
		return envelope.WrappedKey{}, fmt.Errorf("openbao: unexpected transit ciphertext format")
	}
	v, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		return envelope.WrappedKey{}, fmt.Errorf("openbao: transit key version out of range")
	}
	if keyVersion != 0 && strconv.Itoa(keyVersion) != m[1] {
		return envelope.WrappedKey{}, fmt.Errorf("openbao: transit reported key version %d for a v%d ciphertext", keyVersion, v)
	}
	return envelope.WrappedKey{KEKID: w.name, KEKVersion: uint32(v), Ciphertext: []byte(ciphertext)}, nil
}

func (w *TransitWrapper) check(wrapped envelope.WrappedKey) error {
	if wrapped.KEKID != w.name {
		return fmt.Errorf("openbao: record wrapped by %q, this wrapper holds %q", wrapped.KEKID, w.name)
	}
	m := transitCiphertext.FindSubmatch(wrapped.Ciphertext)
	if m == nil {
		return fmt.Errorf("openbao: wrapped key is not a transit ciphertext")
	}
	if string(m[1]) != strconv.FormatUint(uint64(wrapped.KEKVersion), 10) {
		return fmt.Errorf("openbao: record claims kek version %d, ciphertext says v%s", wrapped.KEKVersion, m[1])
	}
	return nil
}
