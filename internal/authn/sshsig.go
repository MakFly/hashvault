// Package authn authenticates hashvault principals.
//
// Humans and machines prove possession of an SSH key by signing a one-time
// challenge with `ssh-keygen -Y sign` (the OpenSSH SSHSIG format). For a
// FIDO2 key (sk-ssh-ed25519) the signature carries the authenticator flags:
// user presence (a touch) is required, and its time becomes the MFA age
// that policies can condition on. A session token is opaque, random, held
// only as a SHA-256 hash, and short-lived.
package authn

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Namespace is the SSHSIG namespace of a login signature, so a signature
// made for anything else (git commits, files) is never a login.
const Namespace = "hashvault-login"

// Authenticator flags of an sk signature.
const (
	FlagUserPresent  = 0x01
	FlagUserVerified = 0x04
)

var (
	// ErrSignature is the only error a failed signature check returns.
	ErrSignature = errors.New("authn: signature does not verify")
)

const (
	sigPreamble = "SSHSIG"
	armorBegin  = "-----BEGIN SSH SIGNATURE-----"
	armorEnd    = "-----END SSH SIGNATURE-----"
	maxArmored  = 16 << 10
)

// Signed is a verified SSHSIG.
type Signed struct {
	Key ssh.PublicKey
	// SK reports a FIDO2 key; Flags are then the authenticator flags.
	SK    bool
	Flags byte
}

type sshsigBlob struct {
	Magic     [6]byte
	Version   uint32
	PublicKey []byte
	Namespace string
	Reserved  string
	HashAlg   string
	Signature []byte
}

type signedData struct {
	Magic     [6]byte
	Namespace string
	Reserved  string
	HashAlg   string
	Hash      []byte
}

// VerifySSHSIG checks an armored SSHSIG over message in namespace, made by
// key. Any mismatch returns ErrSignature.
func VerifySSHSIG(armored []byte, message []byte, namespace string, key ssh.PublicKey) (Signed, error) {
	blob, err := dearmor(armored)
	if err != nil {
		return Signed{}, ErrSignature
	}
	var s sshsigBlob
	if err := ssh.Unmarshal(blob, &s); err != nil || string(s.Magic[:]) != sigPreamble || s.Version != 1 {
		return Signed{}, ErrSignature
	}
	if s.Namespace != namespace || s.Reserved != "" {
		return Signed{}, ErrSignature
	}
	sigKey, err := ssh.ParsePublicKey(s.PublicKey)
	if err != nil || !bytes.Equal(sigKey.Marshal(), key.Marshal()) {
		return Signed{}, ErrSignature
	}
	var h hash.Hash
	switch s.HashAlg {
	case "sha512":
		h = sha512.New()
	case "sha256":
		h = sha256.New()
	default:
		return Signed{}, ErrSignature
	}
	h.Write(message)
	var magic [6]byte
	copy(magic[:], sigPreamble)
	data := ssh.Marshal(signedData{Magic: magic, Namespace: s.Namespace, Reserved: s.Reserved, HashAlg: s.HashAlg, Hash: h.Sum(nil)})

	var sig struct {
		Format string
		Blob   []byte
		Rest   []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(s.Signature, &sig); err != nil {
		return Signed{}, ErrSignature
	}
	if err := key.Verify(data, &ssh.Signature{Format: sig.Format, Blob: sig.Blob, Rest: sig.Rest}); err != nil {
		return Signed{}, ErrSignature
	}
	out := Signed{Key: key}
	if strings.HasPrefix(key.Type(), "sk-") {
		// x/crypto already refuses an sk signature without user presence;
		// checked again here, because the MFA claim depends on it.
		if len(sig.Rest) < 1 || sig.Rest[0]&FlagUserPresent == 0 {
			return Signed{}, ErrSignature
		}
		out.SK, out.Flags = true, sig.Rest[0]
	}
	return out, nil
}

func dearmor(armored []byte) ([]byte, error) {
	if len(armored) > maxArmored {
		return nil, errors.New("signature too large")
	}
	text := strings.TrimSpace(string(armored))
	if !strings.HasPrefix(text, armorBegin) || !strings.HasSuffix(text, armorEnd) {
		return nil, errors.New("not an armored SSH signature")
	}
	body := strings.TrimSuffix(strings.TrimPrefix(text, armorBegin), armorEnd)
	body = strings.Join(strings.Fields(body), "")
	return base64.StdEncoding.DecodeString(body)
}

// ParseKey parses one authorized_keys line (options are refused: a key's
// restrictions belong to hashvault policies, not to the key line).
func ParseKey(line string) (ssh.PublicKey, error) {
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("authn: %w", err)
	}
	if len(options) > 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("authn: one key, without options")
	}
	switch key.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519:
		return key, nil
	}
	return nil, fmt.Errorf("authn: key type %s refused: use ed25519 or sk-ed25519", key.Type())
}
