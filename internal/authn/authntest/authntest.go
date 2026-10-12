// Package authntest creates SSH keys and SSHSIG login signatures for tests:
// software ed25519 keys, and FIDO2-style sk-ed25519 keys signed with chosen
// authenticator flags (CI has no hardware key).
package authntest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Key is a test key: its authorized_keys line and a signer of login
// messages in a namespace.
type Key struct {
	Line string
	Sign func(msg []byte, namespace string) []byte
}

type signedData struct {
	Magic     [6]byte
	Namespace string
	Reserved  string
	HashAlg   string
	Hash      []byte
}

type blob struct {
	Magic     [6]byte
	Version   uint32
	PublicKey []byte
	Namespace string
	Reserved  string
	HashAlg   string
	Signature []byte
}

var magic = func() (m [6]byte) { copy(m[:], "SSHSIG"); return }()

func data(msg []byte, namespace string) []byte {
	h := sha512.Sum512(msg)
	return ssh.Marshal(signedData{Magic: magic, Namespace: namespace, HashAlg: "sha512", Hash: h[:]})
}

func armor(raw []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(raw)
	var out bytes.Buffer
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(b64) > 70 {
		out.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	out.WriteString(b64 + "\n-----END SSH SIGNATURE-----\n")
	return out.Bytes()
}

// Ed25519 returns a software key (a machine's key).
func Ed25519() Key {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	pub := signer.PublicKey()
	return Key{
		Line: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Sign: func(msg []byte, namespace string) []byte {
			sig, _ := signer.Sign(rand.Reader, data(msg, namespace))
			raw := ssh.Marshal(struct {
				Format string
				Blob   []byte
			}{sig.Format, sig.Blob})
			return armor(ssh.Marshal(blob{Magic: magic, Version: 1, PublicKey: pub.Marshal(), Namespace: namespace, HashAlg: "sha512", Signature: raw}))
		},
	}
}

// SK returns a FIDO2-style key whose signatures carry flags (0x01: user
// present, 0x04: user verified).
func SK(flags byte) Key {
	pubRaw, priv, _ := ed25519.GenerateKey(rand.Reader)
	const app = "ssh:"
	pub, _ := ssh.ParsePublicKey(ssh.Marshal(struct {
		Type   string
		PubKey []byte
		App    string
	}{ssh.KeyAlgoSKED25519, pubRaw, app}))
	return Key{
		Line: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Sign: func(msg []byte, namespace string) []byte {
			appDigest := sha256.Sum256([]byte(app))
			dataDigest := sha256.Sum256(data(msg, namespace))
			original := ssh.Marshal(struct {
				AppDigest []byte `ssh:"rest"`
				Flags     byte
				Counter   uint32
				DataHash  []byte `ssh:"rest"`
			}{appDigest[:], flags, 1, dataDigest[:]})
			raw := ssh.Marshal(struct {
				Format string
				Blob   []byte
				Flags  byte
				Count  uint32
			}{ssh.KeyAlgoSKED25519, ssh.Marshal(struct {
				Sig []byte `ssh:"rest"`
			}{ed25519.Sign(priv, original)}), flags, 1})
			return armor(ssh.Marshal(blob{Magic: magic, Version: 1, PublicKey: pub.Marshal(), Namespace: namespace, HashAlg: "sha512", Signature: raw}))
		},
	}
}
