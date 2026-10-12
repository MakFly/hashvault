package authn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// opensshKey creates an ed25519 key with ssh-keygen and returns a signer
// that runs `ssh-keygen -Y sign`: the exact tool operators use.
func opensshKey(t *testing.T) (ssh.PublicKey, func(msg []byte, namespace string) []byte) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "id")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyFile).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	pubLine, _ := os.ReadFile(keyFile + ".pub")
	pub, err := ParseKey(string(pubLine))
	if err != nil {
		t.Fatal(err)
	}
	sign := func(msg []byte, namespace string) []byte {
		msgFile := filepath.Join(dir, "msg")
		if err := os.WriteFile(msgFile, msg, 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("ssh-keygen", "-Y", "sign", "-q", "-n", namespace, "-f", keyFile, msgFile).CombinedOutput(); err != nil { // #nosec G204 -- test
			t.Fatalf("%v %s", err, out)
		}
		sig, err := os.ReadFile(msgFile + ".sig")
		if err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(msgFile + ".sig")
		return sig
	}
	return pub, sign
}

// skKey builds a FIDO2-style sk-ssh-ed25519 key and signs like an
// authenticator would, with chosen flags: there is no hardware in CI.
type skKey struct {
	priv ed25519.PrivateKey
	pub  ssh.PublicKey
}

const skApp = "ssh:"

func newSK(t *testing.T) skKey {
	t.Helper()
	pubRaw, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := ssh.Marshal(struct {
		Type        string
		PubKey      []byte
		Application string
	}{ssh.KeyAlgoSKED25519, pubRaw, skApp})
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return skKey{priv: priv, pub: pub}
}

func armor(blob []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(blob)
	var out bytes.Buffer
	out.WriteString(armorBegin + "\n")
	for len(b64) > 70 {
		out.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	out.WriteString(b64 + "\n" + armorEnd + "\n")
	return out.Bytes()
}

func (k skKey) sign(msg []byte, namespace string, flags byte) []byte {
	h := sha512.Sum512(msg)
	var magic [6]byte
	copy(magic[:], sigPreamble)
	data := ssh.Marshal(signedData{Magic: magic, Namespace: namespace, HashAlg: "sha512", Hash: h[:]})
	app := sha256.Sum256([]byte(skApp))
	dataDigest := sha256.Sum256(data)
	original := ssh.Marshal(struct {
		AppDigest []byte `ssh:"rest"`
		Flags     byte
		Counter   uint32
		DataHash  []byte `ssh:"rest"`
	}{app[:], flags, 42, dataDigest[:]})
	sig := ssh.Marshal(struct {
		Format string
		Blob   []byte
		Flags  byte
		Count  uint32
	}{ssh.KeyAlgoSKED25519, ssh.Marshal(struct {
		Sig []byte `ssh:"rest"`
	}{ed25519.Sign(k.priv, original)}), flags, 42})
	return armor(ssh.Marshal(sshsigBlob{Magic: magic, Version: 1, PublicKey: k.pub.Marshal(), Namespace: namespace, HashAlg: "sha512", Signature: sig}))
}

func TestOpenSSHSignaturesVerify(t *testing.T) {
	pub, sign := opensshKey(t)
	msg := []byte("hello vault")
	sig := sign(msg, Namespace)
	got, err := VerifySSHSIG(sig, msg, Namespace, pub)
	if err != nil || got.SK {
		t.Fatalf("%+v %v", got, err)
	}
	other, _ := opensshKey(t)
	for name, f := range map[string]func() error{
		"other message":   func() error { _, err := VerifySSHSIG(sig, []byte("hello vaulT"), Namespace, pub); return err },
		"other namespace": func() error { _, err := VerifySSHSIG(sign(msg, "git"), msg, Namespace, pub); return err },
		"other key":       func() error { _, err := VerifySSHSIG(sig, msg, Namespace, other); return err },
		"not armored":     func() error { _, err := VerifySSHSIG([]byte("nope"), msg, Namespace, pub); return err },
		"bad base64": func() error {
			_, err := VerifySSHSIG([]byte(armorBegin+"\n!!!\n"+armorEnd), msg, Namespace, pub)
			return err
		},
		"too large": func() error { _, err := VerifySSHSIG(make([]byte, maxArmored+1), msg, Namespace, pub); return err },
	} {
		if err := f(); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: want ErrSignature, got %v", name, err)
		}
	}
}

func TestFIDO2SignaturesNeedATouch(t *testing.T) {
	k := newSK(t)
	msg := []byte("hello vault")
	got, err := VerifySSHSIG(k.sign(msg, Namespace, FlagUserPresent), msg, Namespace, k.pub)
	if err != nil || !got.SK || got.Flags&FlagUserVerified != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	got, err = VerifySSHSIG(k.sign(msg, Namespace, FlagUserPresent|FlagUserVerified), msg, Namespace, k.pub)
	if err != nil || got.Flags&FlagUserVerified == 0 {
		t.Fatalf("user verification flag lost: %+v %v", got, err)
	}
	if _, err := VerifySSHSIG(k.sign(msg, Namespace, 0), msg, Namespace, k.pub); !errors.Is(err, ErrSignature) {
		t.Fatalf("a signature without user presence verified: %v", err)
	}
}

func TestParseKey(t *testing.T) {
	pub, _ := opensshKey(t)
	line := string(ssh.MarshalAuthorizedKey(pub))
	if _, err := ParseKey(line); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKey(`restrict ` + line); err == nil {
		t.Fatal("a key with options was accepted")
	}
	if _, err := ParseKey(string(ssh.MarshalAuthorizedKey(newSK(t).pub))); err != nil {
		t.Fatalf("sk key refused: %v", err)
	}
	rsa := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 x"
	if _, err := ParseKey(rsa); err == nil {
		t.Fatal("an rsa line was accepted")
	}
	if _, err := ParseKey("garbage"); err == nil {
		t.Fatal("garbage accepted")
	}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestLoginFlow(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)}
	s := NewSessions("vault-test", c.now)
	sk := newSK(t)
	alice := Principal{Name: "human/alice", Type: "human", Key: sk.pub}

	id, msg, err := s.Challenge(alice.Name)
	if err != nil || !bytes.Contains(msg, []byte("vault=vault-test\nprincipal=human/alice\n")) {
		t.Fatalf("challenge %q %v", msg, err)
	}
	token, sess, err := s.Login(id, alice, sk.sign(msg, Namespace, FlagUserPresent))
	if err != nil || !strings.HasPrefix(token, "hvs.") || sess.TouchedAt.IsZero() {
		t.Fatalf("login %+v %v", sess, err)
	}
	if _, _, err := s.Login(id, alice, sk.sign(msg, Namespace, FlagUserPresent)); !errors.Is(err, ErrChallenge) {
		t.Fatalf("a challenge was used twice: %v", err)
	}

	c.t = c.t.Add(10 * time.Minute)
	got, err := s.Lookup(token)
	if err != nil || got.Principal != "human/alice" {
		t.Fatal(got, err)
	}
	ctx := got.Context(c.t)
	if ctx["hv:MfaAgeSeconds"][0] != "600" || ctx["hv:PrincipalType"][0] != "human" {
		t.Fatalf("context %v", ctx)
	}
	c.t = c.t.Add(6 * time.Minute)
	if _, err := s.Lookup(token); !errors.Is(err, ErrToken) {
		t.Fatalf("an expired token was accepted: %v", err)
	}
	if _, err := s.Lookup("hvs.unknown"); !errors.Is(err, ErrToken) {
		t.Fatal("unknown token accepted")
	}
}

func TestLoginRefusals(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)}
	s := NewSessions("vault-test", c.now)
	pub, sign := opensshKey(t)
	bot := Principal{Name: "machine/deployer", Type: "machine", Key: pub}

	id, msg, _ := s.Challenge(bot.Name)
	if _, _, err := s.Login(id, Principal{Name: "machine/other", Type: "machine", Key: pub}, sign(msg, Namespace)); !errors.Is(err, ErrChallenge) {
		t.Fatalf("a challenge for another principal: %v", err)
	}
	id, msg, _ = s.Challenge(bot.Name)
	c.t = c.t.Add(2 * ChallengeTTL)
	if _, _, err := s.Login(id, bot, sign(msg, Namespace)); !errors.Is(err, ErrChallenge) {
		t.Fatalf("an expired challenge: %v", err)
	}
	id, msg, _ = s.Challenge(bot.Name)
	if _, _, err := s.Login(id, bot, sign(append(msg, 'x'), Namespace)); !errors.Is(err, ErrSignature) {
		t.Fatalf("a signature over another message: %v", err)
	}
	// A software key logs in, but never satisfies an MFA condition.
	id, msg, _ = s.Challenge(bot.Name)
	token, sess, err := s.Login(id, bot, sign(msg, Namespace))
	if err != nil || !sess.TouchedAt.IsZero() || sess.ExpiresAt.Sub(sess.IssuedAt) != MachineTTL {
		t.Fatalf("%+v %v", sess, err)
	}
	if _, ok := sess.Context(c.t)["hv:MfaAgeSeconds"]; ok {
		t.Fatal("a software key produced an MFA age")
	}
	s.Revoke(token)
	if _, err := s.Lookup(token); !errors.Is(err, ErrToken) {
		t.Fatal("revoked token still valid")
	}
	id, msg, _ = s.Challenge(bot.Name)
	if _, _, err := s.Login(id, bot, sign(msg, Namespace)); err != nil {
		t.Fatal(err)
	}
	if n := s.RevokePrincipal(bot.Name); n != 1 {
		t.Fatalf("revoked %d sessions", n)
	}
	for range maxPending {
		if _, _, err := s.Challenge(bot.Name); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.Challenge(bot.Name); err == nil {
		t.Fatal("challenge flood not bounded")
	}
	c.t = c.t.Add(2 * ChallengeTTL)
	if _, _, err := s.Challenge(bot.Name); err != nil {
		t.Fatalf("expired challenges must be purged: %v", err)
	}
}
