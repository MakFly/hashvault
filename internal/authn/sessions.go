package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	// ErrChallenge reports an unknown, used, expired or foreign challenge.
	ErrChallenge = errors.New("authn: invalid challenge")
	// ErrToken reports an unknown or expired token.
	ErrToken = errors.New("authn: invalid token")
)

// Lifetimes.
const (
	ChallengeTTL = 60 * time.Second
	HumanTTL     = 15 * time.Minute
	MachineTTL   = 5 * time.Minute
	maxPending   = 1024
)

// Principal is what authn needs to know about a principal.
type Principal struct {
	Name string
	// Type is human, machine, ci, workload or breakglass.
	Type string
	Key  ssh.PublicKey
}

// Session is an authenticated principal.
type Session struct {
	Principal string
	Type      string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// TouchedAt is when a FIDO2 key confirmed user presence; zero for a
	// software key, which can never satisfy an MFA condition.
	TouchedAt    time.Time
	UserVerified bool
}

// MFAAge returns the seconds since the touch, and false without one.
func (s Session) MFAAge(now time.Time) (int64, bool) {
	if s.TouchedAt.IsZero() {
		return 0, false
	}
	return int64(now.Sub(s.TouchedAt) / time.Second), true
}

type challenge struct {
	principal string
	message   []byte
	expires   time.Time
}

// Sessions issues challenges and tokens. It is safe for concurrent use and
// holds everything in memory: a daemon restart logs everyone out.
type Sessions struct {
	mu         sync.Mutex
	vault      string
	challenges map[string]challenge
	tokens     map[[32]byte]Session
	now        func() time.Time
}

// NewSessions returns an empty store. vault names this vault and is part of
// every challenge, so a signature for one vault is not a login on another.
func NewSessions(vault string, now func() time.Time) *Sessions {
	if now == nil {
		now = time.Now
	}
	return &Sessions{vault: vault, challenges: map[string]challenge{}, tokens: map[[32]byte]Session{}, now: now}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails since Go 1.24
	return hex.EncodeToString(b)
}

// Challenge returns an id and the exact message the client must sign.
func (s *Sessions) Challenge(principal string) (string, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, c := range s.challenges {
		if now.After(c.expires) {
			delete(s.challenges, id)
		}
	}
	if len(s.challenges) >= maxPending {
		return "", nil, errors.New("authn: too many pending challenges")
	}
	id := randomHex(16)
	msg := fmt.Appendf(nil, "hashvault login v1\nvault=%s\nprincipal=%s\nchallenge=%s\nexpires=%s\n",
		s.vault, principal, randomHex(32), now.Add(ChallengeTTL).UTC().Format(time.RFC3339))
	s.challenges[id] = challenge{principal: principal, message: msg, expires: now.Add(ChallengeTTL)}
	return id, msg, nil
}

// Login consumes a challenge, verifies the signature against the
// principal's key and returns a token. The challenge is spent even when the
// signature fails.
func (s *Sessions) Login(id string, p Principal, armored []byte) (string, Session, error) {
	s.mu.Lock()
	c, ok := s.challenges[id]
	delete(s.challenges, id)
	s.mu.Unlock()
	now := s.now()
	if !ok || c.principal != p.Name || now.After(c.expires) {
		return "", Session{}, ErrChallenge
	}
	signed, err := VerifySSHSIG(armored, c.message, Namespace, p.Key)
	if err != nil {
		return "", Session{}, err
	}
	ttl := MachineTTL
	if p.Type == "human" || p.Type == "breakglass" {
		ttl = HumanTTL
	}
	sess := Session{Principal: p.Name, Type: p.Type, IssuedAt: now, ExpiresAt: now.Add(ttl)}
	if signed.SK {
		sess.TouchedAt = now
		sess.UserVerified = signed.Flags&FlagUserVerified != 0
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	token := "hvs." + base64.RawURLEncoding.EncodeToString(raw)
	s.mu.Lock()
	s.tokens[sha256.Sum256([]byte(token))] = sess
	s.mu.Unlock()
	return token, sess, nil
}

// Lookup returns the session of a token.
func (s *Sessions) Lookup(token string) (Session, error) {
	h := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, sess := range s.tokens {
		if now.After(sess.ExpiresAt) {
			delete(s.tokens, k)
		}
	}
	// The map lookup already compares hashes; the constant-time compare
	// documents that a token is never compared in clear.
	for k, sess := range s.tokens {
		if subtle.ConstantTimeCompare(k[:], h[:]) == 1 {
			return sess, nil
		}
	}
	return Session{}, ErrToken
}

// Revoke ends a session (logout, or a disabled principal).
func (s *Sessions) Revoke(token string) {
	h := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, h)
}

// RevokePrincipal ends every session of a principal.
func (s *Sessions) RevokePrincipal(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, sess := range s.tokens {
		if sess.Principal == name {
			delete(s.tokens, k)
			n++
		}
	}
	return n
}

// Context returns the IAM condition keys a session contributes.
func (s Session) Context(now time.Time) map[string][]string {
	ctx := map[string][]string{
		"hv:PrincipalType": {s.Type},
		"hv:CurrentTime":   {now.UTC().Format(time.RFC3339)},
	}
	if age, ok := s.MFAAge(now); ok {
		ctx["hv:MfaAgeSeconds"] = []string{strconv.FormatInt(age, 10)}
	}
	return ctx
}
