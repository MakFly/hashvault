// Package batch carries secret values from hashvaultd to one host agent.
//
// A batch is signed, then encrypted:
//
//  1. the JSON payload is signed with the vault's Ed25519 key, over a
//     domain-separated message, so the agent knows who sent it;
//  2. payload and signature are encrypted with age to that agent's hybrid
//     (ML-KEM-768 + X25519) recipient, so only that agent can read it.
//
// Encryption alone would not do: anyone holding the agent's public recipient
// could forge a batch. The agent also checks the batch is addressed to it,
// fresh (a short validity window) and never replayed (see Replay).
package batch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"filippo.io/age"

	"github.com/MakFly/hashvault/internal/target"
)

// Version is the batch format.
const Version = "hv-batch-1"

// Limits.
const (
	MaxValidity = 10 * time.Minute
	ClockSkew   = 30 * time.Second
	maxSize     = 8 << 20
)

const signDomain = "hashvault batch v1\x00"

var (
	// ErrInvalid reports a batch that fails a check. The message names the
	// check, never a value.
	ErrInvalid  = errors.New("batch: invalid")
	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
)

// Item is one secret version in a batch.
type Item struct {
	Key      string          `json:"key"`
	Version  uint64          `json:"version"`
	Resource string          `json:"resource"`
	Value    []byte          `json:"value"`
	Spec     target.ItemSpec `json:"spec"`
}

// Consumers says what to restart or reload once the values are in place.
type Consumers struct {
	// Docker lists compose services (label com.docker.compose.service) of
	// the project to restart. docker kind only.
	Docker []string `json:"docker,omitempty"`
	// ComposeProject is the compose project name; empty means the app name.
	ComposeProject string `json:"compose_project,omitempty"`
	// Reload lists commands (argv, no shell) to run in order. ssh kind only.
	Reload [][]string `json:"reload,omitempty"`
}

// Batch is the payload.
type Batch struct {
	// Preparation is an immutable generation id. Nonempty batches install
	// resources without invoking consumers or changing the active generation.
	Preparation string      `json:"preparation,omitempty"`
	Version     string      `json:"version"`
	ID          string      `json:"id"`
	Agent       string      `json:"agent"`
	Target      string      `json:"target"`
	Kind        target.Kind `json:"kind"`
	App         string      `json:"app"`
	Env         string      `json:"env"`
	IssuedAt    time.Time   `json:"issued_at"`
	ExpiresAt   time.Time   `json:"expires_at"`
	// Rollback allows versions lower than the ones the agent last applied.
	Rollback  bool      `json:"rollback,omitempty"`
	Items     []Item    `json:"items"`
	Consumers Consumers `json:"consumers"`
}

// Clear wipes the values held by the batch.
func (b *Batch) Clear() {
	for i := range b.Items {
		clear(b.Items[i].Value)
	}
}

func (b Batch) validate(agent string, now time.Time) error {
	if b.Preparation != "" {
		if !target.ValidPreparationID(b.Preparation) || len(b.Consumers.Docker) != 0 || len(b.Consumers.Reload) != 0 {
			return fmt.Errorf("%w: a preparation needs a valid generation and no consumers", ErrInvalid)
		}
	}
	switch {
	case b.Version != Version:
		return fmt.Errorf("%w: version %q", ErrInvalid, b.Version)
	case len(b.ID) != 32:
		return fmt.Errorf("%w: id", ErrInvalid)
	case b.Agent != agent:
		return fmt.Errorf("%w: addressed to agent %q, this is %q", ErrInvalid, b.Agent, agent)
	case !namePattern.MatchString(b.Target):
		return fmt.Errorf("%w: target name", ErrInvalid)
	case b.Kind != target.Docker && b.Kind != target.SSH:
		return fmt.Errorf("%w: kind %q is not handled by a host agent", ErrInvalid, b.Kind)
	case b.IssuedAt.After(now.Add(ClockSkew)):
		return fmt.Errorf("%w: issued in the future", ErrInvalid)
	case !b.ExpiresAt.After(now):
		return fmt.Errorf("%w: expired", ErrInvalid)
	case b.ExpiresAt.Sub(b.IssuedAt) > MaxValidity:
		return fmt.Errorf("%w: validity longer than %s", ErrInvalid, MaxValidity)
	case len(b.Items) == 0:
		return fmt.Errorf("%w: no item", ErrInvalid)
	}
	d := target.Desired{App: b.App, Env: b.Env}
	for _, it := range b.Items {
		d.Items = append(d.Items, target.Item{Key: it.Key, Version: it.Version, Resource: it.Resource, Spec: it.Spec})
	}
	if err := d.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if b.Kind == target.SSH && len(b.Consumers.Docker) > 0 {
		return fmt.Errorf("%w: docker consumers in an ssh batch", ErrInvalid)
	}
	if b.Kind == target.Docker && len(b.Consumers.Reload) > 0 {
		return fmt.Errorf("%w: reload commands in a docker batch", ErrInvalid)
	}
	for _, argv := range b.Consumers.Reload {
		if len(argv) == 0 || len(argv[0]) == 0 || argv[0][0] != '/' {
			return fmt.Errorf("%w: reload commands need an absolute program path", ErrInvalid)
		}
	}
	return nil
}

// NewID returns a random batch id. crypto/rand.Read never fails since Go
// 1.24: it crashes the program rather than return weak bytes.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type sealed struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func message(payload []byte) []byte {
	return append([]byte(signDomain), payload...)
}

// Seal signs then encrypts a batch for one agent.
func Seal(b Batch, signer ed25519.PrivateKey, recipient age.Recipient) ([]byte, error) {
	payload, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	inner, err := json.Marshal(sealed{Payload: payload, Signature: ed25519.Sign(signer, message(payload))})
	if err != nil {
		return nil, err
	}
	defer clear(inner)
	r, err := age.EncryptReader(bytes.NewReader(inner), recipient)
	if err != nil {
		return nil, fmt.Errorf("batch: encrypt: %w", err)
	}
	return io.ReadAll(r)
}

// Open decrypts, verifies and validates a batch. The caller clears it.
func Open(data []byte, identity age.Identity, trusted ed25519.PublicKey, agent string, now time.Time) (Batch, error) {
	if len(data) > maxSize {
		return Batch{}, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, maxSize)
	}
	r, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return Batch{}, fmt.Errorf("%w: not encrypted to this agent", ErrInvalid)
	}
	inner, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil || len(inner) > maxSize {
		return Batch{}, fmt.Errorf("%w: unreadable", ErrInvalid)
	}
	defer clear(inner)
	var s sealed
	if err := strictUnmarshal(inner, &s); err != nil {
		return Batch{}, fmt.Errorf("%w: envelope", ErrInvalid)
	}
	defer clear(s.Payload)
	if len(trusted) != ed25519.PublicKeySize || !ed25519.Verify(trusted, message(s.Payload), s.Signature) {
		return Batch{}, fmt.Errorf("%w: signature", ErrInvalid)
	}
	var b Batch
	if err := strictUnmarshal(s.Payload, &b); err != nil {
		return Batch{}, fmt.Errorf("%w: payload", ErrInvalid)
	}
	if err := b.validate(agent, now); err != nil {
		b.Clear()
		return Batch{}, err
	}
	return b, nil
}

func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}
