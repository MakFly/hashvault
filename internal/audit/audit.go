// Package audit is hashvault's tamper-evident audit log.
//
// Each entry is one JSON line carrying the SHA-256 hash of the previous
// entry, so editing, deleting or reordering a line breaks every hash after
// it. That alone does not stop someone who rewrites the whole file: periodic
// checkpoints sign the current head with an Ed25519 key, and copies of those
// checkpoints kept off the host (the anchors) pin the history up to them.
//
// Entries never hold a secret value: Append refuses detail keys that look
// like one.
package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Genesis is the prev hash of the first entry.
var Genesis = strings.Repeat("0", 64)

const (
	checkpointDomain = "hashvault audit checkpoint v1\x00"
	maxLine          = 64 << 10
)

var (
	// ErrBroken reports a log whose chain or checkpoints do not verify.
	ErrBroken = errors.New("audit: log broken")
	// ErrSecretDetail reports a detail key that looks like a secret value.
	ErrSecretDetail = errors.New("audit: detail key looks like a secret value")
	secretish       = regexp.MustCompile(`(?i)value|secret|password|passwd|token|key_material|plaintext|private`)
)

// Entry is one audited event.
type Entry struct {
	Seq       uint64            `json:"seq"`
	Time      time.Time         `json:"ts"`
	Prev      string            `json:"prev"`
	Principal string            `json:"principal"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Decision  string            `json:"decision"`
	Outcome   string            `json:"outcome"`
	Detail    map[string]string `json:"detail,omitempty"`
	Hash      string            `json:"hash"`
}

// digest hashes the entry with Hash cleared. encoding/json writes struct
// fields in declaration order and map keys sorted, so the encoding is
// stable; it cannot fail on these field types.
func (e Entry) digest() string {
	e.Hash = ""
	data, _ := json.Marshal(e)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Checkpoint signs the head of the chain at Seq.
type Checkpoint struct {
	Seq       uint64    `json:"seq"`
	Head      string    `json:"head"`
	Time      time.Time `json:"ts"`
	KeyID     string    `json:"key_id"`
	Signature []byte    `json:"sig"`
}

func (c Checkpoint) message() []byte {
	c.Signature = nil
	data, _ := json.Marshal(c) // cannot fail on these field types
	return append([]byte(checkpointDomain), data...)
}

// KeyID names an Ed25519 public key: the first 16 hex digits of its SHA-256.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Log appends to an audit file.
type Log struct {
	mu          sync.Mutex
	file        *os.File
	checkpoints *os.File
	signer      ed25519.PrivateKey
	seq         uint64
	head        string
	now         func() time.Time
}

// Open verifies the existing file (fail closed: a broken chain refuses to
// open) and returns a log ready to append. Checkpoints are written to
// path + ".checkpoints".
func Open(path string, signer ed25519.PrivateKey, now func() time.Time) (*Log, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("audit: an Ed25519 signing key is required")
	}
	if now == nil {
		now = time.Now
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- path from the daemon configuration
	if err != nil {
		return nil, err
	}
	rep, err := verifyChain(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	cp, err := os.OpenFile(path+".checkpoints", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- path from the daemon configuration
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Log{file: f, checkpoints: cp, signer: signer, seq: rep.Entries, head: rep.Head, now: now}, nil
}

// Close closes the files.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return errors.Join(l.file.Close(), l.checkpoints.Close())
}

// Head returns the last sequence number and hash.
func (l *Log) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, l.head
}

// Append chains, writes and syncs one entry. Seq, Time, Prev and Hash are
// set by the log.
func (l *Log) Append(e Entry) (Entry, error) {
	for k := range e.Detail {
		if secretish.MatchString(k) {
			return Entry{}, fmt.Errorf("%w: %q", ErrSecretDetail, k)
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Seq = l.seq + 1
	e.Time = l.now().UTC()
	e.Prev = l.head
	e.Hash = e.digest()
	line, _ := json.Marshal(e)
	if len(line) >= maxLine {
		return Entry{}, errors.New("audit: entry too large")
	}
	if _, err := l.file.Write(append(line, '\n')); err != nil {
		return Entry{}, err
	}
	if err := l.file.Sync(); err != nil {
		return Entry{}, err
	}
	l.seq, l.head = e.Seq, e.Hash
	return e, nil
}

// Checkpoint signs the current head, appends it to the checkpoints file and
// returns it, so the caller can ship a copy off the host (the anchor).
func (l *Log) Checkpoint() (Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := Checkpoint{Seq: l.seq, Head: l.head, Time: l.now().UTC(), KeyID: KeyID(l.signer.Public().(ed25519.PublicKey))}
	c.Signature = ed25519.Sign(l.signer, c.message())
	line, _ := json.Marshal(c)
	if _, err := l.checkpoints.Write(append(line, '\n')); err != nil {
		return Checkpoint{}, err
	}
	return c, l.checkpoints.Sync()
}

// Report is the result of a verification.
type Report struct {
	Entries     uint64
	Head        string
	Checkpoints int
	// Heads maps a sequence number to the hash of its entry, for checking
	// checkpoints after the chain walk.
	heads map[uint64]string
}

// verifyChain walks the file from the start.
func verifyChain(r io.ReadSeeker) (Report, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return Report{}, err
	}
	rep := Report{Head: Genesis, heads: map[uint64]string{0: Genesis}}
	br := bufio.NewReaderSize(r, maxLine)
	for {
		line, err := br.ReadBytes('\n')
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err == io.EOF {
			return rep, fmt.Errorf("%w: entry %d is truncated (no final newline)", ErrBroken, rep.Entries+1)
		}
		if err != nil {
			return rep, err
		}
		var e Entry
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return rep, fmt.Errorf("%w: entry %d is not valid JSON", ErrBroken, rep.Entries+1)
		}
		switch {
		case e.Seq != rep.Entries+1:
			return rep, fmt.Errorf("%w: entry %d has seq %d", ErrBroken, rep.Entries+1, e.Seq)
		case e.Prev != rep.Head:
			return rep, fmt.Errorf("%w: entry %d does not chain to entry %d", ErrBroken, e.Seq, rep.Entries)
		}
		if e.digest() != e.Hash {
			return rep, fmt.Errorf("%w: entry %d was modified", ErrBroken, e.Seq)
		}
		rep.Entries, rep.Head = e.Seq, e.Hash
		rep.heads[e.Seq] = e.Hash
	}
	return rep, nil
}

// Verify checks the chain of the file at path, every checkpoint in its
// checkpoints file, and the anchors (checkpoints kept elsewhere). A
// checkpoint or anchor must be signed by trusted and name the hash the chain
// has at its sequence number: a rewritten history fails here even if its
// own chain is consistent.
func Verify(path string, trusted ed25519.PublicKey, anchors []Checkpoint) (Report, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-chosen path
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	rep, err := verifyChain(f)
	if err != nil {
		return rep, err
	}
	local, err := ReadCheckpoints(path + ".checkpoints")
	if err != nil && !os.IsNotExist(err) {
		return rep, err
	}
	for _, c := range append(local, anchors...) {
		if err := checkCheckpoint(c, trusted, rep); err != nil {
			return rep, err
		}
		rep.Checkpoints++
	}
	return rep, nil
}

func checkCheckpoint(c Checkpoint, trusted ed25519.PublicKey, rep Report) error {
	if len(trusted) != ed25519.PublicKeySize || c.KeyID != KeyID(trusted) || !ed25519.Verify(trusted, c.message(), c.Signature) {
		return fmt.Errorf("%w: checkpoint at %d is not signed by the trusted key", ErrBroken, c.Seq)
	}
	head, ok := rep.heads[c.Seq]
	if !ok {
		return fmt.Errorf("%w: checkpoint at %d is beyond the end of the log (%d): entries were removed", ErrBroken, c.Seq, rep.Entries)
	}
	if head != c.Head {
		return fmt.Errorf("%w: history up to entry %d differs from the signed checkpoint", ErrBroken, c.Seq)
	}
	return nil
}

// ReadCheckpoints reads a checkpoints file.
func ReadCheckpoints(path string) ([]Checkpoint, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-chosen path
	if err != nil {
		return nil, err
	}
	var out []Checkpoint
	for i, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var c Checkpoint
		if err := json.Unmarshal(line, &c); err != nil {
			return nil, fmt.Errorf("%w: checkpoint line %d", ErrBroken, i+1)
		}
		out = append(out, c)
	}
	return out, nil
}
