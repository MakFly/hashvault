package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"filippo.io/age"

	"github.com/MakFly/hashvault/internal/openbao"
	"github.com/MakFly/hashvault/internal/registry"
	"github.com/MakFly/hashvault/internal/secrets"
)

// Where the daemon's own keys live, as ordinary sealed secrets.
var (
	AuditKeyRef = secrets.Ref{Env: "sys", App: "hashvault", Key: "AUDIT_SIGNING_KEY"}
	BatchKeyRef = secrets.Ref{Env: "sys", App: "hashvault", Key: "BATCH_SIGNING_KEY"}
)

// adminPolicy is the bootstrap administrator's policy: everything, from the
// SSH tunnel only, with a FIDO2 touch less than 15 minutes old.
const adminPolicy = `{
  "Version": "hv-1",
  "Statement": [{
    "Sid": "BootstrapAdmin",
    "Effect": "Allow",
    "Action": "*",
    "Resource": "hv:*",
    "Condition": {
      "NumericLessThanEquals": {"hv:MfaAgeSeconds": 900},
      "StringEquals": {"hv:SourceChannel": "tunnel"}
    }
  }]
}`

// baoPolicy is what hashvaultd's AppRole token may do in OpenBao, nothing
// more: read and write records, use (never export) the KEK, renew itself,
// and seal.
func baoPolicy(kv, transit, kekPrefix string) string {
	return fmt.Sprintf(`path "%[1]s/data/*"     { capabilities = ["create", "read", "update"] }
path "%[1]s/metadata/*" { capabilities = ["read", "list"] }
path "%[1]s/destroy/*"  { capabilities = ["update"] }
path "%[2]s/datakey/plaintext/%[3]s*" { capabilities = ["update"] }
path "%[2]s/decrypt/%[3]s*"           { capabilities = ["update"] }
path "%[2]s/rewrap/%[3]s*"            { capabilities = ["update"] }
path "%[2]s/keys/%[3]s*/rotate"       { capabilities = ["update"] }
path "%[2]s/keys/%[3]s*/config"       { capabilities = ["update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "sys/seal"              { capabilities = ["update", "sudo"] }
`, kv, transit, kekPrefix)
}

// BootstrapOptions configures the one-time ceremony.
type BootstrapOptions struct {
	KVMount      string
	TransitMount string
	KEK          string
	AppRoleMount string
	Role         string
	// Admin is the first principal, a human with a FIDO2 key.
	AdminName string
	AdminKey  string
	// Recipients receive the unseal bundle: typically two hardware keys and
	// an offline paper key.
	Recipients []age.Recipient
}

// BootstrapResult is everything the operator keeps.
type BootstrapResult struct {
	RoleID string
	// Bundle is the age-encrypted unseal bundle: the only copy of the
	// unseal key and the AppRole secret id.
	Bundle   []byte
	AuditKey ed25519.PublicKey
	BatchKey ed25519.PublicKey
}

// Bundle is the decrypted unseal bundle.
type Bundle struct {
	UnsealKey string `json:"unseal_key"`
	SecretID  string `json:"secret_id"`
}

// Bootstrap initialises an empty OpenBao and hashvault on top of it. The
// root token exists only during the ceremony and is revoked at the end.
func Bootstrap(ctx context.Context, bao *openbao.Client, o BootstrapOptions) (BootstrapResult, error) {
	if len(o.Recipients) == 0 {
		return BootstrapResult{}, errors.New("bootstrap: at least one bundle recipient is required")
	}
	admin := registry.Principal{Name: o.AdminName, SSHKey: o.AdminKey, Policies: []string{"admin"}}
	if err := admin.Validate(); err != nil {
		return BootstrapResult{}, err
	}
	st, err := bao.SealStatus(ctx)
	if err != nil {
		return BootstrapResult{}, err
	}
	if st.Initialized {
		return BootstrapResult{}, errors.New("bootstrap: OpenBao is already initialised; the ceremony runs once")
	}
	init, err := bao.Init(ctx, 1, 1)
	if err != nil {
		return BootstrapResult{}, err
	}
	bundle := Bundle{UnsealKey: init.KeysB64[0]}
	if _, err := bao.Unseal(ctx, bundle.UnsealKey); err != nil {
		return BootstrapResult{}, err
	}
	if err := bao.WaitActive(ctx, 30*time.Second); err != nil {
		return BootstrapResult{}, err
	}
	bao.SetToken(init.RootToken)
	// Whatever happens next, the root token does not survive the ceremony.
	defer func() { _ = bao.RevokeSelf(context.WithoutCancel(ctx)) }()

	steps := []func() error{
		func() error { return bao.Mount(ctx, o.KVMount, "kv", map[string]string{"version": "2"}) },
		func() error { return bao.Mount(ctx, o.TransitMount, "transit", nil) },
		func() error { return bao.TransitCreateKey(ctx, o.TransitMount, o.KEK, "chacha20-poly1305") },
		func() error {
			return bao.PutACLPolicy(ctx, "hashvaultd", baoPolicy(o.KVMount, o.TransitMount, "hv-kek"))
		},
		func() error { return bao.EnableAuth(ctx, o.AppRoleMount, "approle") },
		func() error {
			return bao.AppRoleWrite(ctx, o.AppRoleMount, o.Role, map[string]any{
				"token_policies": []string{"hashvaultd"}, "token_period": "1h", "token_type": "service",
				"secret_id_num_uses": 0, "bind_secret_id": true,
			})
		},
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return BootstrapResult{}, fmt.Errorf("bootstrap: %w", err)
		}
	}
	res := BootstrapResult{}
	if res.RoleID, err = bao.AppRoleRoleID(ctx, o.AppRoleMount, o.Role); err != nil {
		return BootstrapResult{}, err
	}
	if bundle.SecretID, err = bao.AppRoleSecretID(ctx, o.AppRoleMount, o.Role); err != nil {
		return BootstrapResult{}, err
	}

	store := secrets.New(bao, o.KVMount, openbao.NewTransitWrapper(bao, o.TransitMount, o.KEK))
	for _, k := range []struct {
		ref secrets.Ref
		pub *ed25519.PublicKey
	}{{AuditKeyRef, &res.AuditKey}, {BatchKeyRef, &res.BatchKey}} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return BootstrapResult{}, err
		}
		_, err = store.Put(ctx, k.ref, priv)
		clear(priv)
		if err != nil {
			return BootstrapResult{}, err
		}
		*k.pub = pub
	}
	reg := registry.New(bao, o.KVMount)
	if err := reg.PutPolicy(ctx, "admin", []byte(adminPolicy)); err != nil {
		return BootstrapResult{}, err
	}
	if err := reg.PutPrincipal(ctx, admin); err != nil {
		return BootstrapResult{}, err
	}

	plain, err := json.Marshal(bundle)
	if err != nil {
		return BootstrapResult{}, err
	}
	defer clear(plain)
	r, err := age.EncryptReader(bytes.NewReader(plain), o.Recipients...)
	if err != nil {
		return BootstrapResult{}, err
	}
	if res.Bundle, err = io.ReadAll(r); err != nil {
		return BootstrapResult{}, err
	}
	return res, nil
}

// OpenBundle decrypts an unseal bundle with the operator's identities.
func OpenBundle(data []byte, identities ...age.Identity) (Bundle, error) {
	r, err := age.Decrypt(bytes.NewReader(data), identities...)
	if err != nil {
		return Bundle{}, fmt.Errorf("bundle: %w", err)
	}
	plain, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return Bundle{}, err
	}
	defer clear(plain)
	var b Bundle
	if err := json.Unmarshal(plain, &b); err != nil || b.UnsealKey == "" || b.SecretID == "" {
		return Bundle{}, errors.New("bundle: not an unseal bundle")
	}
	return b, nil
}
