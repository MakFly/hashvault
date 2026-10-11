# Cryptography specification

Status: draft for format `hv1`, implemented in `internal/envelope`. Reviewers
welcome: open an issue, or follow `SECURITY.md` for anything sensitive.

## Goals

- A secret value is never stored in clear, and never under a key that the
  storage layer alone can use.
- A ciphertext is bound to the secret version it belongs to. Copying it to
  another secret, environment or version makes it fail to open.
- Rotating the key encryption key never requires decrypting a value.
- Destroying a secret version destroys the only copy of its data key.
- Only standard, audited primitives. No custom cipher, no custom mode.

## Key hierarchy

```text
+--------------------------------------------------+
| Unseal key of the storage backend (OpenBao),     |
| encrypted with age to hardware keys (YubiKey)    |
+------------------------+-------------------------+
                         | manual unseal ceremony
                         v
+------------------------+-------------------------+
| OpenBao root key > barrier keyring (AES-GCM)     |
+------------------------+-------------------------+
                         |
                         v
+------------------------+-------------------------+
| KEK: Transit key, versioned, not exportable,     |
| movable to an HSM or KMS (OpenBao 2.7+)          |
+------------------------+-------------------------+
                         | datakey / rewrap
                         v
+------------------------+-------------------------+
| DEK: 256 bits, one per secret version            |
+------------------------+-------------------------+
                         | XChaCha20-Poly1305 + AAD
                         v
+------------------------+-------------------------+
| hv1 record: ciphertext + wrapped DEK             |
+--------------------------------------------------+
```

Values are therefore encrypted twice at rest: by the hv1 envelope, and by the
OpenBao barrier that stores the record.

## Primitives

| Use | Primitive | Implementation |
|---|---|---|
| Value encryption | XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) | `golang.org/x/crypto/chacha20poly1305.NewX` |
| Nonces and DEKs | CSPRNG | `crypto/rand` |
| DEK wrapping | OpenBao Transit (`datakey`, `rewrap`) | OpenBao |
| Unseal key protection | age X25519, `age-plugin-yubikey` | age |

XChaCha20-Poly1305 is preferred over AES-256-GCM for two reasons: its 192-bit
nonce makes random nonces safe without any counter state, and it runs in
constant time without AES hardware support. With one DEK per version, the
nonce space is not under pressure either way; the choice is about removing a
failure mode, not about throughput.

## Record format `hv1`

A record is a JSON object with exactly these fields, in this order:

| Field | Type | Meaning |
|---|---|---|
| `v` | integer | Format version, `1` |
| `kek_id` | string | KEK name, `[A-Za-z0-9][A-Za-z0-9._-]*`, at most 128 bytes |
| `kek_version` | integer | KEK version that wrapped the DEK, at least 1 |
| `wrapped_dek` | base64 | Wrapped DEK, 1 to 4096 bytes |
| `nonce` | base64 | 24 random bytes |
| `ct` | base64 | Ciphertext and 16-byte tag; plaintext at most 1 MiB |

Parsers refuse unknown fields, trailing data, other versions and any field out
of range before running any cryptography.

## Associated data

```text
"hv1" | u32 len | resource | u32 len | env | u64 version | u32 len | kek_id
```

Integers are big-endian. Every variable-length field is length-prefixed, which
makes the encoding injective: `("a", "bc")` and `("ab", "c")` never produce
the same bytes. A property test checks this on random inputs.

- `resource`: the IAM resource of the secret, for example
  `hv:prod:secret/acme-api/DATABASE_URL`. No space, no control character,
  at most 1024 bytes.
- `env`: `[a-z][a-z0-9-]{0,31}`.
- `version`: the secret version, from 1.
- `kek_id`: bound so that a record cannot be relabelled to another KEK.

`kek_version` is deliberately **not** bound: rewrapping changes it without
touching the value ciphertext.

## Storage layout

Records live in an OpenBao KV v2 mount, one entry per secret version:

```text
<mount>/data/<env>/<app>/<KEY>/<N>      field "record": base64 of the hv1 JSON
```

- The version `N` bound into the associated data is part of the path, so it
  never changes. A new value is written with `cas=0` on the next free `N`:
  two concurrent writers cannot take the same number, the loser retries.
- The KV versions of one entry only move when the record is rewrapped. The
  previous KV versions are destroyed right after, so a retired wrapped key
  does not stay readable through the KV history.
- Destroying a secret version destroys its KV data but keeps its metadata:
  the number `N` stays visible and is never reused.
- The KEK is a `chacha20-poly1305` Transit key. Transit ciphertexts have the
  form `vault:v<k>:<base64>`; the record's `kek_version` must equal `k`, or
  the wrapper refuses to send it to OpenBao.

## Operations

**Seal**
1. Validate the binding and the plaintext size.
2. Ask the key wrapper for a fresh DEK and its wrapped form
   (`transit/datakey/plaintext/<kek>`).
3. Draw a 24-byte nonce, encrypt with the associated data above.
4. Wipe the plaintext DEK, store the record.

**Open**
1. Validate the binding and the record layout.
2. Unwrap the DEK (`transit/decrypt/<kek>`), open the ciphertext, wipe the DEK.
3. Any authentication failure returns one generic error: a wrong key, a moved
   record and a flipped bit are indistinguishable.

**KEK rotation**: rotate the Transit key, `rewrap` every wrapped DEK (the
plaintext DEK never leaves OpenBao), then raise `min_decryption_version`. The
value ciphertext and nonce are unchanged. A rewrap that changes `kek_id` is
refused.

**DEK rotation**: every write creates a new secret version, hence a new DEK.

**Crypto-shredding**: destroying a version deletes its record, which holds the
only copy of its wrapped DEK. The deletion is complete once the last backup
holding that record expires (the backup retention window, 7 days by default).
This is documented, not hidden.

## Memory hygiene

- Plaintext DEKs and values are `[]byte`, never `string`, and are cleared
  after use.
- The daemon (not implemented yet) will lock its memory (`mlock`), disable
  core dumps (`PR_SET_DUMPABLE=0`, `LimitCORE=0`) and run without swap. It
  will refuse to start if it cannot lock memory.
- Limit: the Go runtime may copy a buffer before it is cleared (stack growth,
  heap escape). Clearing narrows exposure; it cannot guarantee none.
- Tokens (with the daemon) will be 256-bit random values stored as SHA-256
  hashes and compared with `crypto/subtle.ConstantTimeCompare`.

## Test evidence

- The XChaCha20-Poly1305 primitive is checked against draft-irtf-cfrg-xchacha
  appendix A.3.1.
- Round trip, empty value, size limit.
- A ciphertext moved to another resource, environment, version or KEK id fails.
- Every single-bit flip in the ciphertext, nonce or wrapped DEK fails.
- Two seals of the same value share no nonce, DEK or ciphertext.
- DEKs handed out by the key wrapper are cleared after Seal and Open.
- Rewrap keeps the value openable after rotation and a raised minimum version;
  a rewrap that changes the KEK id is refused.
- The record parser is fuzzed: no panic, stable re-encoding, never opens under
  an unrelated KEK.
