# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- README: document Swarm secret names as versioned app and target names, with
  hashvault updating consuming service references.

### Fixed

- `internal/iam`: the glob matcher consumed a pattern `*` as a literal when
  the input held a `*` at the same position, so `a*` did not match `a*b`. A
  Deny statement could fail to apply to a context value containing `*`. Found
  by the differential fuzz target on its first CI run. Request resources may
  no longer contain `*` or `?`.

### Added

- `hashvaultd` (`cmd/hashvaultd`, `docs/operations.md`): one-time bootstrap
  ceremony (initialises OpenBao, mounts, KEK, a minimal OpenBao policy and an
  AppRole, audit and batch signing keys stored sealed, the first FIDO2
  administrator, the unseal bundle encrypted with age to hardware keys, root
  token revoked); starts sealed; unseal accepted from the operators' SSH
  tunnel only, locked out after five failures; seals itself and OpenBao when
  idle or on shutdown; refuses to start without locked memory.
- HTTP API on a unix socket (`internal/server`): secrets, policies,
  principals, IAM simulator, targets, publication, audit verification. Every
  request is authorized by IAM with a context from the session, the
  kernel-reported peer (source channel) and the request, and audited before
  it runs; the audit log failing stops the operation.
- Registry (`internal/registry`) of principals, policies, targets and
  publication records in OpenBao KV; IAM actions `principal:Create`,
  `principal:Disable`, `principal:Read`.
- Operator CLI `hashvault` (`cmd/hashvault`): login with `ssh-keygen -Y
  sign`, secrets, `import dotenv` (refuses keys it cannot store before storing
  anything, reports `${VAR}` references), policies, principals, simulator,
  targets, publish, audit, unseal with age identities (YubiKey plugin),
  seal. Values come from stdin or files, never from arguments.
- `internal/authn`: challenge-response login with SSH keys in the OpenSSH
  SSHSIG format (`ssh-keygen -Y sign -n hashvault-login`). Challenges name the
  vault and the principal, live 60 s and are single use. FIDO2 keys
  (`sk-ssh-ed25519`) must carry the user-presence flag, and the touch time
  becomes `hv:MfaAgeSeconds`; a software key logs in but never satisfies an
  MFA condition. Tokens are opaque, stored as SHA-256 only, 15 min for humans
  and 5 min for machines. Only ed25519 and sk-ed25519 keys, without options.
- `internal/audit`: tamper-evident audit log. JSON lines chained by SHA-256,
  appended with fsync, verified on open (a broken chain refuses to open);
  Ed25519-signed checkpoints, and verification against anchors kept off the
  host, which exposes a fully rewritten history or a truncation below an
  anchor. Detail keys that look like secret values are refused.
- `docker` and `ssh` targets, vault side (`internal/target/host`): batches
  addressed to one agent, delivered by local `sudo -n hashvault-agent
  receive` or by OpenSSH with a pinned host key and a key restricted to that
  command; compose services (docker) or reload commands (ssh) as consumers; a
  rolled back receipt surfaces as a verify error; a downgrade needs the
  signed rollback flag (`Desired.Rollback`). Tested end to end against the
  real agent in process, and against a real OpenSSH server in a throwaway
  container.
- Host agent for the `docker` and `ssh` targets (`cmd/hashvault-agent`,
  `docs/host-agent.md`): receives a batch signed by the vault (Ed25519) and
  encrypted to that agent only (age hybrid, ML-KEM-768 + X25519), checks
  addressee, freshness and replay, seals each value with `systemd-creds`,
  materialises it on tmpfs per service (files and a literal `.env`), restarts
  compose services or runs reload commands, and restores the previous values
  on failure. `materialize` rebuilds tmpfs at boot from the store alone;
  `exec` runs a command with the env items. Deployment files: boot unit,
  sudoers rule, restricted `authorized_keys` line.
- Test images come from the AWS ECR Public mirror of the Docker official
  images, which avoids Docker Hub's anonymous pull quota.
- Swarm target (`internal/target/swarm`): one immutable swarm secret per
  version, named `hv_<app>_<target>_v<N>` (from the version, never from a hash
  of the value), labelled with its hashvault coordinates. Plan, apply, verify
  (a paused or rolled back update fails), rollback, inventory and garbage
  collection after a retention window. A hand-made secret mounted on a managed
  file name is replaced, other mounts are kept: the migration path from
  `*_v1` secrets. Objects whose labels disagree with their name are refused.
- App manifest `hashvault.json` (`hv-manifest-1`), the env contract: exposure,
  file name, consuming services, uid, gid and mode, with unknown fields,
  write or execute modes and two keys on one mount refused.
- `internal/dockerapi`: minimal standard-library Docker Engine API client.
- Integration tests against a throwaway Docker-in-Docker daemon; the host
  daemon is never used as a test target.
- `internal/openbao`: minimal standard-library client for OpenBao (KV v2 with
  check-and-set, Transit data keys, decrypt, rewrap, rotation, seal status),
  over a unix socket or loopback TCP, with bounded responses and no proxy.
  Transit-backed key wrapper for the hv1 envelope.
- `internal/secrets`: versioned secrets, one KV entry per version, safe
  concurrent writers, crypto-shredding that never reuses a version number,
  rewrap of every live version after a KEK rotation.
- Integration tests against a real OpenBao 2.7.1 dev server
  (`make openbao` downloads the pinned, checksum-verified binary).
- `internal/envelope`: format `hv1`, one data encryption key per secret version,
  XChaCha20-Poly1305 with associated data that binds the resource, the
  environment, the version and the wrapping key name; rewrap after rotation;
  strict record parser.
- `internal/iam`: policy language `hv-1` with closed action and condition-key
  catalogs, explicit Deny, permission boundaries, negated operators and a
  simulator. Closed value sets for `hv:TargetKind` (`docker`, `ssh`, `swarm`,
  `k3s`, `k8s`), `hv:PublishMode`, `hv:SourceChannel` and `hv:PrincipalType`.
- Five example policies in `examples/policies/`, each covered by a decision
  table.
- Specifications: `docs/crypto-spec.md`, `docs/iam-spec.md`,
  `docs/threat-model.md`.
- Tests: draft-irtf-cfrg-xchacha vector, tamper and relocation tests, IAM
  property tests, fuzz targets for the record parser, the policy parser and
  the glob matcher (differential against `regexp`).
- CI: lint, race tests, coverage thresholds, govulncheck, gitleaks, short
  fuzzing; nightly fuzzing; OpenSSF Scorecard.
