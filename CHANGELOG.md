# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- `internal/iam`: the glob matcher consumed a pattern `*` as a literal when
  the input held a `*` at the same position, so `a*` did not match `a*b`. A
  Deny statement could fail to apply to a context value containing `*`. Found
  by the differential fuzz target on its first CI run. Request resources may
  no longer contain `*` or `?`.

### Added

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
