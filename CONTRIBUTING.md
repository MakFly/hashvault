# Contributing

Thank you for helping. hashvault guards production secrets, so the bar for a
change is "proven", not "looks right".

## Before you start

- For anything beyond a small fix, open an issue first to agree on the
  approach.
- Security issues go through `SECURITY.md`, never a public issue or PR.

## Workflow

1. Fork, then branch from `main`: `feat/...`, `fix/...`, `docs/...`.
2. Make the change with its tests.
3. Run `make ci`. It must pass.
4. Add a line under "Unreleased" in `CHANGELOG.md`.
5. Open a pull request using the template.

## Rules for code

- Go, formatted with `gofmt`. English identifiers, comments and docs.
- No new dependency without a reason in the PR description. Cryptography uses
  the standard library, `golang.org/x/crypto` or OpenBao; never a new
  primitive or an unaudited library.
- Secret material is `[]byte`, cleared after use, never a `string`, never
  logged, never in an error message.
- Errors from authentication paths stay generic: they must not tell an
  attacker which check failed.

## Rules for tests

- Every behavior has a test. Security invariants get a property test; parsers
  get a fuzz target.
- Integration tests run against real OpenBao and Docker binaries, not mocks.
- Coverage thresholds (`scripts/coverage-check.sh`) are 90% for `envelope`,
  `iam`, `audit`, `authn` and `approvals`, 80% elsewhere. Do not lower them
  to merge.
- Changing the `hv1` format or the `hv-1` policy language means a new version
  plus a migration path, never an in-place edit.

## Commits

- Conventional prefixes: `feat(iam): ...`, `fix(envelope): ...`, `docs: ...`.
- Sign off every commit (`git commit -s`): you certify the
  [Developer Certificate of Origin](https://developercertificate.org/).

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
