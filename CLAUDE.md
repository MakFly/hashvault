# CLAUDE.md

hashvault: self-hosted secrets vault and IAM layer over OpenBao, publishing to
five targets: `docker` (plain Docker, Compose), `ssh` (classic SSH
deployment), `swarm`, `k3s`, `k8s`. Go module
`github.com/MakFly/hashvault`, public open-source project (Apache-2.0).

- Checks: `make ci` (lint, race tests, coverage thresholds, govulncheck,
  gitleaks). Fast loop: `make test`.
- Specs are the source of truth: `docs/crypto-spec.md` (format `hv1`),
  `docs/iam-spec.md` (policy language `hv-1`), `docs/threat-model.md`. A code
  change that alters them updates them in the same change.
- Never change the `hv1` record layout or AAD encoding in place: add a format
  version.
- Secret material is `[]byte`, cleared after use, never logged.
- Public repository: no private infrastructure detail (IPs, real app names,
  real secret names). Examples use `acme-api`, `example.com`, `192.0.2.0/24`.
- staticcheck and gosec run with `LINT_TOOLCHAIN` (Go 1.26) until they read Go
  1.27 export data; see the Makefile.
- Add a line to `CHANGELOG.md` under "Unreleased" for every user-visible change.
