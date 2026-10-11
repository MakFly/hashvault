# Governance

hashvault is maintained by its maintainers, listed in `.github/CODEOWNERS`.

- Maintainers review and merge pull requests. A change touching
  `internal/envelope`, `internal/iam`, `internal/authn`, `internal/audit` or a
  file format needs a maintainer review focused on security.
- Decisions that change a guarantee (threat model, crypto format, policy
  semantics) are proposed in an issue labelled `design`, with the reasoning,
  before code.
- Releases are cut by maintainers, signed, and published with an SBOM.
- New maintainers are invited after a sustained record of reviewed
  contributions.
