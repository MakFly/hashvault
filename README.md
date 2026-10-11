# hashvault

**Self-hosted secrets vault with AWS-style IAM for Docker, classic SSH
deployments, Docker Swarm, k3s and Kubernetes, built on OpenBao.**

[![ci](https://github.com/MakFly/hashvault/actions/workflows/ci.yml/badge.svg)](https://github.com/MakFly/hashvault/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/MakFly/hashvault/badge)](https://scorecard.dev/viewer/?uri=github.com/MakFly/hashvault)
[![Go Report Card](https://goreportcard.com/badge/github.com/MakFly/hashvault)](https://goreportcard.com/report/github.com/MakFly/hashvault)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Status: pre-alpha.** The envelope encryption format and the IAM policy
> engine are implemented and tested. The daemon, the CLI and the target
> adapters are not written yet. Do not use hashvault for real secrets yet.
> See the [roadmap](#roadmap).

hashvault is a small control plane that becomes the single source of truth for
production secrets, and the only way a human or a machine reads, writes,
rotates or publishes them. It publishes each secret to where your workloads
run: a plain Docker host, a server you deploy to over SSH, a Swarm, a k3s or a
Kubernetes cluster. Your services keep running even while the vault is sealed.

## Why

Running a few services on Docker Swarm or a small cluster, secrets tend to end
up scattered:

- **Swarm secrets are immutable and unreadable.** Rotating one means a new name
  (`db_password_v2`) and a coordinated stack update, by hand.
- **Out-of-band changes get reverted.** A `docker service update --secret-add`
  that is not mirrored in the stack file disappears at the next deploy.
- **A typo is a silent outage.** When a secret's target doubles as an
  environment variable name, a misspelled target breaks nothing at boot and
  one feature in production, for weeks.
- **Operator passwords have no home.** They live in a `0600` file on a laptop.

Full-featured vaults solve storage, but not publication to a Swarm, a plain
Docker host or an SSH-deployed server,
and their policy languages have no conditions on MFA age, source channel or
approvals. hashvault adds exactly that layer on top of
[OpenBao](https://openbao.org), and nothing else.

## Features

- **Envelope encryption**: one data key per secret version, XChaCha20-Poly1305,
  ciphertexts bound to their resource, environment and version. Key
  encryption keys live in OpenBao Transit and can move to an HSM or KMS.
- **AWS-style IAM**: JSON policies, explicit Deny wins, permission boundaries,
  conditions on MFA age, source channel, approvals, target and time. Closed
  catalogs turn typos into parse errors. A simulator explains every decision.
- **Push publishing to five targets**: plain Docker (`docker run`, Compose),
  classic SSH deployments (`.env`, systemd, PM2, supervisor, PHP-FPM), Docker
  Swarm (directly, or as the secrets backend of a deployment tool), k3s and
  Kubernetes. Optional pull mode (systemd credential socket, Secrets Store CSI
  provider).
- **Sealed by default**: hardware-key unseal (YubiKey through
  `age-plugin-yubikey`), automatic re-seal after inactivity, no unseal secret
  on disk.
- **Tamper-evident audit**: hash-chained log, signed checkpoints, off-host
  anchors.
- **No network exposure**: unix sockets only, operators come in through an
  SSH tunnel, remote targets through an outbound agent.

## Architecture

```text
+--------------------+   +--------------------+   +--------------------+
| hashvault CLI      |   | deployment helper  |   | web UI (later)     |
| (SSH tunnel)       |   | (signed plans)     |   | (SSH tunnel)       |
+---------+----------+   +---------+----------+   +---------+----------+
          |                        |                        |
          +------------------------+------------------------+
                                   | unix socket
                                   v
+----------------------------------+-----------------------------------+
| hashvaultd                                                           |
|   authn : FIDO2 SSH keys, signed plans, OIDC (CI)                    |
|   iam   : evaluator, simulator, approvals                            |
|   crypto: hv1 envelope, one DEK per version                          |
|   audit : hash chain, signed checkpoints                             |
|   targets: docker, ssh, swarm, k3s, k8s                              |
+----------------------------------+-----------------------------------+
                                   | unix socket, token in memory only
                                   v
+----------------------------------+-----------------------------------+
| OpenBao: KV v2 (envelopes), Transit (KEK), Shamir seal, Raft         |
+----------------------------------------------------------------------+
```

Workloads read a copy that was already published (Swarm Raft, encrypted
credential store on the host, Kubernetes Secret). They never call hashvault, so sealing the
vault blocks publications, not production.

## Targets

| Target (`hv:TargetKind`) | What it is | Mechanism | Works while sealed |
|---|---|---|---|
| `docker` | `docker run` or Docker Compose, no Swarm | `systemd-creds` store, materialised to tmpfs at boot, bind-mounted to `/run/secrets` | yes, across reboots |
| `ssh` | Classic deployment over SSH (rsync, git pull) run by systemd, PM2, supervisor or PHP-FPM | Encrypted store on the host, then a `.env` on tmpfs, `LoadCredentialEncrypted=`, or `hashvault-agent exec` | yes, across reboots |
| `swarm` | Docker Swarm | Secret objects named by value digest, rolled by the deployer | yes |
| `k3s` | k3s cluster | Immutable `Secret` objects named by digest, rollout on change; refused unless `k3s secrets-encrypt` is enabled | yes (push mode) |
| `k8s` | Any other Kubernetes (vanilla, EKS, GKE, AKS...) | Same, refused without an `EncryptionConfiguration` (KMS v2 preferred) | yes (push mode) |

## Planned usage

Not implemented yet; this is the interface the roadmap targets.

```sh
hashvault unseal                                   # touch your YubiKey
hashvault secret put acme-api/DATABASE_URL --stdin
hashvault iam simulate --principal machine/deployer \
  --action secret:Publish --resource hv:prod:secret/acme-api/DATABASE_URL
hashvault publish acme-api --target swarm-main
hashvault audit verify
```

## Security model

Read [`docs/threat-model.md`](docs/threat-model.md),
[`docs/crypto-spec.md`](docs/crypto-spec.md) and
[`docs/iam-spec.md`](docs/iam-spec.md). In short:

- only standard, audited primitives (`golang.org/x/crypto`, OpenBao Transit,
  age); no home-made cipher;
- every security claim has a test, a property test or a fuzz target behind it;
- root on a host that runs your workloads can read what is published there.
  hashvault narrows exposure windows; it does not defeat a malicious root.

Report vulnerabilities privately: see [`SECURITY.md`](SECURITY.md).

## How it compares

| | hashvault | OpenBao / Vault | Infisical | SOPS + age | Swarm secrets |
|---|---|---|---|---|---|
| Encrypted storage | via OpenBao | yes | yes | files in Git | Raft |
| Conditional IAM (MFA age, channel, approvals) | yes | path ACLs | roles | no | no |
| Publishes to Docker, SSH hosts, Swarm | yes | no | partial | no | n/a |
| Runs while the vault is sealed | yes | n/a | n/a | yes | yes |
| Moving parts | 2 daemons | 1 | app + Postgres + Redis | none | none |

hashvault does **not** do dynamic database credentials, PKI, or SaaS
synchronisation. Use OpenBao directly for those.

## Roadmap

| Phase | Content | Status |
|---|---|---|
| P0 | Envelope format, IAM engine, specs, CI | in progress |
| P1 | Daemon and CLI, Swarm through a deployment tool backend, staging on a Proxmox LXC | planned |
| P2 | Plain Docker, classic SSH deployments, Swarm without a deployment tool | planned |
| P3 | Web UI through the tunnel, OIDC for humans, docs site | planned |
| P4 | k3s and k8s, CSI provider, CI OIDC | planned |

Every release runs for at least 7 days on a staging LXC, with recovery drills,
before it reaches a production host.

## Development

Requires Go 1.26 or later (the module pins its toolchain).

```sh
make help      # every target, by section
make openbao   # pinned OpenBao binary for integration tests (checksum verified)
make test      # unit, property and integration tests, race detector
make cover     # every test, integration required, per-package thresholds
make lint      # gofmt, go vet, staticcheck, gosec
make fuzz      # every fuzz target, FUZZTIME=30s each
make ci        # everything CI runs
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE). OpenBao is a separate project under MPL-2.0; hashvault
talks to it over its API and does not include its code.
