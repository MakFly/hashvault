# Threat model

Status: design baseline. It describes the target architecture; parts of it are
not implemented yet (see the roadmap in `README.md`).

## Assets

- Secret values and their versions.
- The KEK (OpenBao Transit) and the unseal key.
- Policies, principals and approvals.
- The audit log and its anchors.

## Trust zones

```text
+------------------------------------------------------------+
| T1 Operator workstation: hashvault CLI, hardware key       |
+-----------------------------+------------------------------+
                              | SSH tunnel, never public HTTP
- - - - - - - - - - - - - - - + - - - - - - - - - - - - - - -  B1 network
                              v
+-----------------------------+------------------------------+
| T2 Vault host: hashvaultd + OpenBao (systemd, unix sockets)|
|    deployment helper, orchestrator store (encrypted)       |
+-----------------------------+------------------------------+
                              | published copy only
- - - - - - - - - - - - - - - + - - - - - - - - - - - - - - -  B2 workload
                              v
+-----------------------------+------------------------------+
| T3 Workloads: /run/secrets, .env on tmpfs, k8s Secret      |
+------------------------------------------------------------+
```

Workloads never call the vault in the default push mode. A sealed or stopped
vault blocks publications, not running services.

## Threats and controls

| Threat (STRIDE) | Where | Control |
|---|---|---|
| Spoofing a human | B1 | FIDO2 SSH key signing a challenge with a touch; 15-minute tokens |
| Spoofing a machine | T2 socket | Signed deployment plan checked against hashvault's own principal registry; peer credentials on the unix socket |
| Spoofing a remote agent | agent link | Outbound connection, WireGuard and mTLS, key enrolled by ceremony, 5-minute tokens |
| Tampering: moving a ciphertext | storage | AEAD with associated data binding resource, environment, version and KEK id |
| Tampering: audit log | audit file | Hash chain, signed checkpoints, off-host anchors |
| Repudiation | everywhere | Every read, write, publish, policy change and unseal is audited |
| Disclosure: logs, env, core dumps, swap | daemon | Locked memory, no core dumps, no swap, logs carry fingerprints only |
| Disclosure: backups | snapshots | Barrier encryption plus age encryption to hardware keys |
| Disclosure: credential store on a Docker or SSH host | target host | `systemd-creds` encryption (host key, TPM2 when present), root-only files, service-only `$CREDENTIALS_DIRECTORY` |
| Disclosure: `.env` of an SSH deployment | target host | Materialised on tmpfs only (never on disk, never in the release directory), mode 0400, owned by the app user, re-created at boot from the encrypted store |
| Spoofing the SSH push channel | vault > SSH host | Dedicated user, key restricted by `command=` and `restrict` in `authorized_keys`, host key pinned |
| Disclosure: Kubernetes Secrets | etcd | Publication refused without encryption at rest; namespace RBAC; immutable objects |
| Denial of service | T2 | Push mode keeps workloads running while sealed; per-principal rate limits |
| Elevation through policy | IAM | Policy writes need approval; simulator; explicit Deny wins; closed catalogs |

## Out of scope, stated plainly

- **Root on a target host** can read every secret published there, and root
  on the vault host can read the daemon's memory while it is unsealed.
  hashvault narrows the window (automatic re-seal after inactivity, default
  60 minutes) and keeps root to a single operator account. It does not stop a
  malicious root.
- **A compromised hardware key with its PIN** is equivalent to the operator.
  Enrol a backup key and revoke a lost one immediately.
- **The orchestrator itself**: Swarm Raft encryption, etcd encryption and the
  container runtime are trusted once a value is published to them.
- **Side channels** on shared hardware (co-tenant VMs) are not addressed.

## Staging is not production

A Proxmox LXC staging environment shares the host kernel, has no TPM, limits
`RLIMIT_MEMLOCK` and runs some systemd hardening directives as no-ops. Results
there validate behavior and procedures, not the isolation guarantees of the
final host.
