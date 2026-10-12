# Operations

How to install hashvault on one host, run the bootstrap ceremony, unseal,
and publish. Every command here is real; the Ansible role that automates the
install is the next step of the roadmap. Linux release artifacts now include
an installer, static console assets and the systemd units used below.

## Install a Linux artifact

Download the package and checksum from the repository's packaging workflow,
verify the archive, then extract and install it. The installer supports a
custom absolute prefix and never starts services or overwrites vault data.

```sh
sha256sum -c hashvault-<version>-linux-amd64.tar.gz.sha256
tar -xzf hashvault-<version>-linux-amd64.tar.gz
sh hashvault/scripts/install.sh --prefix /usr/local --services
```

OpenBao is an external dependency, not vendored into the monorepo. Install a
verified OpenBao binary at `/usr/local/bin/bao` before using its service unit.
The integration suite pins and verifies the version recorded in the Makefile.

Create dedicated `hashvault` and `openbao` system accounts, with group
`hashvault` available to both units. Copy the provided configuration examples
to `/etc/hashvault/hashvaultd.json` and `/etc/openbao/openbao.hcl`; assign
ownership to their service accounts and restrict their permissions. Never
replace an existing OpenBao storage directory during an upgrade.

Set `tunnel_uids` from the actual SSH operator account's UID. That account also
needs permission to traverse `/run/hashvault` and connect to its socket, through
the `hashvault` group or a narrowly scoped ACL. Do not infer the operator from
a seed or Git metadata. Complete the bootstrap below before starting hashvaultd.

The daemon unit permits a local Swarm socket through the Docker group and
restricted remote SSH agents. Its `NoNewPrivileges` and read-only filesystem
hardening intentionally prevent the local sudo transport; use a restricted SSH
agent on localhost when preparing Docker/SSH resources on the same manager.

Install units and configuration on the actual manager, reload systemd's unit
definitions, start OpenBao for the bootstrap ceremony, then enable the daemon
after its generated role id is present. Configuration and runtime service
installation are operator actions; the package installer does not perform them.

```text
+------------------------------+       +------------------------------+
| Operator workstation         |       | Vault host                   |
| hashvault CLI, FIDO2 key,    | ssh   | OpenBao (raft, unix socket)  |
| unseal bundle + identity     +------>+ hashvaultd (unix socket)     |
+------------------------------+  -L   +--------------+---------------+
                                                      |
                                                      v
                                       +--------------+---------------+
                                       | Targets: swarm (local socket)|
                                       | docker / ssh (hashvault-agent)|
                                       +------------------------------+
```

## 1. OpenBao

Install the release binary (checksum checked) and run it under systemd as the
`openbao` user, integrated storage, listening on a unix socket only:

```hcl
# /etc/openbao/openbao.hcl
storage "raft" {
  path    = "/var/lib/openbao/raft"
  node_id = "vault-1"
}
listener "unix" {
  address      = "/run/openbao/api.sock"
  socket_mode  = "0660"
  socket_group = "hashvault"
}
api_addr     = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
```

OpenBao starts sealed and uninitialised. Do not initialise it by hand: the
hashvault bootstrap does it.

## 2. hashvaultd

```json
// /etc/hashvault/hashvaultd.json (0600, owner hashvault)
{
  "vault_id": "vault-1",
  "listen": "/run/hashvault/api.sock",
  "openbao": "unix:///run/openbao/api.sock",
  "kek": "hv-kek-prod",
  "audit_path": "/var/lib/hashvault/audit.jsonl",
  "tunnel_uids": [1001],
  "ssh_dir": "/etc/hashvault/ssh",
  "idle_seal_minutes": 60
}
```

`tunnel_uids` lists the uids of the operator accounts that reach the socket
through SSH: a request from them is `hv:SourceChannel=tunnel`, and only they
may unseal. Run the daemon with `LimitMEMLOCK=infinity`: it refuses to start
if it cannot lock its memory.

## 3. Bootstrap (once)

On the vault host, with the administrator's FIDO2 public key and the bundle
recipients (two hardware keys and an offline key are a sensible minimum):

```sh
hashvaultd init --config /etc/hashvault/hashvaultd.json \
  --admin human/alice --admin-key alice_sk.pub \
  --recipient age1yubikey1... --recipient age1yubikey1... --recipient age1pq1... \
  --bundle-out /root/unseal-bundle.age
```

The ceremony initialises OpenBao (one unseal key), mounts the KV and Transit
engines, creates the KEK, an OpenBao policy limited to what hashvaultd needs
and its AppRole, generates the audit and batch signing keys (stored sealed),
creates the administrator, encrypts the unseal key and the AppRole secret id
to the recipients, and revokes the root token. It prints the batch signing
public key: hosts running `hashvault-agent` pin it.

Copy the bundle off the host, then delete it there.

## 4. Unseal, from the workstation

```sh
ssh -N -L /tmp/hv.sock:/run/hashvault/api.sock ops@vault-1 &
export HASHVAULT_SOCKET=/tmp/hv.sock
hashvault unseal --bundle unseal-bundle.age --identity yubikey-identity.txt   # PIN, touch
hashvault login --principal human/alice --key ~/.ssh/id_ed25519_sk           # touch
```

After `idle_seal_minutes` without an authenticated request, the daemon seals
itself and OpenBao. Published secrets keep working; publishing needs a new
unseal.

## 5. Everyday use

```sh
hashvault secret put prod/acme-api/DATABASE_URL < db-url.txt
hashvault import dotenv /path/to/.env --env prod --app legacy --dry-run
hashvault policy put deployer deployer.json
hashvault principal create machine/deployer --key deployer.pub
hashvault principal attach machine/deployer deployer
hashvault iam simulate --principal machine/deployer --action secret:Read \
  --resource hv:prod:secret/acme-api/DATABASE_URL
hashvault target put swarm-main.json
hashvault publish --target swarm-main --manifest hashvault.json --dry-run
hashvault publish --target swarm-main --manifest hashvault.json
hashvault audit verify
hashvault seal
```

Target files:

```json
{"name": "swarm-main", "kind": "swarm", "env": "prod",
 "config": {"docker": "unix:///var/run/docker.sock", "stack": "acme"}}

{"name": "web-01", "kind": "ssh", "env": "prod",
 "config": {"agent": "web-01", "recipient": "age1pq1...",
            "transport": {"type": "ssh", "host": "web-01.example.com", "user": "hashvault",
                          "key_file": "push_ed25519", "known_hosts_file": "web-01.known_hosts"},
            "reload": {"acme-api": [["/usr/bin/systemctl", "reload", "php8.4-fpm"]]}}}
```

`key_file` and `known_hosts_file` are plain names inside `ssh_dir`: a target
registration cannot point the daemon at another file. Swarm targets accept a
unix Docker socket only. `k3s` and `k8s` targets are on standby: registering
one is refused.

## 6. Checks after an install

- `ss -ltn` lists no port for OpenBao or hashvaultd.
- `hashvault status` answers through the tunnel; from another account the
  unseal is refused.
- `hashvault audit verify` reports `ok: true`.
- Validate the installed units and review `systemd-analyze security hashvaultd`.
  Its Docker socket access is deliberately privileged; a numeric hardening
  score is not a proof of isolation from the manager's workloads.
- Prepare a first deployment and verify both its references and consumers,
  following [`deployments.md`](deployments.md).
- Open the local console following [`console.md`](console.md).
