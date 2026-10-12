# Operations

How to install hashvault on one host, run the bootstrap ceremony, unseal,
and publish. Every command here is real; the Ansible role that automates the
install is the next step of the roadmap.

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
- `systemd-analyze security hashvaultd` stays under 2.0 with the hardened unit.
