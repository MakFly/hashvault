# Host agent (`docker` and `ssh` targets)

`hashvault-agent` is a small root helper installed on hosts without an
orchestrator: a plain Docker host (`docker run`, Docker Compose) or a server
you deploy to over SSH (rsync, git pull; systemd, PM2, supervisor, PHP-FPM).
The vault never logs in to these hosts as root and never leaves a value on
their disk in clear.

```text
+----------------------------------------------------------+
| hashvaultd: builds a batch, signs it (Ed25519), encrypts |
| it to this agent only (age, ML-KEM-768 + X25519)         |
+----------------------------+-----------------------------+
                             | sudo -n hashvault-agent receive (local)
                             | or SSH key restricted to that command
                             v
+----------------------------+-----------------------------+
| hashvault-agent receive (root)                           |
|   checks signature, addressee, freshness, replay         |
|   seals each value with systemd-creds                    |
|   > /etc/credstore.encrypted/<app>.<KEY>  (+ .prev)      |
+----------------------------+-----------------------------+
                             v
+----------------------------+-----------------------------+
| materialise on tmpfs, one directory per service:         |
|   /run/hashvault/<app>/<service>/<target>   0400         |
|   /run/hashvault/<app>/<service>/.env       0400         |
+----------------------------+-----------------------------+
                             v
+----------------------------+-----------------------------+
| restart consumers: compose services (docker) or reload   |
| commands (ssh); on failure, previous values are put back |
+----------------------------------------------------------+
```

## What protects what

- **Confidentiality in transit**: age hybrid encryption to the agent's own
  identity. Nobody else, the vault included, can decrypt a batch once sealed.
- **Authenticity**: an Ed25519 signature by the vault, over a
  domain-separated message. The agent pins the vault's public key. Encryption
  alone would not do: the agent's recipient is public.
- **Freshness**: a batch names its agent and is valid for at most 10 minutes
  (30 s clock skew). Its id is remembered until it expires, and a key never
  goes back to an older version unless the batch carries the signed rollback
  flag.
- **At rest**: values are sealed by `systemd-creds` with the host key, and the
  TPM2 when the machine has one. The credential name is bound into the
  ciphertext, so a file renamed to another credential does not decrypt.
- **In use**: the clear copy lives on tmpfs only. The agent refuses to
  materialise into a directory that is not tmpfs. Files are `0400` and owned
  by the uid and gid of the manifest; directories are root-owned `0711`.
- **Least privilege**: the vault (or the SSH push user) may run exactly
  `hashvault-agent receive` as root, with no argument and no environment.

## Install

```sh
install -m 0755 hashvault-agent /usr/local/bin/
hashvault-agent init --agent web-01 \
  --trusted-signer '<vault Ed25519 public key, base64>' \
  [--docker-socket unix:///var/run/docker.sock]   # docker hosts only
# prints the agent recipient (age1pq1...): register it in the vault

install -m 0644 deploy/systemd/hashvault-materialize.service /etc/systemd/system/
systemctl enable hashvault-materialize.service
install -m 0440 deploy/sudoers.d/hashvault-agent /etc/sudoers.d/   # visudo -cf first
```

For `ssh` targets, create a `hashvault` user and install its key as in
`deploy/authorized_keys.example`: `restrict,command="sudo -n
/usr/local/bin/hashvault-agent receive"`.

`init` refuses to overwrite an existing identity. The configuration
(`/etc/hashvault-agent/config.json`) and the identity must not be writable
(config) or readable (identity) by group or others; the agent refuses them
otherwise. `sealer_command` must end with `systemd-creds`.

## Consuming the values

### Docker Compose (`docker`)

Mount the service directory, not single files: a rotation replaces files by
rename, and a single-file bind mount would keep pointing at the old one.

```yaml
services:
  api:
    volumes:
      - /run/hashvault/acme-api/api:/run/secrets:ro
```

The agent restarts the containers labelled
`com.docker.compose.project=<project>` and `com.docker.compose.service=<svc>`
and waits until they run (and are healthy, when they have a healthcheck).

### systemd service (`ssh`)

```ini
# /etc/systemd/system/acme-api.service.d/hashvault.conf
[Service]
LoadCredentialEncrypted=DATABASE_URL:acme-api.DATABASE_URL
```

The service reads `$CREDENTIALS_DIRECTORY/DATABASE_URL`.

### `.env` (`ssh`, Laravel, Symfony, Node, Rails)

Point the release's `.env` at the tmpfs copy:

```sh
ln -sfn /run/hashvault/acme-api/web/.env /var/www/acme-api/current/.env
```

Values are written `KEY='value'`: single quotes are literal in the common
dotenv parsers, so a `$` stays a `$`. A value containing a single quote, a
newline or a NUL cannot be written that way; the publication is refused and
rolled back. Expose such a value as a file instead.

### PM2, supervisor, a binary (`ssh`)

```sh
hashvault-agent exec --app acme-api --service web -- /usr/bin/node server.js
```

The agent decrypts the env items of that service, adds them to the
environment and replaces itself with the command (no shell, absolute path).

## Vault side

`internal/target/host` builds the batch and delivers it. One adapter serves
both kinds; only the consumers differ:

| | `docker` | `ssh` |
|---|---|---|
| Consumers | every compose service named in the manifest items | the reload commands configured for the app |
| Usual transport | `LocalSudo`: `sudo -n /usr/local/bin/hashvault-agent receive` | `SSH`: OpenSSH client to the restricted key |

The SSH transport runs the system `ssh` with `-F /dev/null` (no user or
system configuration can override it), `BatchMode`, `IdentitiesOnly`, no agent,
no forwarding, and `StrictHostKeyChecking=yes` against a pinned
`known_hosts` file: there is no trust on first use. It sends no remote
command; the server's `command=` decides what runs.

A plan for a host target lists what will be pushed and restarted: the agent
exposes nothing but `receive`, so its state is not read from the vault.
Going back after a successful publication is a new publication of the
previous versions with the rollback flag, signed in the batch.

## Rollback

Each key keeps its previous sealed value as `<file>.prev`. If materialising or
restarting fails, the agent restores the previous files and metadata,
materialises and restarts again, and answers `rolled_back`. A batch that was
rolled back is not recorded, so it can be retried once the cause is fixed.

## Receipt

`receive` prints one JSON line and never a value:

```json
{"batch_id":"…","app":"acme-api","status":"applied","items":{"DATABASE_URL":3},"at":"…"}
```

`status` is `applied`, `rolled_back` or `refused`; the exit code is 0 only for
`applied`.
