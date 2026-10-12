# Deployment integration

Hashvault prepares secrets. Your deployment tool installs code or images and
checks the application's health. A preparation contains references and pinned
versions, never secret values. The CLI, console and integrations use the same
API and IAM evaluator.

```text
+--------------------------------------------+
| Operator CLI, console or deployment tool   |
+----------------------+---------------------+
                       |
                       v
+----------------------+---------------------+
| hashvaultd: authorize and prepare          |
| Resolve versions, install resources        |
+----------------------+---------------------+
                       |
                       v
+----------------------+---------------------+
| Deployer: apply code and references        |
| Check all consumers and application        |
+----------------------+---------------------+
                       |
                       v
+----------------------+---------------------+
| Confirm release, or restore old release    |
+--------------------------------------------+
```

## Application contract

Commit a `hashvault.json` containing names, consumers and file permissions:

```json
{
  "version": "hv-manifest-1",
  "app": "acme-api",
  "items": {
    "DATABASE_URL": {
      "expose": "env",
      "services": ["api", "worker"],
      "uid": "1000",
      "gid": "1000",
      "mode": "0400"
    }
  }
}
```

Service names must match the deployment configuration. Hashvault defaults to
UID/GID 0 and mode 0400; declare the actual service account for non-root
applications. The file target defaults to the lowercase key. `expose: env`
still mounts a file on Docker and Swarm: the image must export it at startup,
or the application must support a file-based configuration convention.

The manifest is target-independent. Target registration selects the environment
and runtime. Secret values are supplied separately with `secret put` or
`import dotenv`. Swarm never returns a stored value through its secrets API.

## Prepare and confirm

```sh
hashvault prepare --target swarm-main --manifest hashvault.json --output preparation.json
hashvault preparation get <preparation-id>
hashvault preparation list --target swarm-main --app acme-api
hashvault publication --target swarm-main --app acme-api
hashvault confirm <preparation-id> --release <release-id> --previous <active-preparation-id>
```

`prepare` resolves the whole version vector before decrypting values. Use
repeated `--version KEY=N` flags to select exact older versions. Preparation
does not create, modify or restart a workload. It works before a first deploy.

The descriptor's `id` identifies immutable resources. `confirm` records an
authorized deployer's attestation that its release uses those resources and
passed its checks. Hashvault does not independently probe an application during
confirmation. The expected previous id prevents stale confirmation; the first
confirmation uses an empty previous id. Repeating the same id and release is
idempotent. A different release with an obsolete predecessor returns HTTP 409.

Keep each descriptor with its release artifacts. Descriptors contain metadata
such as names and principals, so distribute them only where needed. Never
substitute latest versions while retrying or rolling back a release.

## Docker Swarm

Run hashvaultd on the manager with its local Docker Unix socket. A preparation
creates `hv_<app>_<target>_v<N>` objects and returns their names and IDs. It does
not need an existing service and does not run `service update`.

```sh
hashvault render preparation.json --format stack > secrets.json
docker stack deploy --detach=false -c stack.yml -c secrets.json acme
# Run the deployment tool's application and worker health checks here.
hashvault confirm <preparation-id> --release <release-id> --previous <previous-id>
```

The rendered JSON is valid YAML. It declares external secrets and per-service
mounts with the manifest's target, UID, GID and mode. Images remain free of
runtime secret values.

At migration, remove the old references for Hashvault-managed file targets
from the base stack. Docker's multi-file merge can retain references with a
different source name; an overlay alone does not safely migrate duplicate
mounts. Shuttle's native backend replaces matching legacy mounts automatically
and preserves foreign secrets.

Prepared objects are marked `hv.prepared=true`. Hashvault's existing GC keeps
them even while unmounted, because retained stack files may need them during
rollback. Retiring old preparations and their resources is an explicit operator
decision; this release does not automatically delete prepared generations.

## Docker and Compose

Enroll `hashvault-agent` on the Docker host and register a `docker` target.
The transport can be restricted SSH to a remote host, including localhost, or
the existing local sudo transport when service hardening permits it.

Preparation sends a signed, encrypted batch to the agent. Each generation has
its own encrypted credential directory and tmpfs copies:

```text
+---------------------------------------------------------+
| Encrypted files                                         |
| /etc/credstore.encrypted/.generations/<id>/<app>.<KEY>  |
+----------------------------+----------------------------+
                             |
                             v
+----------------------------+----------------------------+
| Tmpfs copies                                            |
| /run/hashvault/.generations/<id>/<app>/<service>/       |
+---------------------------------------------------------+
```

```sh
hashvault prepare --target docker-web-01 --manifest hashvault.json --output preparation.json
hashvault render preparation.json --format compose > mounts.json
docker compose -f compose.yml -f mounts.json up -d
# Verify every affected service, then confirm the preparation.
```

The rendered configuration mounts each service's generation directory read-only
at `/run/secrets`. For `docker run`, use the same descriptor's
`services.<service>.directory` as a read-only bind mount. The deployment tool
owns container creation, replacement and health checks.

Directories are versioned so preparing new values cannot alter files visible
to a running release. Boot materialization reconstructs all retained generations
from the host's encrypted store without contacting the vault. Restore an old
release by restoring its image and its original mount directory together.

## Deployments over SSH

Enroll an agent on the application host and register an `ssh` target. The same
generation mechanism supplies files, a per-service `.env` on tmpfs and encrypted
systemd credentials. The deployment tool chooses how its release consumes them:

- Link the new release's `.env` to `services.<service>.dotenv`. Do not rewrite
  the old release's link before promotion.
- Reference the generation's files directly in the application's configuration.
- Render a systemd drop-in with `hashvault render preparation.json --format
  systemd --service api`. Credential IDs are `<app>.<KEY>`, matching the name
  authenticated by systemd-creds. Read them through `$CREDENTIALS_DIRECTORY`.

Install the new release, configure its references, then reload or restart it and
run health checks. Keep the old release's references for rollback. The legacy
`hashvault-agent exec` continues to consume the active publication; prepared
deployments use their descriptor's fixed files instead.

The existing dotenv materializer rejects single quotes, newlines and NUL in
env-exposed values. Declare those values as files and configure the application
to read them directly.

## Shuttle

The corresponding Shuttle backend uses a signed helper operation named
`secrets-hashvault`. Its payload contains only the manifest. On the manager,
the helper authenticates a machine principal against the local vault socket,
requests preparation and returns only its descriptor to the workstation.

```yaml
secrets:
  backend: hashvault
  hashvault:
    target: swarm-main
    manifest: hashvault.json
```

`hashvault.json` is the service contract; remove duplicated `secrets.items`.
For a redeploy with a sealed vault, set the optional local
`secrets.hashvault.preparation` to a previously exported descriptor. The manifest
and descriptor must match. Referenced objects must still exist on the manager.

Create `/etc/shuttle/hashvault.json` on the manager, owned by root, mode 0600:

```json
{
  "socket": "/run/hashvault/api.sock",
  "principal": "machine/shuttle-helper",
  "key_file": "/etc/shuttle/hashvault.key"
}
```

Enroll the corresponding SSH public key with Hashvault and attach
`examples/policies/shuttle-helper.json`, adjusted to the actual application and
target. The machine key is a protected, noninteractive software key. It never
unseals the vault and is explicitly denied value reads. Signed deployment plans
are verified by Shuttle before it invokes the API; Hashvault authenticates the
enrolled machine and evaluates its own scoped IAM policy. Do not use the future
`hv:Approved`/`hv:PlanAction` example as if those conditions were implemented.

Shuttle records the preparation id in the retained stack, confirms after
successful convergence, and confirms the retained preparation after rollback.
If the vault becomes unavailable between deployment and confirmation, the
healthy release remains running and the helper leaves a metadata-only retry
record. Unseal the vault, then run `shuttle secrets sync`; it checks the current
release again before confirming it.

## Availability and limitations

A sealed or unavailable vault prevents new preparations. Already prepared
resources continue working and exported descriptors can be reused without a
vault request. Confirmation needs the vault; retry it after recovery.

Serialize deployments per application. Preparation is safe to do in parallel,
but two independent deployers must not race their workload specifications. The
confirmation CAS protects metadata, not the orchestrator from competing writers.
Use either deployment-managed preparations or legacy `publish` to manage a
given application's release, rather than running both concurrently.

Restoring an old value cannot restore an external credential which its provider
has revoked. Plan rotations with an overlap window when rollback must remain
possible. A single-node Docker or SSH restart also provides no automatic
zero-downtime guarantee; that belongs to the deployment strategy.
