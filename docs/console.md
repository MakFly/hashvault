# Local web console

The repository is a Go/Bun monorepo. `ui/` contains React, TypeScript, Vite,
shadcn components and React Router Data Mode. `api/openapi.json` is the API
contract; `bun run api:types` regenerates the UI's TypeScript definitions.

The release ships static UI assets with the CLI. It requires no JavaScript
server in production. The installer places them at
`<prefix>/share/hashvault/ui`, which `hashvault ui` discovers beside its binary.

## Open the console

Keep the usual SSH tunnel to the daemon's Unix socket open, authenticate with
your operator key, then launch the local console:

```sh
export HASHVAULT_SOCKET=/tmp/hv.sock
hashvault login --principal human/operator --key ~/.ssh/id_ed25519_sk
hashvault ui
```

Open the one-use URL printed by the CLI. An explicit `--assets DIR` selects an
existing released asset directory; `--listen 127.0.0.1:8822` selects a numeric
loopback address. The bridge refuses non-loopback listeners.

The browser exchanges the launch nonce for a process-local HttpOnly, SameSite
Strict cookie. The Hashvault bearer remains in the CLI, never in browser storage
or URLs. The loopback HTTP bridge enforces its exact Host and Origin, refuses
browser authentication requests, and serves assets through an `os.Root` confined
filesystem. Closing the CLI ends that browser session. Keep the bridge local;
it is not an authenticated public web gateway.

The CLI reuses the token from `hashvault login`. On expiry or sealing, authenticate
again in the terminal and refresh the console. FIDO2 SSH signatures are produced
by the existing CLI, not emulated with browser WebAuthn. Unseal remains the
operator's terminal ceremony.

## Screens

- Secrets: select an environment and application, add versions, inspect history
  and explicitly reveal a value with separate read permission. Values are hidden
  again after 30 seconds and cleared from the view when it closes.
- Deployments: prepare a manifest, download or inspect its metadata-only
  descriptor, inspect the last publication and record a verified release.
- Targets: register or edit Swarm, Docker and SSH target configurations.
- Access: enroll SSH public keys, create or edit policies, attach permission
  boundaries and disable principals.
- Audit: verify the local hash chain and signed checkpoints.

The console does not poll authenticated endpoints while idle, so it does not
keep a vault artificially unsealed. Status requests omit authentication.
Every permitted operation still goes through the daemon's IAM and audit path;
UI visibility is not an authorization boundary.

## Source checks

`make ui-check` installs the locked Bun workspace, typechecks and lints it, and
checks that regenerated API definitions are unchanged. This work adds no
frontend unit tests or browser test suite. Source checks do not establish visual
or runtime browser behavior.
