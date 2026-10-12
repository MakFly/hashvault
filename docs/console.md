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

For development, `make dev` starts a persistent local OpenBao vault, its real
hashvault API, Vite on `http://127.0.0.1:4322`, and the CLI security bridge on
loopback port 8822. Open `http://127.0.0.1:4322/`. No SSH tunnel or manual login
is needed for this local vault.
The explicit `--dev-session` mode bootstraps its process-local browser cookie
using a same-origin POST with strict Host and Origin checks. Release mode keeps
its one-use launch nonce. Vite forwards `/api` and `/session`
to that bridge; API routes cannot fall through to `index.html`.

The development-only `hashvault-local` executable uses Raft storage in
`.tools/dev-vault` (ignored by Git). Its Unix API socket, credentials, machine
key and token are private to the current OS user. OpenBao uses dynamically
selected loopback API/cluster ports. `machine/dev-local` authenticates with a
software SSH key through the existing SSHSIG login. The launcher renews that
five-minute machine session every two minutes. This session does not claim MFA.
Bootstrap revokes its root token once the restricted daemon AppRole is ready.

The local unseal key and AppRole credential are stored in an owner-only local
file, allowing automatic unseal on restart. This convenience is for development
only, with no hardware ceremony or idle sealing. Use sample secrets here. The
production daemon, its FIDO2 bootstrap and SSH authentication are unchanged;
`hashvault-local` is not included in release artifacts. The automatic local
vault refuses deployment preparation/publication, so it cannot invoke Docker
or SSH adapters. Target and access forms still use the real local registry.

`make stop` stops only the owned development processes and removes runtime
tokens/sockets, retaining secrets and audit history. It also recognizes a launch
made with the previous UI-only runner. After using **Seal vault** locally,
`make stop` followed by `make dev` reopens the local vault. Existing
`HASHVAULT_SOCKET` and `HASHVAULT_TOKEN_FILE` settings do not redirect `make dev`
to production. For local CLI commands while the stack is running:

```sh
export HASHVAULT_SOCKET="$PWD/.tools/dev-vault/api.sock"
export HASHVAULT_TOKEN_FILE="$PWD/.tools/dev-vault/token"
.tools/hashvault-dev status
```

An unavailable vault displays an offline state inside the console with secret
actions disabled. It does not replace the whole application with a router error.

The scoped frontend logger follows Tanship's readable development format:
time, level, scope, method, path, status, duration and correlation metadata.
Browser diagnostics also appear in the Vite terminal through its HMR channel.
Production browser logs are JSON. Terminal `LOG_LEVEL`, `LOG_FORMAT=json` and
`NO_COLOR` are supported; `VITE_NO_COLOR` disables browser console colors.
Secret values, request/response bodies, launch nonces, tokens and cookies are
never logged. Paths omit query strings and fragments. Error details are reduced
to their type, because raw messages and stacks can contain secret material.

`make ui-check` installs the locked Bun workspace, typechecks and lints it, and
checks that regenerated API definitions are unchanged. This work adds no
frontend unit tests or browser test suite. Source checks do not establish visual
or runtime browser behavior.
