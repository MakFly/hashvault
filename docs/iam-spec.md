# IAM specification

Status: policy language `hv-1`, implemented in `internal/iam`.

hashvault decides every request with policies in the spirit of AWS IAM:
deny by default, an explicit Deny always wins, a permission boundary can only
restrict. Policies are JSON documents, validated against closed catalogs so
that a typo is a parse error rather than a silent gap.

## Principals

| Type | Example | Authentication |
|---|---|---|
| Human | `human/alice` | FIDO2 SSH key (`ed25519-sk`) signing a challenge with a touch; OIDC + WebAuthn later |
| Machine | `machine/shuttle-helper@host1` | Signed deployment plan, key enrolled by ceremony |
| Remote agent | `machine/agent/vm12` | Ed25519 key enrolled by ceremony, mTLS over WireGuard |
| CI | `ci/github/acme/api@refs/heads/main` | GitHub Actions OIDC token |
| Workload | `workload/k8s/lab/acme/api` | Projected Kubernetes ServiceAccount token, TokenReview |
| Break-glass | `breakglass/1` | Offline key, disabled by default, every use alerts |

The current API authenticates humans and machines through SSHSIG challenge
responses. Shuttle verifies the operator's signed deployment plan in its own
root helper, then uses an enrolled machine SSH key on the vault's Unix socket.
Hashvault itself does not yet consume signed deployment plans or approval
proofs; `hv:Approved` remains false. The usable scoped machine policy is
[`examples/policies/shuttle-helper.json`](../examples/policies/shuttle-helper.json).
Other authentication types in the table describe the target design.

Deployment `prepare`, preparation reads and `confirm` require `secret:Publish`
on both the target and every declared secret. They never grant `secret:Read`.
Preparation listing also requires `secret:List` on the selected application.
Confirmations are deployer attestations with an expected-predecessor CAS, not
independent runtime health checks by the vault.

Tokens are opaque and short-lived: 15 minutes for humans, 5 minutes for
machines. There are no long-lived API keys for humans.

## Resources

| Pattern | Meaning |
|---|---|
| `hv:<env>:secret/<app>/<KEY>` | A secret. Secrets are target-agnostic: one value can be published to Swarm and Kubernetes. |
| `hv:<env>:target/<name>` | A registered publication target |
| `hv:policy/<name>` | A policy document |
| `hv:principal/<type>/<name>` | A principal (its key, tags and attached policies) |
| `hv:sys:unseal`, `hv:sys:seal` | Seal state |
| `hv:audit` | The audit log |

## Actions

The catalog is closed. `*` and `service:*` patterns are accepted, but every
pattern must cover at least one catalog action.

```text
approval:Grant
audit:Read
policy:Attach  policy:Get  policy:Put  policy:Simulate
principal:Create  principal:Disable  principal:Read
secret:Delete  secret:List  secret:Publish  secret:Read  secret:Rotate  secret:Write
sys:Seal  sys:Unseal
target:List  target:Register  target:Remove
```

Actions match case-insensitively. Resources match case-sensitively.

## Document

```json
{
  "Version": "hv-1",
  "Statement": [
    {
      "Sid": "OpsHuman",
      "Effect": "Allow",
      "Action": ["secret:*", "sys:*"],
      "Resource": "hv:*",
      "Condition": {
        "NumericLessThanEquals": {"hv:MfaAgeSeconds": 900},
        "StringEquals": {"hv:SourceChannel": "tunnel"}
      }
    }
  ]
}
```

- `Version` must be `hv-1`.
- 1 to 64 statements; `Sid` optional, letters and digits, unique per policy.
- `Action` and `Resource`: a string or an array of 1 to 64 strings. `*`
  matches any sequence, `?` one character. There is no escape.
- `Resource` is `*` or starts with `hv:`.
- Unknown fields are refused, as is any trailing data. Documents are limited
  to 64 KiB.

## Conditions

All operators of a statement must hold (AND), all keys of an operator must
hold (AND), and within one key any context value may match any policy value
(OR).

| Operator | Key type | Key absent |
|---|---|---|
| `StringEquals`, `StringLike` | string | false |
| `StringNotEquals`, `StringNotLike` | string | **true** |
| `NumericLessThanEquals`, `NumericGreaterThanEquals` | numeric | false |
| `DateLessThan`, `DateGreaterThan` | date (RFC 3339) | false |
| `Bool` | bool | false |

A negated operator holds when the key is absent. That makes "deny unless the
request came through the tunnel" expressible as a Deny with
`StringNotEquals: {"hv:SourceChannel": "tunnel"}`.

Policy values are checked against the key type at parse time: `"15min"` for a
numeric key or `"yes"` for a bool key is refused. Four string keys have a
closed set of values, and a value outside it is refused too (`"kubernetes"`
for `hv:TargetKind`, whose values are `k3s` and `k8s`). With `StringLike` and
`StringNotLike`, the pattern must match at least one allowed value:
`"k?s"` covers both Kubernetes targets.

| Key | Allowed values |
|---|---|
| `hv:TargetKind` | `docker` (plain Docker, Compose), `ssh` (classic SSH deployment), `swarm`, `k3s`, `k8s` |
| `hv:PublishMode` | `push`, `pull` |
| `hv:SourceChannel` | `tunnel`, `socket`, `agent` |
| `hv:PrincipalType` | `human`, `machine`, `ci`, `workload`, `breakglass` |

| Key | Type | Set by |
|---|---|---|
| `hv:ApprovalCount` | numeric | Number of distinct approvers of the request |
| `hv:Approved` | bool | The request met its approval rule |
| `hv:CurrentTime` | date | Server clock |
| `hv:Env` | string | Environment of the resource |
| `hv:MfaAgeSeconds` | numeric | Seconds since the last hardware-key touch |
| `hv:Namespace` | string | Kubernetes namespace of the target or workload |
| `hv:PlanAction` | string | Action named in a signed deployment plan |
| `hv:PrincipalTag/<name>` | string | Tags of the principal (CI ref, team...) |
| `hv:PrincipalType` | string | `human`, `machine`, `ci`, `workload`, `breakglass` |
| `hv:PublishMode` | string | `push` or `pull` |
| `hv:SourceChannel` | string | `tunnel`, `socket` or `agent` |
| `hv:TargetKind` | string | `docker`, `ssh`, `swarm`, `k3s`, `k8s` |
| `hv:TargetName` | string | Registered target name |

## Evaluation

1. An unauthenticated request, an unknown action, an invalid resource or a
   policy name attached twice: **ImplicitDeny**.
2. Collect every statement whose Action and Resource match, from the identity
   policies and the permission boundary, and evaluate its conditions.
3. If an applicable statement is a Deny: **ExplicitDeny**.
4. If no identity Allow applies: **ImplicitDeny**.
5. If a boundary is set and no boundary Allow applies: **ImplicitDeny**. An
   empty boundary denies everything.
6. Otherwise: **Allow**.

The result lists the statements that applied in a canonical order (identity
before boundary, then policy name, then index). The decision never depends on
the order of policies or statements.

`hashvault iam simulate` runs the same evaluation and returns, for every
statement, whether the action, the resource and each condition matched.

## Invariants under test

Checked on 20 000 random policy sets and requests each:

- no policy means ImplicitDeny;
- adding a Deny never turns a non-Allow into Allow;
- adding an identity Allow never revokes an Allow;
- a boundary never grants what the identity policies alone do not;
- the decision is ExplicitDeny exactly when a Deny statement applied;
- shuffling policies and statements changes neither the decision nor the set
  of applied statements.

The glob matcher is fuzzed against the `regexp` package as a reference, and the
parser is fuzzed for panics and for documents that validate but cannot be
evaluated.

## Example policies

`examples/policies/` holds five documents, each covered by a decision table
in `internal/iam/evaluate_test.go`:

| File | Principal | Grants |
|---|---|---|
| `ops-human.json` | operator | Everything on secrets, targets and seal, with a touch less than 15 minutes old, through the tunnel only |
| `deploy-bot.json` | deployment helper | Publish approved prod secrets to one Swarm target; reading, writing and policy changes are explicitly denied |
| `ci-preprod.json` | CI | Publish preprod secrets from `main` only; anything in prod is explicitly denied |
| `workload-pull.json` | Kubernetes workload | Pull its own app's secrets, from its namespace, in pull mode |
| `break-glass.json` | break-glass key | Unseal and read until a fixed expiry date |
