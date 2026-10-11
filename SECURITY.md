# Security policy

hashvault holds production secrets. We treat every report seriously and
answer every one.

## Supported versions

hashvault is pre-alpha: only the latest commit on `main` is supported. Once
releases exist, the latest minor release receives security fixes.

## Reporting a vulnerability

**Do not open a public issue.** Use
[GitHub private vulnerability reporting](https://github.com/MakFly/hashvault/security/advisories/new).

Include what you can of:

- the affected component (`envelope`, `iam`, a target adapter, the daemon...);
- the impact: what an attacker gains, from which position (network, local
  user, compromised workload);
- a reproduction, with every real secret value redacted.

Never send a real secret, token or unseal key, even yours.

## What to expect

| Step | Target delay |
|---|---|
| Acknowledgement | 3 working days |
| First assessment (confirmed or not, severity) | 10 working days |
| Fix or mitigation for a confirmed issue | 90 days at most |

We coordinate disclosure with you, credit you in the advisory unless you
prefer otherwise, and publish a GitHub security advisory with the fix.

## Scope

In scope: this repository, its release artifacts and its documented
deployment procedures.

Out of scope (see `docs/threat-model.md`): attacks that require root on a host
running the workloads, a stolen hardware key together with its PIN, and
vulnerabilities in OpenBao, Docker, systemd or Kubernetes themselves (report
those upstream; tell us if hashvault's use of them makes things worse).
