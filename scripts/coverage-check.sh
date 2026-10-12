#!/usr/bin/env bash
# Enforce per-package statement coverage from a Go cover profile.
#
#   scripts/coverage-check.sh coverage.out
#
# Security-critical packages need 90%, the rest 80%. Test helper packages
# (envelopetest, baotest, dindtest) are not held to a threshold. Coverage is
# measured across packages (-coverpkg): a client exercised only through its
# adapter's integration tests counts as covered.
set -euo pipefail

profile=${1:?usage: coverage-check.sh <coverprofile>}
module=$(go list -m)

threshold() {
  case "$1" in
    internal/envelope | internal/iam | internal/audit | internal/authn | internal/approvals | internal/openbao | internal/secrets) echo 90 ;;
    */envelopetest | */baotest | */dindtest) echo 0 ;;
    *) echo 80 ;;
  esac
}

# Per package: covered statements / total statements. With -coverpkg the same
# block can appear once per test binary, so blocks are deduplicated and count
# as covered if any binary ran them.
report=$(awk -v mod="$module/" '
  NR == 1 { next }
  {
    block = $1; stmts[block] = $2; if ($3 > 0) hit[block] = 1
  }
  END {
    for (block in stmts) {
      split(block, loc, ":"); file = loc[1]; sub(mod, "", file)
      n = split(file, parts, "/"); pkg = parts[1]
      for (i = 2; i < n; i++) pkg = pkg "/" parts[i]
      total[pkg] += stmts[block]; if (block in hit) covered[pkg] += stmts[block]
    }
    for (p in total) printf "%s %.1f\n", p, 100 * covered[p] / total[p]
  }
' "$profile" | sort)

status=0
while read -r pkg pct; do
  min=$(threshold "$pkg")
  if awk -v p="$pct" -v m="$min" 'BEGIN { exit !(p + 0 < m + 0) }'; then
    printf '\033[31mFAIL\033[0m %-40s %5s%% < %s%%\n' "$pkg" "$pct" "$min"
    status=1
  else
    printf '\033[32mok  \033[0m %-40s %5s%% (min %s%%)\n' "$pkg" "$pct" "$min"
  fi
done <<< "$report"
exit "$status"
