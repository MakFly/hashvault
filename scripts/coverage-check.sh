#!/usr/bin/env bash
# Enforce per-package statement coverage from a Go cover profile.
#
#   scripts/coverage-check.sh coverage.out
#
# Security-critical packages need 90%, the rest 80%. Test helper packages
# (envelopetest) are exercised through the packages that use them and are
# not measured on their own.
set -euo pipefail

profile=${1:?usage: coverage-check.sh <coverprofile>}
module=$(go list -m)

threshold() {
  case "$1" in
    internal/envelope | internal/iam | internal/audit | internal/authn | internal/approvals) echo 90 ;;
    */envelopetest) echo 0 ;;
    *) echo 80 ;;
  esac
}

# Per package: covered statements / total statements, from the raw profile.
report=$(awk -v mod="$module/" '
  NR == 1 { next }
  {
    split($1, loc, ":"); file = loc[1]; sub(mod, "", file)
    n = split(file, parts, "/"); pkg = parts[1]
    for (i = 2; i < n; i++) pkg = pkg "/" parts[i]
    total[pkg] += $2; if ($3 > 0) covered[pkg] += $2
  }
  END { for (p in total) printf "%s %.1f\n", p, 100 * covered[p] / total[p] }
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
