#!/usr/bin/env bash
#
# Deprecate old versions of every @exortek/* package.
#
# For each package we tell npm "deprecate everything matching this semver
# range" — one call per package, npm handles the version fan-out.
#
# Usage:
#   ./scripts/deprecate.sh              # dry-run (default)
#   ./scripts/deprecate.sh --apply      # actually runs npm deprecate
#   ./scripts/deprecate.sh --undo       # clears deprecation on the same ranges
#
# Requires `npm whoami` to succeed (i.e. `npm login` was run in this shell).

set -euo pipefail

# Format:  <package>|<semver-range-to-deprecate>|<reason-shown-to-users>
#
# Ranges are cumulative — each new release supersedes every prior version.
# When bumping, replace the range (don't stack multiple entries per package).
ENTRIES=(
  "@exortek/jwt|<1.2.0|Upgrade to @exortek/jwt@^1.2.0 — atomic CAS for token rotation, Redis dialect override."
  "@exortek/jwks|<1.0.1|Upgrade to @exortek/jwks@^1.0.1 — cache:false fix, SSRF hardening, abort-listener leak."
  "@exortek/password|<1.1.0|Upgrade to @exortek/password@^1.1.0 — constant-time history check, verify cost cap."
  "@exortek/otp|<1.1.0|Upgrade to @exortek/otp@^1.1.0 — dead ErrorCode cleanup."
  "@exortek/session|<1.3.0|Upgrade to @exortek/session@^1.3.0 — fingerprint binding bypass fix, fail-closed verify."
  "@exortek/security|<1.3.0|Upgrade to @exortek/security@^1.3.0 — CSRF form-field fix, dead fallback removal, XFF walk."
)

MODE="${1:-dry}"
case "$MODE" in
  --apply) ACTION="apply"   ;;
  --undo)  ACTION="undo"    ;;
  *)       ACTION="dry-run" ;;
esac

if [[ "$ACTION" != "dry-run" ]]; then
  if ! npm whoami >/dev/null 2>&1; then
    echo "npm CLI not authenticated. Run: npm login" >&2
    exit 1
  fi
  echo "npm user: $(npm whoami)"
fi

echo "==> deprecate.sh · mode=$ACTION · entries=${#ENTRIES[@]}"
echo

for row in "${ENTRIES[@]}"; do
  pkg="${row%%|*}"
  rest="${row#*|}"
  range="${rest%%|*}"
  reason="${rest#*|}"
  spec="${pkg}@${range}"

  case "$ACTION" in
    apply)
      echo "  $spec"
      echo "    reason: $reason"
      npm deprecate "$spec" "$reason"
      ;;
    undo)
      echo "  $spec (undo)"
      npm deprecate "$spec" ""
      ;;
    dry-run)
      echo "  [dry] npm deprecate '$spec' '$reason'"
      ;;
  esac
done

echo
[[ "$ACTION" == "dry-run" ]] && echo "dry-run complete. Re-run with --apply to deprecate."
exit 0
