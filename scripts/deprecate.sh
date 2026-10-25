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
  # Security audit release. jwk and ua are not listed: their releases carry no
  # security-relevant change.
  "@exortek/apikey|<1.2.0|Security fixes in @exortek/apikey@1.2.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/auth|<2.0.0|Security fixes in @exortek/auth@2.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/challenge|<2.0.0|Security fixes in @exortek/challenge@2.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/crypto|<2.0.0|Security fixes in @exortek/crypto@2.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/jwe|<2.0.0|Security fixes in @exortek/jwe@2.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/jwks|<1.1.2|Security fixes in @exortek/jwks@1.1.2 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/jws|<1.1.0|Security fixes in @exortek/jws@1.1.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/jwt|<2.0.0|Security fixes in @exortek/jwt@2.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/magic-link|<3.0.0|Security fixes in @exortek/magic-link@3.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/oauth2|<2.0.0|Security fixes in @exortek/oauth2@2.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/oidc|<2.0.0|Security fixes in @exortek/oidc@2.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/opaque|<2.0.0|Security fixes in @exortek/opaque@2.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/otp|<1.1.5|Security fixes in @exortek/otp@1.1.5 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/paseto|<2.0.0|Security fixes in @exortek/paseto@2.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/passkey|<2.0.0|Security fixes in @exortek/passkey@2.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/password|<2.0.0|Security fixes in @exortek/password@2.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/security|<2.0.0|Security fixes in @exortek/security@2.0.0 — upgrade; see the CHANGELOG for migration notes."
  "@exortek/session|<2.0.0|Security fixes in @exortek/session@2.0.0 — upgrade; see the CHANGELOG for migration notes."
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
