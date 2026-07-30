#!/usr/bin/env bash
#
# Create a GitHub Release for every published @exortek/* package at its
# current version — tag + the package's top CHANGELOG entry as the notes.
# Run this locally after `yarn release` (or the release.yml workflow) has
# published to npm; it fills in the GitHub "Releases" page, which the CI
# publish step does not touch.
#
# Idempotent: a package that already has a Release for its current version
# is skipped, so re-runs and unchanged packages are no-ops. `gh release
# create` creates AND pushes the tag atomically.
#
# Usage:
#   ./scripts/releases.sh            # dry-run (default) — prints what it would create
#   ./scripts/releases.sh --apply    # actually create the Releases
#
# Requires the `gh` CLI authenticated (check with `gh auth status`).

set -euo pipefail

REPO="ExorTek/auth"
MODE="${1:-dry}"
if [[ "$MODE" == "--apply" ]]; then
  ACTION="apply"
else
  ACTION="dry-run"
fi

if [[ "$ACTION" == "apply" ]]; then
  if ! gh auth status >/dev/null 2>&1; then
    echo "gh CLI not authenticated. Run: gh auth login" >&2
    exit 1
  fi
fi

# Tags point at the currently checked-out commit — run from a checkout whose
# package.json versions match what was published.
sha="$(git rev-parse HEAD)"
echo "==> releases.sh · mode=$ACTION · target=${sha:0:7}"
echo

created=0
skipped=0
for dir in packages/*/; do
  name="$(node -p "try{require('./${dir}package.json').name}catch{''}")"
  [[ -z "$name" ]] && continue
  private="$(node -p "try{require('./${dir}package.json').private?'y':'n'}catch{'y'}")"
  [[ "$private" == "y" ]] && continue # @exortek/shared is private — not published
  ver="$(node -p "require('./${dir}package.json').version")"
  tag="${name}@${ver}"

  if gh release view "$tag" -R "$REPO" >/dev/null 2>&1; then
    echo "  skip (exists): $tag"
    skipped=$((skipped + 1))
    continue
  fi

  if [[ "$ACTION" == "apply" ]]; then
    notes="$(mktemp)"
    # Top CHANGELOG block: from the first "## " up to (not including) the next.
    awk '/^## /{c++} c==1{print} c==2{exit}' "${dir}CHANGELOG.md" >"$notes" 2>/dev/null || true
    [[ -s "$notes" ]] || echo "Release $tag" >"$notes"
    gh release create "$tag" -R "$REPO" --target "$sha" --title "$tag" --notes-file "$notes"
    rm -f "$notes"
    echo "  created: $tag"
  else
    echo "  [dry] would create: $tag"
  fi
  created=$((created + 1))
done

echo
echo "==> ${created} to create · ${skipped} already present"
[[ "$ACTION" == "dry-run" ]] && echo "dry-run complete. Re-run with --apply to create the Releases."
