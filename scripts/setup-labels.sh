#!/usr/bin/env bash
# Create / update the standard label set on the ExorTek/auth repo.
#
#   Usage:
#     bash scripts/setup-labels.sh
#
# Requires the GitHub CLI (`gh`) authenticated against the repo.
# `--force` overwrites existing labels' colour + description so this
# script is safe to re-run.

set -euo pipefail

REPO="${REPO:-ExorTek/auth}"

# name|color|description
LABELS=(
  "type:bug|d73a4a|Something is broken or behaves incorrectly"
  "type:enhancement|a2eeef|New feature, API, or behaviour proposal"
  "type:docs|7057ff|Documentation content or website content"
  "type:question|d876e3|Support-shaped issue — often belongs in Discussions"
  "type:chore|cccccc|Tooling, CI, build, refactor with no user-visible change"

  "status:needs-triage|fbca04|Not yet reviewed by a maintainer"
  "status:accepted|0e8a16|Confirmed and scheduled for work"
  "status:blocked|b60205|Waiting on an upstream fix, decision, or external factor"
  "status:duplicate|cfd3d7|Already tracked elsewhere; comment links the original"
  "status:wontfix|ffffff|Out of scope or explicitly declined"

  "pkg:crypto|0075ca|Concerns @exortek/crypto"
  "pkg:security|006b75|Concerns @exortek/security"
  "pkg:otp|1d76db|Concerns @exortek/otp"
  "pkg:password|5319e7|Concerns @exortek/password"
  "pkg:session|c5def5|Concerns @exortek/session"
  "pkg:jwk|bfd4f2|Concerns @exortek/jwk"
  "pkg:jws|d4c5f9|Concerns @exortek/jws"
  "pkg:jwt|f9d0c4|Concerns @exortek/jwt"
  "pkg:challenge|a2eeef|Concerns @exortek/challenge"
  "pkg:apikey|c2e0c6|Concerns @exortek/apikey"
  "pkg:magic-link|fef2c0|Concerns @exortek/magic-link"
  "pkg:jwks|e6e6fa|Concerns @exortek/jwks"
  "pkg:tooling|e4e669|Repo tooling — build, CI, docs site, monorepo config"

  "good-first-issue|7057ff|Small, well-scoped — a nice entry point for new contributors"
  "help-wanted|008672|Maintainers welcome a PR; not urgent"
  "breaking-change|b60205|Requires a major version bump"
)

echo "Applying label set to $REPO"

for spec in "${LABELS[@]}"; do
  IFS='|' read -r name color desc <<< "$spec"
  printf '  · %-24s ' "$name"
  gh label create "$name" \
    --repo "$REPO" \
    --color "$color" \
    --description "$desc" \
    --force > /dev/null
  echo "ok"
done

echo "Done."
