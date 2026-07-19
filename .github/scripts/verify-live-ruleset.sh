#!/usr/bin/env bash
set -euo pipefail

allow_hidden=false
if [[ "$#" -eq 1 && "$1" == --allow-hidden-bypass-actors ]]; then
  allow_hidden=true
elif [[ "$#" -ne 0 ]]; then
  echo "usage: verify-live-ruleset.sh [--allow-hidden-bypass-actors]" >&2
  exit 2
fi

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
test "$GITHUB_REPOSITORY" = MADPANDA3D/CF-MCP

readback_dir=$(mktemp -d -p /tmp cloudflare-ruleset-readback.XXXXXX)
cleanup() {
  rm -f -- \
    "$readback_dir/repository.json" \
    "$readback_dir/main.json" \
    "$readback_dir/rulesets.json" \
    "$readback_dir/main-ruleset.json" \
    "$readback_dir/main-effective-rules.json"
  rmdir -- "$readback_dir"
}
trap cleanup EXIT

gh api "repos/$GITHUB_REPOSITORY" > "$readback_dir/repository.json"
gh api "repos/$GITHUB_REPOSITORY/branches/main" > "$readback_dir/main.json"
gh api \
  "repos/$GITHUB_REPOSITORY/rulesets?includes_parents=false&targets=branch&per_page=100" \
  > "$readback_dir/rulesets.json"

ruleset_name=$(jq -er .name .github/rulesets/protect-main.json)
mapfile -t ruleset_ids < <(jq -r \
  --arg name "$ruleset_name" \
  --arg source "$GITHUB_REPOSITORY" \
  '.[] | select(
    .name == $name
    and .source_type == "Repository"
    and .source == $source
  ) | .id' \
  "$readback_dir/rulesets.json")
if [[ "${#ruleset_ids[@]}" -ne 1 || ! "${ruleset_ids[0]}" =~ ^[0-9]+$ ]]; then
  echo "The exact repository-owned public-main ruleset is not unique." >&2
  exit 1
fi

gh api \
  "repos/$GITHUB_REPOSITORY/rulesets/${ruleset_ids[0]}?includes_parents=false" \
  > "$readback_dir/main-ruleset.json"
gh api "repos/$GITHUB_REPOSITORY/rules/branches/main" \
  > "$readback_dir/main-effective-rules.json"

arguments=(
  --repository-json "$readback_dir/repository.json"
  --branch-json "$readback_dir/main.json"
  --rulesets-json "$readback_dir/rulesets.json"
  --ruleset-json "$readback_dir/main-ruleset.json"
  --effective-rules-json "$readback_dir/main-effective-rules.json"
  --expected-config .github/rulesets/protect-main.json
  --repository "$GITHUB_REPOSITORY"
  --default-branch main
)
if [[ "$allow_hidden" == true ]]; then
  arguments+=(--allow-hidden-bypass-actors)
fi
python scripts/check_repository_ruleset.py "${arguments[@]}"
