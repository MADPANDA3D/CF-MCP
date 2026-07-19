#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_REF_NAME:?GITHUB_REF_NAME is required}"

test "$GITHUB_REPOSITORY" = MADPANDA3D/CF-MCP
test "$GITHUB_REF_NAME" = v1.0.0
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]

default_branch=$(gh api "repos/$GITHUB_REPOSITORY" --jq .default_branch)
test "$default_branch" = main

default_branch_sha=$(gh api \
  "repos/$GITHUB_REPOSITORY/branches/$default_branch" \
  --jq .commit.sha)
if [[ "$default_branch_sha" != "$GITHUB_SHA" ]]; then
  echo "::error::Canonical main moved to $default_branch_sha; expected release SHA $GITHUB_SHA."
  exit 1
fi

tag_ref_json=$(mktemp -p /tmp cloudflare-tag-ref.XXXXXX.json)
gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$GITHUB_REF_NAME" > "$tag_ref_json"
tag_ref_sha=$(jq -r .object.sha "$tag_ref_json")
tag_ref_type=$(jq -r .object.type "$tag_ref_json")
if [[ "$tag_ref_type" != tag || ! "$tag_ref_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::$GITHUB_REF_NAME is not an annotated tag."
  exit 1
fi

tag_object_json=$(mktemp -p /tmp cloudflare-tag-object.XXXXXX.json)
gh api "repos/$GITHUB_REPOSITORY/git/tags/$tag_ref_sha" > "$tag_object_json"
tag_name=$(jq -r .tag "$tag_object_json")
tag_target_type=$(jq -r .object.type "$tag_object_json")
tag_target_sha=$(jq -r .object.sha "$tag_object_json")
if [[ "$tag_name" != "$GITHUB_REF_NAME" \
  || "$tag_target_type" != commit \
  || "$tag_target_sha" != "$GITHUB_SHA" ]]; then
  echo "::error::$GITHUB_REF_NAME no longer points directly to release SHA $GITHUB_SHA."
  exit 1
fi

echo "Release refs remain exact: main and annotated $GITHUB_REF_NAME -> $GITHUB_SHA."
