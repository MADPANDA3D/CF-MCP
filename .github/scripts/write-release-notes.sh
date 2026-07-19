#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: write-release-notes.sh OUTPUT_FILE" >&2
  exit 2
fi
: "${IMAGE_NAME:?IMAGE_NAME is required}"
: "${IMAGE_DIGEST:?IMAGE_DIGEST is required}"
[[ "$IMAGE_NAME" == ghcr.io/* ]]
[[ "$IMAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]

{
  printf '%s\n\n' 'Cloudflare MCP v1.0.0 clean public release.'
  printf '%s\n' 'Python wheel and source archive are attached to this GitHub Release.'
  printf '%s\n\n' 'This project intentionally does not publish to PyPI.'
  printf 'Container: \x60%s@%s\x60\n\n' "$IMAGE_NAME" "$IMAGE_DIGEST"
  printf '%s\n' \
    'Verify package files with the attached SHA256SUMS and deploy the container by exact digest.'
} > "$1"
