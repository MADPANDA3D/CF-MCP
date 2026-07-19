#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -lt 2 || $# -gt 4 ]]; then
  echo "usage: $0 IMAGE BUILD_SHA [SOURCE_FINGERPRINT] [IMAGE_REFERENCE]" >&2
  exit 2
fi

image=$1
build_sha=$2
portal_grant=ci-portal-grant-000000000000000000000000000000000000000000
access_token=ci-standalone-token-000000000000000000000000000000000000000000
source_fingerprint=${3:-development}
image_reference=${4:-development}
active_container=

configured_env=$(docker image inspect "$image" --format '{{range .Config.Env}}{{println .}}{{end}}')
if grep -Eq '^HOME=' <<<"$configured_env"; then
  echo "image must preserve the runtime user's passwd HOME" >&2
  exit 1
fi
if ! grep -Fxq "MCP_BUILD_SHA=$build_sha" <<<"$configured_env"; then
  echo "image does not contain the expected baked build SHA" >&2
  exit 1
fi
if ! grep -Fxq "MCP_SOURCE_FINGERPRINT=$source_fingerprint" <<<"$configured_env"; then
  echo "image does not contain the expected baked source fingerprint" >&2
  exit 1
fi
configured_labels=$(docker image inspect "$image" --format '{{range $key, $value := .Config.Labels}}{{println $key "=" $value}}{{end}}')
if ! grep -Fxq "org.opencontainers.image.revision = $build_sha" <<<"$configured_labels"; then
  echo "image revision label does not match the expected build SHA" >&2
  exit 1
fi
if ! grep -Fxq "com.madpanda.source-fingerprint = $source_fingerprint" <<<"$configured_labels"; then
  echo "image source-fingerprint label does not match the expected source fingerprint" >&2
  exit 1
fi

cleanup() {
  if [[ -n "$active_container" ]]; then
    docker rm -f "$active_container" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for mode in portal standalone; do
  active_container="cloudflare-mcp-smoke-$mode"
  cleanup
  active_container="cloudflare-mcp-smoke-$mode"

  mode_env=(-e "MCP_MODE=$mode")
  if [[ "$mode" == portal ]]; then
    mode_env+=(-e "MCP_PORTAL_GRANT_TOKEN=$portal_grant")
  else
    mode_env+=(-e "MCP_ACCESS_TOKEN=$access_token")
  fi

  docker run -d --rm --name "$active_container" \
    --init --network none --read-only --user 10001:10001 \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
    "${mode_env[@]}" \
    -e "MCP_IMAGE_REFERENCE=$image_reference" \
    -e MCP_EXPECTED_TOOL_COUNT=6 \
    -e MCP_ALLOWED_HOSTS=127.0.0.1,localhost \
    -e MCP_APPROVAL_SIGNING_KEY=approval-smoke-key-000000000000000000000000 \
    "$image" >/dev/null

  ready=false
  for _ in {1..30}; do
    if docker exec "$active_container" python -c \
      "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).read()" \
      >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 1
  done
  if [[ "$ready" != true ]]; then
    docker logs "$active_container" >&2 || true
    exit 1
  fi
  docker exec "$active_container" python -c \
    "import os,pwd; e=pwd.getpwuid(os.getuid()); assert os.getuid()==10001; assert os.getgid()==10001; assert os.environ['HOME']==e.pw_dir; assert e.pw_dir!='/tmp'"
  if ! smoke_output=$(docker exec "$active_container" python /app/scripts/runtime_smoke.py 2>&1); then
    printf '%s\n' "$smoke_output" >&2
    docker logs "$active_container" >&2 || true
    exit 1
  fi
  printf '%s\n' "$smoke_output"
  cleanup
  active_container=
done
