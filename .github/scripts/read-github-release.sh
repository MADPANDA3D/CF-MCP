#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: read-github-release.sh API_ENDPOINT OUTPUT_JSON" >&2
  exit 2
fi

api_endpoint=$1
output_json=$2
rm -f "$output_json"
response_file=$(mktemp -p /tmp cloudflare-release-response.XXXXXX)
trap 'rm -f "$response_file"' EXIT

set +e
gh api --include "$api_endpoint" > "$response_file" 2>/dev/null
gh_exit=$?
set -e

http_code=$(awk '/^HTTP\// {code=$2} END {print code}' "$response_file")
case "$http_code" in
  200)
    if [[ "$gh_exit" -ne 0 ]]; then
      echo "GitHub returned HTTP 200 but gh exited with $gh_exit." >&2
      exit 1
    fi
    python - "$response_file" "$output_json" <<'PY'
import json
import sys
from pathlib import Path

response_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
payload = response_path.read_bytes()
for separator in (b'\r\n\r\n', b'\n\n'):
    if separator in payload:
        body = payload.split(separator, 1)[1]
        break
else:
    raise SystemExit('GitHub response did not contain a header/body boundary.')
try:
    value = json.loads(body)
except json.JSONDecodeError as exc:
    raise SystemExit(f'GitHub Release response was not valid JSON: {exc.msg}.') from None
if not isinstance(value, dict):
    raise SystemExit('GitHub Release response was not a JSON object.')
output_path.write_bytes(body)
PY
    echo present
    ;;
  404)
    if [[ "$gh_exit" -eq 0 ]]; then
      echo "GitHub returned HTTP 404 but gh reported success." >&2
      exit 1
    fi
    rm -f "$output_json"
    echo absent
    ;;
  "")
    echo "GitHub Release request did not return an HTTP status." >&2
    exit 1
    ;;
  *)
    echo "GitHub Release request failed with HTTP $http_code." >&2
    exit 1
    ;;
esac
