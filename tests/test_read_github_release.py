from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "read-github-release.sh"


def _fake_gh(tmp_path: Path) -> Path:
    binary = tmp_path / "gh"
    binary.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
case "${GH_FAKE_STATUS:?}" in
  200)
    printf 'HTTP/2.0 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n%s' \
      "${GH_FAKE_BODY-}"
    ;;
  404)
    printf 'HTTP/2.0 404 Not Found\\r\\nContent-Type: application/json\\r\\n\\r\\n{}'
    exit 1
    ;;
  *)
    printf 'HTTP/2.0 %s Failure\\r\\nContent-Type: application/json\\r\\n\\r\\n{}' \
      "$GH_FAKE_STATUS"
    exit 1
    ;;
esac
"""
    )
    binary.chmod(0o755)
    return binary


def _run(tmp_path: Path, http_code: int, body: str = "{}") -> subprocess.CompletedProcess[str]:
    _fake_gh(tmp_path)
    env = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "GH_FAKE_STATUS": str(http_code),
        "GH_FAKE_BODY": body,
    }
    return subprocess.run(
        ["bash", str(SCRIPT), "repos/example/releases/tags/v1.0.0", str(tmp_path / "out.json")],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_present_release_writes_only_the_json_body(tmp_path: Path) -> None:
    body = json.dumps({"tag_name": "v1.0.0"})

    result = _run(tmp_path, 200, body)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "present"
    assert json.loads((tmp_path / "out.json").read_text()) == {"tag_name": "v1.0.0"}


def test_exact_404_is_the_only_absent_state(tmp_path: Path) -> None:
    output = tmp_path / "out.json"
    output.write_text("stale")

    result = _run(tmp_path, 404)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "absent"
    assert not output.exists()


def test_server_failure_is_not_treated_as_absent(tmp_path: Path) -> None:
    result = _run(tmp_path, 500)

    assert result.returncode != 0
    assert result.stdout == ""
    assert "HTTP 500" in result.stderr


def test_invalid_success_body_fails_closed(tmp_path: Path) -> None:
    result = _run(tmp_path, 200, "[]")

    assert result.returncode != 0
    assert result.stdout == ""
    assert "not a JSON object" in result.stderr
