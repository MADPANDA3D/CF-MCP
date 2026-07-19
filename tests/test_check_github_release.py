from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_github_release.py"
TITLE = "MADPANDA3D Cloudflare MCP v1.0.0"


def _digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _fixture(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Path], Path]:
    assets = {
        "package.whl": tmp_path / "package.whl",
        "package.tar.gz": tmp_path / "package.tar.gz",
        "SHA256SUMS": tmp_path / "SHA256SUMS",
    }
    assets["package.whl"].write_bytes(b"wheel")
    assets["package.tar.gz"].write_bytes(b"sdist")
    assets["SHA256SUMS"].write_text("fixture checksums\n")
    body = tmp_path / "notes.md"
    body.write_text("fixture release body\n")
    release: dict[str, Any] = {
        "tag_name": "v1.0.0",
        "name": TITLE,
        "body": "fixture release body",
        "draft": False,
        "prerelease": False,
        "immutable": False,
        "published_at": "2026-07-19T00:00:00Z",
        "assets": [
            {
                "name": name,
                "state": "uploaded",
                "size": path.stat().st_size,
                "digest": _digest(path),
            }
            for name, path in assets.items()
        ],
    }
    return release, assets, body


def _run(
    tmp_path: Path,
    release: dict[str, Any],
    assets: dict[str, Path],
    body: Path,
    *,
    metadata_assets: bool = False,
) -> subprocess.CompletedProcess[str]:
    release_json = tmp_path / "release.json"
    release_json.write_text(json.dumps(release))
    command = [
        sys.executable,
        str(SCRIPT),
        "--release-json",
        str(release_json),
        "--tag",
        "v1.0.0",
        "--title",
        TITLE,
        "--body-file",
        str(body),
        "--draft",
        "false",
        "--prerelease",
        "false",
    ]
    for name, path in assets.items():
        if metadata_assets:
            command.extend(
                (
                    "--asset-metadata",
                    f"{name}={path.stat().st_size}={_digest(path)}",
                )
            )
        else:
            command.extend(("--asset", f"{name}={path}"))
    return subprocess.run(command, check=False, capture_output=True, text=True)


def test_exact_release_is_accepted(tmp_path: Path) -> None:
    release, assets, body = _fixture(tmp_path)

    result = _run(tmp_path, release, assets, body)

    assert result.returncode == 0, result.stderr
    assert "3-asset allowlist" in result.stdout


def test_exact_release_metadata_is_accepted_without_local_asset_bytes(tmp_path: Path) -> None:
    release, assets, body = _fixture(tmp_path)

    result = _run(tmp_path, release, assets, body, metadata_assets=True)

    assert result.returncode == 0, result.stderr
    assert "3-asset allowlist" in result.stdout


def test_unexpected_asset_is_rejected(tmp_path: Path) -> None:
    release, assets, body = _fixture(tmp_path)
    release["assets"].append(
        {
            "name": "unexpected.txt",
            "state": "uploaded",
            "size": 0,
            "digest": f"sha256:{'0' * 64}",
        }
    )

    result = _run(tmp_path, release, assets, body)

    assert result.returncode != 0
    assert "asset allowlist mismatch" in result.stderr


def test_digest_mismatch_is_rejected(tmp_path: Path) -> None:
    release, assets, body = _fixture(tmp_path)
    release["assets"][0]["digest"] = f"sha256:{'0' * 64}"

    result = _run(tmp_path, release, assets, body)

    assert result.returncode != 0


def test_draft_release_is_rejected_when_published_is_required(tmp_path: Path) -> None:
    release, assets, body = _fixture(tmp_path)
    release["draft"] = True
    release["published_at"] = None

    result = _run(tmp_path, release, assets, body)

    assert result.returncode != 0
    assert "release draft is True" in result.stderr
