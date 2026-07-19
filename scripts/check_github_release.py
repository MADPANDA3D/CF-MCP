#!/usr/bin/env python3
"""Validate an exact GitHub Release JSON object and its local asset bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ExpectedAsset:
    name: str
    size: int
    digest: str


def parse_asset(value: str) -> ExpectedAsset:
    name, separator, raw_path = value.partition("=")
    if not separator or not name or not raw_path or "/" in name or "\\" in name:
        raise argparse.ArgumentTypeError("asset must use the safe form NAME=PATH")
    path = Path(raw_path)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"asset path is not a file: {path}")
    return ExpectedAsset(
        name=name,
        size=path.stat().st_size,
        digest=f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}",
    )


def parse_asset_metadata(value: str) -> ExpectedAsset:
    parts = value.split("=", 2)
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            "asset metadata must use the safe form NAME=SIZE=sha256:DIGEST"
        )
    name, raw_size, digest = parts
    if not name or "/" in name or "\\" in name or not raw_size.isdecimal():
        raise argparse.ArgumentTypeError(
            "asset metadata must use the safe form NAME=SIZE=sha256:DIGEST"
        )
    size = int(raw_size)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise argparse.ArgumentTypeError("asset metadata digest must be lowercase sha256")
    return ExpectedAsset(name=name, size=size, digest=digest)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--body-file", type=Path, required=True)
    parser.add_argument("--draft", choices=("true", "false", "any"), default="any")
    parser.add_argument("--prerelease", choices=("true", "false", "any"), default="any")
    parser.add_argument("--asset", action="append", type=parse_asset, default=[])
    parser.add_argument(
        "--asset-metadata",
        action="append",
        type=parse_asset_metadata,
        default=[],
    )
    args = parser.parse_args()
    if not args.asset and not args.asset_metadata:
        parser.error("at least one --asset or --asset-metadata is required")
    return args


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AssertionError(f"{label} must be a JSON object")
    return value


def expected_state(value: str) -> bool | None:
    if value == "any":
        return None
    return value == "true"


def require(condition: bool, message: object) -> None:
    if not condition:
        raise AssertionError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_nonstandard_number(value: str) -> None:
    raise ValueError(f"nonstandard JSON number: {value}")


def validate_release(args: argparse.Namespace) -> None:
    release = require_object(
        json.loads(
            args.release_json.read_text(),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonstandard_number,
        ),
        "release",
    )
    assets = [*args.asset, *args.asset_metadata]
    expected_assets = {item.name: item for item in assets}
    if len(expected_assets) != len(assets):
        raise AssertionError("expected asset names must be unique")

    require(release.get("tag_name") == args.tag, release.get("tag_name"))
    require(release.get("name") == args.title, release.get("name"))
    expected_body = args.body_file.read_text().strip()
    require(str(release.get("body") or "").strip() == expected_body, "release body mismatch")

    for key, requested in (
        ("draft", expected_state(args.draft)),
        ("prerelease", expected_state(args.prerelease)),
    ):
        observed = release.get(key)
        if not isinstance(observed, bool):
            raise AssertionError(f"release {key} must be boolean")
        if requested is not None and observed is not requested:
            raise AssertionError(f"release {key} is {observed}, expected {requested}")
    if release["draft"] is False and not isinstance(release.get("published_at"), str):
        raise AssertionError("published release must have a published_at timestamp")
    immutable = release.get("immutable")
    if immutable is not None and not isinstance(immutable, bool):
        raise AssertionError("release immutable must be boolean when present")

    assets_payload = release.get("assets")
    if not isinstance(assets_payload, list):
        raise AssertionError("release assets must be a JSON array")
    observed_assets: dict[str, dict[str, Any]] = {}
    for item in assets_payload:
        asset = require_object(item, "asset")
        name = asset.get("name")
        if not isinstance(name, str) or name in observed_assets:
            raise AssertionError("release asset names must be unique strings")
        observed_assets[name] = asset
    if observed_assets.keys() != expected_assets.keys():
        raise AssertionError(
            "release asset allowlist mismatch: "
            f"expected={sorted(expected_assets)} observed={sorted(observed_assets)}"
        )

    for name, expected in expected_assets.items():
        observed = observed_assets[name]
        require(observed.get("state") == "uploaded", (name, observed.get("state")))
        require(observed.get("size") == expected.size, (name, observed.get("size")))
        require(observed.get("digest") == expected.digest, (name, observed.get("digest")))

    print(
        f"GitHub Release {args.tag} matches the exact metadata and "
        f"{len(expected_assets)}-asset allowlist."
    )


def main() -> None:
    args = parse_args()
    try:
        validate_release(args)
    except (AssertionError, json.JSONDecodeError, OSError, ValueError) as exc:
        print(f"GitHub Release validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
