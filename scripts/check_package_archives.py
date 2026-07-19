#!/usr/bin/env python3
"""Require the v1.0.0 wheel and sdist to match an exact public-file allowlist."""

from __future__ import annotations

import stat
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
VERSION = "1.0.0"
DISTRIBUTION = "madpanda_cloudflare_mcp"
PACKAGE_ROOT = ROOT / "src" / "cloudflare_mcp"
PACKAGE_FILES = {
    "cloudflare_mcp/__init__.py",
    "cloudflare_mcp/approval.py",
    "cloudflare_mcp/cloudflare.py",
    "cloudflare_mcp/config.py",
    "cloudflare_mcp/coverage.py",
    "cloudflare_mcp/data/__init__.py",
    "cloudflare_mcp/data/endpoint_coverage.json",
    "cloudflare_mcp/py.typed",
    "cloudflare_mcp/server.py",
    "cloudflare_mcp/tool_manifest.py",
}
SDIST_PUBLIC_FILES = {
    ".gitignore",
    "LICENSE",
    "NOTICE",
    "PKG-INFO",
    "README.md",
    "pyproject.toml",
}


def project_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        version = tomllib.load(handle)["project"].get("version")
    if not isinstance(version, str) or version != VERSION:
        raise AssertionError(f"expected static project version {VERSION}, found {version!r}")
    return version


def require_exact_source_package() -> None:
    observed = {
        path.relative_to(ROOT / "src").as_posix()
        for path in PACKAGE_ROOT.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }
    if observed != PACKAGE_FILES:
        raise AssertionError(
            "source package allowlist mismatch: "
            f"missing={sorted(PACKAGE_FILES - observed)} "
            f"unexpected={sorted(observed - PACKAGE_FILES)}"
        )


def require_safe_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise AssertionError(f"unsafe archive path: {name}")
    return path


def check_wheel(path: Path, version: str) -> None:
    expected_name = f"{DISTRIBUTION}-{version}-py3-none-any.whl"
    if path.name != expected_name:
        raise AssertionError(f"unexpected wheel filename: {path.name}")

    dist_info = f"{DISTRIBUTION}-{version}.dist-info"
    expected = set(PACKAGE_FILES)
    expected.update(
        {
            f"{dist_info}/METADATA",
            f"{dist_info}/RECORD",
            f"{dist_info}/WHEEL",
            f"{dist_info}/entry_points.txt",
            f"{dist_info}/licenses/LICENSE",
            f"{dist_info}/licenses/NOTICE",
        }
    )
    with zipfile.ZipFile(path) as archive:
        names: list[str] = []
        for member in archive.infolist():
            require_safe_path(member.filename)
            if member.is_dir():
                continue
            mode = member.external_attr >> 16
            if stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                raise AssertionError(f"wheel contains a non-regular file: {member.filename}")
            names.append(member.filename)
        for source_name in PACKAGE_FILES:
            if archive.read(source_name) != (ROOT / "src" / source_name).read_bytes():
                raise AssertionError(f"wheel source bytes differ from checkout: {source_name}")
    if len(names) != len(set(names)):
        raise AssertionError("wheel contains duplicate file entries")
    files = set(names)
    if files != expected:
        raise AssertionError(
            f"wheel allowlist mismatch: missing={sorted(expected - files)} "
            f"unexpected={sorted(files - expected)}"
        )


def check_sdist(path: Path, version: str) -> None:
    expected_name = f"{DISTRIBUTION}-{version}.tar.gz"
    if path.name != expected_name:
        raise AssertionError(f"unexpected sdist filename: {path.name}")

    prefix = f"{DISTRIBUTION}-{version}"
    expected = {f"{prefix}/{name}" for name in SDIST_PUBLIC_FILES}
    expected.update(f"{prefix}/src/{name}" for name in PACKAGE_FILES)
    with tarfile.open(path, mode="r:gz") as archive:
        names: list[str] = []
        for member in archive.getmembers():
            require_safe_path(member.name)
            if member.isdir():
                continue
            if not member.isfile():
                raise AssertionError(f"sdist contains a non-regular file: {member.name}")
            names.append(member.name)
        for source_name in PACKAGE_FILES:
            extracted = archive.extractfile(f"{prefix}/src/{source_name}")
            if extracted is None or extracted.read() != (ROOT / "src" / source_name).read_bytes():
                raise AssertionError(f"sdist source bytes differ from checkout: {source_name}")
        for source_name in SDIST_PUBLIC_FILES - {"PKG-INFO"}:
            extracted = archive.extractfile(f"{prefix}/{source_name}")
            if extracted is None or extracted.read() != (ROOT / source_name).read_bytes():
                raise AssertionError(f"sdist root bytes differ from checkout: {source_name}")
    if len(names) != len(set(names)):
        raise AssertionError("sdist contains duplicate file entries")
    files = set(names)
    if files != expected:
        raise AssertionError(
            f"sdist allowlist mismatch: missing={sorted(expected - files)} "
            f"unexpected={sorted(files - expected)}"
        )


def main() -> None:
    version = project_version()
    require_exact_source_package()
    wheels = sorted(DIST.glob("*.whl"))
    sdists = sorted(DIST.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("Expected exactly one wheel and one .tar.gz source distribution.")
    check_wheel(wheels[0], version)
    check_sdist(sdists[0], version)
    print(f"package archive allowlist passed for madpanda-cloudflare-mcp {version}")


if __name__ == "__main__":
    main()
