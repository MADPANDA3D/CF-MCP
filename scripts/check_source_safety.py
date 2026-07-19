#!/usr/bin/env python3
"""Fail CI when public source contains known private-boundary artifacts."""

from __future__ import annotations

import ipaddress
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PATH_PARTS = {
    ".whoami",
    "AGENTS.md",
    "BUGS.md",
    "HANDOVER.md",
    "IMPORT.md",
    "MEMORY.md",
    "private-archives",
    "internal-audits",
    "tickets",
}
FORBIDDEN_PATH_FRAGMENTS = (
    "live-test",
    "live_workspace_report",
    "credential-export",
    "runtime-snapshot",
)
TEXT_RULES = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Cloudflare account or user token": re.compile(r"\bcf(?:at|ut)_[0-9A-Za-z_-]{20,}\b"),
    "private service path": re.compile(r"/(?:home/services|root/cloudflare-mcp)(?:/|\b)"),
}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf"}
IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
PUBLIC_SAFE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/32",
        "127.0.0.0/8",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)


def public_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if result.returncode == 0 and result.stdout:
        listed = [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]
        missing = [path.relative_to(ROOT).as_posix() for path in listed if not path.exists()]
        if missing:
            raise RuntimeError(
                "Git selected missing public paths; commit intended deletions before scanning: "
                + ", ".join(sorted(missing))
            )
        return [path for path in listed if path.is_file()]
    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and ".venv" not in path.parts
        and "__pycache__" not in path.parts
    ]


def main() -> None:
    files = public_files()
    violations: list[str] = []
    for path in files:
        relative = path.relative_to(ROOT)
        parts = set(relative.parts)
        rendered = relative.as_posix()
        if parts & FORBIDDEN_PATH_PARTS or any(
            fragment in rendered.lower() for fragment in FORBIDDEN_PATH_FRAGMENTS
        ):
            violations.append(f"forbidden public path: {rendered}")
            continue
        if path.is_symlink():
            violations.append(f"symbolic link in public source: {rendered}")
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            violations.append(f"unscannable non-text public file: {rendered}")
            continue
        except OSError:
            violations.append(f"unreadable public file: {rendered}")
            continue
        for label, pattern in TEXT_RULES.items():
            if pattern.search(text):
                violations.append(f"{label} in {rendered}")
        for candidate in IPV4_PATTERN.findall(text):
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not any(address in network for network in PUBLIC_SAFE_IPV4_NETWORKS):
                violations.append(f"non-documentation IPv4 address in {rendered}")
    if violations:
        raise SystemExit(
            "Public-source safety gate failed:\n- " + "\n- ".join(sorted(set(violations)))
        )
    print(f"public-source safety gate passed ({len(files)} files)")


if __name__ == "__main__":
    main()
