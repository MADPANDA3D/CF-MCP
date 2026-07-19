#!/usr/bin/env python3
"""Create a private runtime environment without printing generated secrets."""

from __future__ import annotations

import argparse
import os
import secrets
from pathlib import Path


def build_environment(mode: str) -> str:
    access_token = secrets.token_urlsafe(48) if mode == "standalone" else ""
    portal_grant = secrets.token_urlsafe(48) if mode == "portal" else ""
    approval_key = secrets.token_urlsafe(48)
    return "\n".join(
        (
            f"MCP_MODE={mode}",
            f"MCP_ACCESS_TOKEN={access_token}",
            f"MCP_PORTAL_GRANT_TOKEN={portal_grant}",
            "MCP_TENANT_ID_HEADER=x-madpanda-user-id",
            f"MCP_APPROVAL_SIGNING_KEY={approval_key}",
            "MCP_HOST_PORT=8000",
            "MCP_ALLOWED_HOSTS=localhost,127.0.0.1,[::1],cloudflare-mcp",
            "MCP_ALLOWED_ORIGINS=",
            "MCP_REQUEST_BODY_MAX_BYTES=131072",
            "MCP_RESPONSE_BODY_MAX_BYTES=1048576",
            "MCP_PROVIDER_RESPONSE_MAX_BYTES=65536",
            "MCP_BUILD_SHA=development",
            "MCP_SOURCE_FINGERPRINT=development",
            "MCP_IMAGE_REFERENCE=development",
            "",
        )
    )


def create_environment(env_path: Path, mode: str) -> bool:
    """Atomically create one private environment; return false without overwriting."""

    try:
        descriptor = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(build_environment(mode))
        env_path.chmod(0o600)
    except BaseException:
        env_path.unlink(missing_ok=True)
        raise
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create an ignored mode-0600 .env with fresh service and approval secrets."
    )
    parser.add_argument("--mode", choices=("standalone", "portal"), default="standalone")
    args = parser.parse_args()
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not create_environment(env_path, args.mode):
        print("Runtime environment already exists; no values changed.")
        return
    print(
        f"Created ignored mode-0600 {args.mode} environment with fresh service and approval "
        "secrets; no value was printed."
    )


if __name__ == "__main__":
    main()
