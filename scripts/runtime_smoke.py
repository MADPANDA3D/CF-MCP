#!/usr/bin/env python3
"""Provider-free container smoke for both authenticated access modes."""

from __future__ import annotations

import http.client
import json
import os
from importlib.metadata import version
from typing import Any

HOST = "127.0.0.1"
PORT = int(os.getenv("MCP_PORT", "8000"))
MODE = os.environ["MCP_MODE"]
EXPECTED_TOOL_COUNT = int(os.getenv("MCP_EXPECTED_TOOL_COUNT", "6"))
EXPECTED_BUILD_SHA = os.environ["MCP_BUILD_SHA"]
EXPECTED_SOURCE_FINGERPRINT = os.environ["MCP_SOURCE_FINGERPRINT"]
EXPECTED_IMAGE_REFERENCE = os.environ["MCP_IMAGE_REFERENCE"]
ACCESS_TOKEN = os.getenv("MCP_ACCESS_TOKEN", "")
PORTAL_GRANT = os.getenv("MCP_PORTAL_GRANT_TOKEN", "")
TENANT_ID_HEADER = os.getenv("MCP_TENANT_ID_HEADER", "x-madpanda-user-id")
PACKAGE_VERSION = version("madpanda-cloudflare-mcp")


def auth_headers(*, valid: bool = True) -> dict[str, str]:
    if MODE == "standalone":
        token = ACCESS_TOKEN if valid else "wrong-standalone-token-000000000000"
        return {"Authorization": f"Bearer {token}"}
    if MODE == "portal":
        token = PORTAL_GRANT if valid else "wrong-portal-grant-0000000000000000"
        return {
            "X-MADPANDA-PORTAL-GRANT": token,
            TENANT_ID_HEADER: "runtime-smoke-tenant",
        }
    raise AssertionError(f"unexpected MCP_MODE={MODE!r}")


def request(
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], Any]:
    body = (
        json.dumps(payload, separators=(",", ":")).encode()
        if isinstance(payload, dict)
        else payload
    )
    merged = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if headers:
        merged.update(headers)
    connection = http.client.HTTPConnection(HOST, PORT, timeout=8)
    try:
        connection.request(method, path, body=body, headers=merged)
        response = connection.getresponse()
        raw = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
    finally:
        connection.close()
    try:
        decoded: Any = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        decoded = raw.decode("utf-8", errors="replace")
    return response.status, response_headers, decoded


def rpc(method: str, request_id: int, params: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    status, _, health = request("GET", "/health", headers={"Accept": "application/json"})
    require(status == 200, f"health status={status}")
    require(isinstance(health, dict), "health is not JSON")
    require(health.get("status") == "healthy", f"health={health}")
    require(health.get("version") == PACKAGE_VERSION, f"version={health}")
    require(health.get("tool_count") == EXPECTED_TOOL_COUNT, f"tool_count={health}")
    require(health.get("raw_tool_count") == EXPECTED_TOOL_COUNT, f"raw_tool_count={health}")
    require(health.get("agent_ready_tool_count") == 5, f"agent_ready_tool_count={health}")
    require(health.get("build_sha") == EXPECTED_BUILD_SHA, f"build_sha={health}")
    require(
        health.get("source_fingerprint") == EXPECTED_SOURCE_FINGERPRINT,
        f"source_fingerprint={health}",
    )
    require(health.get("image_reference") == EXPECTED_IMAGE_REFERENCE, f"image_reference={health}")
    configuration = health.get("configuration", {})
    require(configuration.get("mode") == MODE, f"mode={health}")
    require(configuration.get("ready") is True, f"not ready: {health}")
    require(
        configuration.get("provider_credentials_mode") == "per_request_byok",
        f"BYOK mode missing: {health}",
    )

    status, _, denied = request("POST", "/mcp", payload=b"malformed-before-auth")
    require(status == 401, f"missing auth was not rejected first: {status} {denied}")
    require(denied.get("error", {}).get("code") == -32001, f"missing auth={denied}")

    status, _, denied = request(
        "POST", "/mcp", payload=b"malformed-before-auth", headers=auth_headers(valid=False)
    )
    require(status == 401, f"invalid auth was not rejected first: {status} {denied}")
    require(denied.get("error", {}).get("code") == -32001, f"invalid auth={denied}")

    origin_headers = auth_headers()
    origin_headers["Origin"] = "https://untrusted.invalid"
    status, _, denied = request(
        "POST", "/mcp", payload=rpc("tools/list", 2, {}), headers=origin_headers
    )
    require(status == 403, f"browser Origin was not rejected: {status} {denied}")
    require(denied.get("error") == "origin_not_allowed", f"origin rejection={denied}")

    status, response_headers, initialized = request(
        "POST",
        "/mcp",
        payload=rpc(
            "initialize",
            3,
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "cloudflare-mcp-image-smoke", "version": "1"},
            },
        ),
        headers=auth_headers(),
    )
    require(status == 200, f"initialize failed: {status} {initialized}")
    require(isinstance(initialized, dict) and "result" in initialized, f"initialize={initialized}")

    discovery_headers = auth_headers()
    session_id = response_headers.get("mcp-session-id")
    if session_id:
        discovery_headers["Mcp-Session-Id"] = session_id
    status, _, tools = request(
        "POST", "/mcp", payload=rpc("tools/list", 4, {}), headers=discovery_headers
    )
    require(status == 200, f"tools/list failed: {status} {tools}")
    listed = tools.get("result", {}).get("tools", []) if isinstance(tools, dict) else []
    require(len(listed) == EXPECTED_TOOL_COUNT, f"tools/list count={len(listed)}")
    names = {tool.get("name") for tool in listed if isinstance(tool, dict)}
    require("list_capabilities" in names, "standard navigation is missing")
    require("cloudflare_api_request" in names, "Cloudflare provider tool is missing")

    status, _, capability = request(
        "POST",
        "/mcp",
        payload=rpc(
            "tools/call",
            5,
            {"name": "list_capabilities", "arguments": {"include_descriptors": False}},
        ),
        headers=discovery_headers,
    )
    require(status == 200, f"local navigation failed: {status} {capability}")
    require(not capability.get("result", {}).get("isError", False), f"navigation={capability}")

    status, _, provider_denied = request(
        "POST",
        "/mcp",
        payload=rpc(
            "tools/call",
            6,
            {"name": "cloudflare_api_request", "arguments": {"method": "GET", "path": "/accounts"}},
        ),
        headers=discovery_headers,
    )
    rendered = json.dumps(provider_denied, ensure_ascii=True)
    require(status in {200, 401}, f"missing BYOK status={status} payload={provider_denied}")
    require("Missing Cloudflare API token" in rendered, f"missing BYOK error={provider_denied}")

    print(json.dumps({"ok": True, "mode": MODE, "tool_count": len(listed)}))


if __name__ == "__main__":
    main()
