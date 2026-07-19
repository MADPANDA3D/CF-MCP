from __future__ import annotations

import json
from typing import Any

import pytest
from starlette.testclient import TestClient
from starlette.types import Message

from cloudflare_mcp.config import runtime_settings
from cloudflare_mcp.server import (
    TOOL_NAMES,
    SecureMCPASGI,
    _normalized_host,
    _service_principal_fingerprint,
    build_app,
    health_payload,
    list_capabilities,
)

ACCESS_TOKEN = "standalone-access-token-000000000000000000000000"
PORTAL_TOKEN = "portal-grant-token-000000000000000000000000000"
PORTAL_TENANT = "tenant_01:project-a"


def configure_runtime(monkeypatch: pytest.MonkeyPatch, mode: str = "standalone") -> None:
    monkeypatch.setenv("MCP_MODE", mode)
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver,cloudflare-mcp")
    monkeypatch.setenv("MCP_ALLOWED_ORIGINS", "")
    monkeypatch.setenv("MCP_BUILD_SHA", "development")
    monkeypatch.setenv("MCP_SOURCE_FINGERPRINT", "development")
    monkeypatch.setenv("MCP_IMAGE_REFERENCE", "development")
    monkeypatch.setenv("MCP_REQUEST_BODY_MAX_BYTES", "131072")
    monkeypatch.setenv("MCP_RESPONSE_BODY_MAX_BYTES", "1048576")
    monkeypatch.setenv("MCP_PROVIDER_RESPONSE_MAX_BYTES", "65536")
    monkeypatch.setenv("MCP_APPROVAL_SIGNING_KEY", "approval-signing-key-000000000000000000000000")
    monkeypatch.setenv("MCP_TENANT_ID_HEADER", "x-madpanda-user-id")
    if mode == "standalone":
        monkeypatch.setenv("MCP_ACCESS_TOKEN", ACCESS_TOKEN)
        monkeypatch.delenv("MCP_PORTAL_GRANT_TOKEN", raising=False)
    else:
        monkeypatch.setenv("MCP_PORTAL_GRANT_TOKEN", PORTAL_TOKEN)
        monkeypatch.delenv("MCP_ACCESS_TOKEN", raising=False)


def service_headers(mode: str = "standalone", *, valid: bool = True) -> dict[str, str]:
    if mode == "standalone":
        token = ACCESS_TOKEN if valid else "wrong-standalone-token"
        return {"Authorization": f"Bearer {token}"}
    token = PORTAL_TOKEN if valid else "wrong-portal-token"
    return {
        "X-MADPANDA-PORTAL-GRANT": token,
        "X-MADPANDA-USER-ID": PORTAL_TENANT,
    }


def test_health_payload_reports_dual_mode_product_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_runtime(monkeypatch, "standalone")
    payload = health_payload()

    assert payload["status"] == "healthy"
    assert payload["version"] == "1.0.0"
    assert payload["tool_count"] == len(TOOL_NAMES) == 6
    assert payload["raw_tool_count"] == 6
    assert payload["agent_ready_tool_count"] == 5
    assert payload["legacy_tool_count"] == 1
    assert payload["catalog_version"] == "2026.07.19.3"
    assert payload["endpoint_operation_count"] == 3148
    assert payload["endpoint_callable_count"] == 2356
    assert payload["endpoint_catalog_only_count"] == 792
    assert payload["configuration"]["mode"] == "standalone"
    assert payload["configuration"]["ready"] is True
    assert payload["configuration"]["provider_credentials_mode"] == "per_request_byok"
    assert payload["configuration"]["high_risk_operation_policy"] == "permanently_blocked"
    assert payload["configuration"]["limits"]["provider_response_max_bytes"] == 65536


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["standalone", "portal"])
@pytest.mark.parametrize("valid", [False, True])
async def test_authentication_runs_before_any_request_body_read(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    valid: bool,
) -> None:
    configure_runtime(monkeypatch, mode)
    app_called = False
    body_read = False
    messages: list[Message] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        nonlocal app_called
        app_called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    async def receive() -> dict[str, Any]:
        nonlocal body_read
        body_read = True
        return {"type": "http.request", "body": b"{not-json", "more_body": False}

    async def send(message: Message) -> None:
        messages.append(message)

    auth = service_headers(mode, valid=valid) if valid else {}
    encoded_headers = [(b"host", b"testserver"), (b"content-type", b"application/json")]
    encoded_headers.extend(
        (key.lower().encode("ascii"), value.encode("ascii")) for key, value in auth.items()
    )
    await SecureMCPASGI(app)(
        {
            "type": "http",
            "path": "/mcp",
            "method": "POST",
            "headers": encoded_headers,
        },
        receive,
        send,
    )

    if valid:
        assert app_called is True
        assert body_read is True
    else:
        assert app_called is False
        assert body_read is False
        assert messages[0]["status"] == 401
        payload = json.loads(messages[1]["body"])
        assert payload["error"]["code"] == -32001
        assert ACCESS_TOKEN not in str(payload)
        assert PORTAL_TOKEN not in str(payload)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "duplicate_name", "duplicate_value"),
    [
        ("standalone", b"authorization", f"Bearer {ACCESS_TOKEN}".encode()),
        ("portal", b"x-madpanda-user-id", PORTAL_TENANT.encode()),
        ("standalone", b"content-type", b"application/json"),
        ("standalone", b"mcp-session-id", b"duplicate-session"),
        ("standalone", b"mcp-protocol-version", b"2025-06-18"),
    ],
)
async def test_duplicate_security_headers_fail_before_body_read(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    duplicate_name: bytes,
    duplicate_value: bytes,
) -> None:
    configure_runtime(monkeypatch, mode)
    app_called = False
    body_read = False
    messages: list[Message] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        nonlocal app_called
        app_called = True

    async def receive() -> dict[str, Any]:
        nonlocal body_read
        body_read = True
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message: Message) -> None:
        messages.append(message)

    encoded_headers = [(b"host", b"testserver"), (b"content-type", b"application/json")]
    encoded_headers.extend(
        (key.lower().encode("ascii"), value.encode("ascii"))
        for key, value in service_headers(mode).items()
    )
    if duplicate_name not in {key for key, _ in encoded_headers}:
        encoded_headers.append((duplicate_name, b"first-value"))
    encoded_headers.append((duplicate_name, duplicate_value))
    await SecureMCPASGI(app)(
        {"type": "http", "path": "/mcp", "method": "POST", "headers": encoded_headers},
        receive,
        send,
    )

    assert app_called is False
    assert body_read is False
    assert messages[0]["status"] == 400
    assert json.loads(messages[1]["body"])["error"] == "duplicate_security_header"


def test_browser_origin_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_runtime(monkeypatch)
    with TestClient(build_app()) as client:
        response = client.post(
            "/mcp",
            headers={
                **service_headers(),
                "Origin": "https://untrusted.invalid",
                "Content-Type": "application/json",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}},
        )

    assert response.status_code == 403
    assert response.json()["error"] == "origin_not_allowed"


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [
        ("testserver", "testserver"),
        ("testserver:8000", "testserver"),
        ("[::1]", "[::1]"),
        ("[0:0:0:0:0:0:0:1]:8000", "[::1]"),
    ],
)
def test_host_normalization_accepts_only_valid_host_and_numeric_port(
    supplied: str,
    expected: str,
) -> None:
    assert _normalized_host(supplied) == expected


@pytest.mark.parametrize(
    "supplied",
    [
        "[::1].evil",
        "[::1]:invalid",
        "[::1]:70000",
        "[::1",
        "::1",
        "testserver:invalid",
        "testserver:70000",
    ],
)
def test_host_normalization_rejects_malformed_suffixes(supplied: str) -> None:
    with pytest.raises(ValueError, match="Host is invalid"):
        _normalized_host(supplied)


def test_malformed_ipv6_host_is_rejected_before_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_runtime(monkeypatch)
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", "[::1]")
    with TestClient(build_app()) as client:
        response = client.post(
            "/mcp",
            headers={"Host": "[::1].evil", "Content-Type": "application/json"},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}},
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_host"


@pytest.mark.parametrize("mode", ["standalone", "portal"])
def test_live_protocol_navigation_is_provider_free_and_dispatcher_needs_byok(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    configure_runtime(monkeypatch, mode)
    headers = {
        **service_headers(mode),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    with TestClient(build_app()) as client:
        tools = client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        navigation = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "list_capabilities",
                    "arguments": {"include_descriptors": False},
                },
            },
        )
        provider = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "cloudflare_api_request",
                    "arguments": {"method": "GET", "path": "/zones"},
                },
            },
        )

    assert tools.status_code == 200
    listed = tools.json()["result"]["tools"]
    assert len(listed) == 6
    assert {tool["name"] for tool in listed} == set(TOOL_NAMES)
    assert navigation.status_code == 200
    assert navigation.json()["result"]["isError"] is False
    assert provider.status_code == 200
    assert provider.json()["result"]["isError"] is True
    assert "x-cloudflare-api-token" in provider.text


@pytest.mark.asyncio
async def test_direct_navigation_rechecks_selected_mode_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_runtime(monkeypatch, "portal")
    monkeypatch.setattr(
        "cloudflare_mcp.server._http_headers",
        lambda: {
            "x-madpanda-portal-grant": PORTAL_TOKEN,
            "x-madpanda-user-id": PORTAL_TENANT,
        },
    )

    result = await list_capabilities(include_descriptors=True)

    assert result["counts"] == {"raw": 6, "agentReady": 5, "legacy": 1, "hidden": 0}
    assert len(result["tools"]) == 6
    assert PORTAL_TOKEN not in json.dumps(result)


def test_portal_approval_principal_is_partitioned_by_tenant_and_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_runtime(monkeypatch, "portal")
    settings = runtime_settings()
    tenant_a = _service_principal_fingerprint(
        {
            "x-madpanda-portal-grant": PORTAL_TOKEN,
            "x-madpanda-user-id": "tenant-a",
        },
        settings,
    )
    tenant_b = _service_principal_fingerprint(
        {
            "x-madpanda-portal-grant": PORTAL_TOKEN,
            "x-madpanda-user-id": "tenant-b",
        },
        settings,
    )
    other_grant = _service_principal_fingerprint(
        {
            "x-madpanda-portal-grant": "other-portal-grant-000000000000000000000000000",
            "x-madpanda-user-id": "tenant-a",
        },
        settings,
    )

    assert len({tenant_a, tenant_b, other_grant}) == 3
    assert PORTAL_TOKEN not in tenant_a
    assert "tenant-a" not in tenant_a


@pytest.mark.asyncio
async def test_full_mcp_response_limit_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_runtime(monkeypatch)
    monkeypatch.setenv("MCP_RESPONSE_BODY_MAX_BYTES", "65536")
    monkeypatch.setenv("MCP_PROVIDER_RESPONSE_MAX_BYTES", "4096")

    async def large_app(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"x" * 65537})

    messages: list[Message] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message: Message) -> None:
        messages.append(message)

    headers = [(b"host", b"testserver"), (b"authorization", f"Bearer {ACCESS_TOKEN}".encode())]
    await SecureMCPASGI(large_app)(
        {"type": "http", "path": "/mcp", "method": "GET", "headers": headers},
        receive,
        send,
    )

    assert messages[0]["status"] == 500
    assert json.loads(messages[1]["body"])["error"]["code"] == -32004


@pytest.mark.asyncio
async def test_authenticated_disconnect_stops_body_reader_without_spinning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_runtime(monkeypatch)
    app_called = False
    receive_calls = 0
    messages: list[Message] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        nonlocal app_called
        app_called = True

    async def receive() -> dict[str, Any]:
        nonlocal receive_calls
        receive_calls += 1
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        messages.append(message)

    headers = [
        (b"host", b"testserver"),
        (b"content-type", b"application/json"),
        (b"authorization", f"Bearer {ACCESS_TOKEN}".encode()),
    ]
    await SecureMCPASGI(app)(
        {"type": "http", "path": "/mcp", "method": "POST", "headers": headers},
        receive,
        send,
    )

    assert receive_calls == 1
    assert app_called is False
    assert messages == []
