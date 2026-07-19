"""FastMCP server for Cloudflare."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from typing import Annotated, Any, Literal

import uvicorn
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
from mcp.types import ToolAnnotations
from pydantic import Field
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cloudflare_mcp import __version__
from cloudflare_mcp.approval import APPROVAL_ATTESTATION_HEADER, fingerprint_secret
from cloudflare_mcp.cloudflare import call_cloudflare_api
from cloudflare_mcp.config import (
    CLOUDFLARE_ACCOUNT_HEADER,
    CLOUDFLARE_TOKEN_HEADER,
    CLOUDFLARE_ZONE_HEADER,
    PORTAL_GRANT_HEADER,
    CloudflareConfig,
    ProviderConfigurationError,
    RuntimeConfigurationError,
    RuntimeSettings,
    ServiceAuthError,
    configuration_status,
    normalize_headers,
    require_service_access,
    required_service_headers,
    resolve_cloudflare_config,
    runtime_settings,
    validate_runtime_settings,
)
from cloudflare_mcp.coverage import CoverageQueryResult, load_coverage, query_coverage
from cloudflare_mcp.tool_manifest import (
    TOOL_CATALOG_VERSION,
    build_tool_manifest,
    search_tools,
    tool_descriptor,
)

TOOL_NAMES = [
    "check_configuration",
    "list_capabilities",
    "get_endpoint_coverage",
    "get_tool_usage",
    "find_tools",
    "cloudflare_api_request",
]

_HOST_NAME_PATTERN = re.compile(r"^[a-z0-9._-]+$")

mcp = FastMCP(name="Cloudflare MCP")


def _cloudflare_token_verify_paths(config: CloudflareConfig) -> list[tuple[str, str]]:
    """Return token verification endpoints in preferred order."""

    account_id = getattr(config, "account_id", None)
    account_path = f"/accounts/{account_id}/tokens/verify" if account_id else ""
    user_path = "/user/tokens/verify"
    api_token = str(getattr(config, "api_token", "") or "")

    if account_path and api_token.startswith("cfat_"):
        return [(account_path, "account")]

    paths = [(user_path, "user")]
    if account_path:
        paths.append((account_path, "account"))
    return paths


async def _verify_cloudflare_token(config: CloudflareConfig) -> tuple[dict[str, Any], str]:
    """Verify user or account-owned Cloudflare tokens without exposing the secret."""

    last_verification: dict[str, Any] | None = None
    last_endpoint_type = "user"
    for path, endpoint_type in _cloudflare_token_verify_paths(config):
        verification = await call_cloudflare_api(
            config=config,
            method="GET",
            path=path,
            max_response_bytes=20_000,
        )
        last_verification = verification
        last_endpoint_type = endpoint_type
        if verification["ok"] or verification["status_code"] not in {401, 403}:
            return verification, endpoint_type

    if last_verification is None:
        raise ProviderConfigurationError("No Cloudflare token verification endpoint available.")
    return last_verification, last_endpoint_type


def _http_headers() -> Mapping[str, str]:
    """Read current HTTP headers when running over HTTP transport."""

    try:
        return dict(get_http_headers(include_all=True))
    except RuntimeError:
        return {}


def _require_access() -> Mapping[str, str]:
    """Recheck service authentication inside every direct tool invocation."""

    headers = _http_headers()
    require_service_access(headers)
    return headers


def _service_principal_fingerprint(headers: Mapping[str, str], settings: RuntimeSettings) -> str:
    """Bind approvals to the authenticated service and partition Portal tenant state."""

    normalized = normalize_headers(headers)
    if settings.mode == "portal":
        portal_grant = normalized.get("x-madpanda-portal-grant", "")
        tenant_id = normalized.get(settings.tenant_id_header, "")
        credential = json.dumps(
            [portal_grant, tenant_id],
            ensure_ascii=True,
            separators=(",", ":"),
        )
        namespace = "service-portal-principal-v1"
    else:
        authorization = normalized.get("authorization", "")
        _, _, credential = authorization.partition(" ")
        namespace = "service-standalone-v1"
    return fingerprint_secret(namespace, credential)


def _scope_headers(
    scope: Scope,
    *,
    tenant_id_header: str,
) -> tuple[dict[str, str], set[str]]:
    """Normalize headers and identify ambiguous duplicate security fields."""

    singleton_headers = {
        "authorization",
        "content-type",
        "content-length",
        "host",
        "mcp-protocol-version",
        "mcp-session-id",
        "origin",
        "transfer-encoding",
        PORTAL_GRANT_HEADER,
        tenant_id_header,
        CLOUDFLARE_TOKEN_HEADER,
        CLOUDFLARE_ACCOUNT_HEADER,
        CLOUDFLARE_ZONE_HEADER,
        APPROVAL_ATTESTATION_HEADER,
    }
    normalized: dict[str, str] = {}
    duplicates: set[str] = set()
    for raw_key, raw_value in scope.get("headers", []):
        key = raw_key.decode("latin-1").lower()
        if key in normalized and key in singleton_headers:
            duplicates.add(key)
        normalized[key] = raw_value.decode("latin-1")
    return normalized, duplicates


def _normalized_host(value: str) -> str:
    host = value.strip().lower()
    if not host or any(character.isspace() or ord(character) < 0x20 for character in host):
        raise ValueError("Request Host is invalid.")
    if host.startswith("["):
        closing = host.find("]")
        if closing < 2:
            raise ValueError("Request Host is invalid.")
        try:
            address = ipaddress.IPv6Address(host[1:closing])
        except ipaddress.AddressValueError as exc:
            raise ValueError("Request Host is invalid.") from exc
        suffix = host[closing + 1 :]
        if suffix and (not suffix.startswith(":") or not _valid_host_port(suffix[1:])):
            raise ValueError("Request Host is invalid.")
        return f"[{address.compressed}]"
    if "[" in host or "]" in host or host.count(":") > 1:
        raise ValueError("Request Host is invalid.")
    name, separator, port = host.partition(":")
    if separator and not _valid_host_port(port):
        raise ValueError("Request Host is invalid.")
    if not _HOST_NAME_PATTERN.fullmatch(name):
        raise ValueError("Request Host is invalid.")
    return name


def _valid_host_port(value: str) -> bool:
    return value.isascii() and value.isdigit() and 1 <= int(value) <= 65_535


def _validate_host_and_origin(headers: Mapping[str, str]) -> None:
    settings = runtime_settings()
    supplied_host = headers.get("host", "")
    if not supplied_host:
        raise ValueError("Missing required Host header.")
    normalized_host = _normalized_host(supplied_host)
    allowed_hosts = {_normalized_host(host) for host in settings.allowed_hosts}
    if normalized_host not in allowed_hosts:
        raise ValueError("Request Host is not trusted.")
    origin = headers.get("origin", "").strip()
    if origin and origin not in settings.allowed_origins:
        raise PermissionError("Request Origin is not allowed.")


async def _send_json(send: Send, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"cache-control", b"no-store"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def _send_jsonrpc_error(
    send: Send,
    *,
    status: int,
    code: int,
    message: str,
    request_id: str | int | None = None,
    data: dict[str, Any] | None = None,
) -> None:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    await _send_json(
        send,
        status,
        {"jsonrpc": "2.0", "id": request_id, "error": error},
    )


class ClientDisconnectedError(ConnectionError):
    """Raised when the client disconnects before its request body is complete."""


async def _read_request_body(receive: Receive, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        message_type = message.get("type")
        if message_type == "http.disconnect":
            raise ClientDisconnectedError("Client disconnected before request body completed.")
        if message_type != "http.request":
            continue
        chunk = message.get("body") or b""
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("Request body exceeds the configured byte limit.")
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


def _replay_receive(body: bytes) -> Receive:
    emitted = False

    async def _receive() -> dict[str, Any]:
        nonlocal emitted
        if not emitted:
            emitted = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    return _receive


def _request_id(body: bytes) -> str | int | None:
    try:
        payload = json.loads(body) if body else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    candidate = payload.get("id")
    return candidate if isinstance(candidate, (str, int)) else None


async def _run_with_bounded_response(
    app: ASGIApp,
    scope: Scope,
    receive: Receive,
    send: Send,
    *,
    max_bytes: int,
    request_id: str | int | None,
) -> None:
    """Buffer one stateless MCP response and reject it before crossing the wire if oversized."""

    response_start: Message | None = None
    chunks: list[bytes] = []
    total = 0
    overflow = False

    async def bounded_send(message: Message) -> None:
        nonlocal response_start, total, overflow
        if message.get("type") == "http.response.start":
            response_start = message
            return
        if message.get("type") != "http.response.body":
            return
        body = message.get("body") or b""
        total += len(body)
        if total > max_bytes:
            overflow = True
            chunks.clear()
        elif not overflow:
            chunks.append(body)

    await app(scope, receive, bounded_send)
    if overflow:
        await _send_jsonrpc_error(
            send,
            status=500,
            code=-32004,
            message="MCP response exceeds the configured byte limit.",
            request_id=request_id,
        )
        return
    if response_start is None:
        await _send_jsonrpc_error(
            send,
            status=500,
            code=-32603,
            message="MCP application returned no response.",
            request_id=request_id,
        )
        return
    response_body = b"".join(chunks)
    headers = [
        (key, value)
        for key, value in response_start.get("headers", [])
        if key.lower() != b"content-length"
    ]
    headers.append((b"content-length", str(len(response_body)).encode("ascii")))
    await send({**response_start, "headers": headers})
    await send({"type": "http.response.body", "body": response_body})


class SecureMCPASGI:
    """Authenticate MCP requests before body reads and enforce HTTP size/origin policy."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        try:
            settings = runtime_settings()
        except RuntimeConfigurationError as exc:
            await _send_json(
                send, 503, {"ok": False, "error": "configuration_error", "message": str(exc)}
            )
            return
        headers, duplicate_security_headers = _scope_headers(
            scope,
            tenant_id_header=settings.tenant_id_header,
        )
        if duplicate_security_headers:
            await _send_json(
                send,
                400,
                {
                    "ok": False,
                    "error": "duplicate_security_header",
                    "message": "Duplicate HTTP security headers are not allowed.",
                },
            )
            return
        try:
            _validate_host_and_origin(headers)
        except PermissionError as exc:
            await _send_json(
                send, 403, {"ok": False, "error": "origin_not_allowed", "message": str(exc)}
            )
            return
        except ValueError as exc:
            await _send_json(send, 400, {"ok": False, "error": "invalid_host", "message": str(exc)})
            return

        path = str(scope.get("path", ""))
        if path == "/mcp/":
            await _send_json(
                send,
                410,
                {"error": "deprecated_endpoint", "message": "Use /mcp without a trailing slash."},
            )
            return
        if path != "/mcp":
            await self.app(scope, receive, send)
            return

        try:
            require_service_access(headers, settings)
        except ServiceAuthError as exc:
            await _send_jsonrpc_error(
                send,
                status=401,
                code=-32001,
                message=str(exc),
                data={"required_headers": required_service_headers(settings)},
            )
            return

        method = str(scope.get("method", "")).upper()
        body = b""
        consumed = False
        if method in {"POST", "PUT", "PATCH"}:
            declared = headers.get("content-length", "")
            if declared:
                try:
                    if int(declared) > settings.request_body_max_bytes:
                        raise ValueError
                except ValueError:
                    await _send_jsonrpc_error(
                        send,
                        status=413,
                        code=-32003,
                        message="Request body exceeds the configured byte limit.",
                    )
                    return
            try:
                body = await _read_request_body(receive, settings.request_body_max_bytes)
            except ClientDisconnectedError:
                return
            except ValueError as exc:
                await _send_jsonrpc_error(send, status=413, code=-32003, message=str(exc))
                return
            consumed = True
        if method == "POST" and "application/json" not in headers.get("content-type", "").lower():
            await _send_jsonrpc_error(
                send,
                status=400,
                code=-32600,
                message="Content-Type must include application/json.",
                request_id=_request_id(body),
            )
            return

        await _run_with_bounded_response(
            self.app,
            scope,
            _replay_receive(body) if consumed else receive,
            send,
            max_bytes=settings.mcp_response_max_bytes,
            request_id=_request_id(body),
        )


def health_payload() -> dict[str, Any]:
    """Return a secret-safe health payload."""

    coverage = load_coverage()
    settings = runtime_settings(validate=False)
    status = configuration_status(settings=settings)
    manifest = build_tool_manifest()
    try:
        validate_runtime_settings(settings)
        configuration_ready = True
    except RuntimeConfigurationError:
        configuration_ready = False
    return {
        "status": "healthy" if configuration_ready else "degraded",
        "service": "cloudflare-mcp",
        "version": __version__,
        "build_sha": manifest["buildSha"],
        "source_fingerprint": settings.source_fingerprint,
        "image_reference": settings.image_reference,
        "catalog_version": TOOL_CATALOG_VERSION,
        "descriptor_hash": manifest["descriptorHash"],
        "transport": "streamable_http",
        "mcp_path": "/mcp",
        "tool_count": len(TOOL_NAMES),
        "raw_tool_count": manifest["counts"]["raw"],
        "exposed_tool_count": len(TOOL_NAMES),
        "agent_ready_tool_count": manifest["counts"]["agentReady"],
        "legacy_tool_count": manifest["counts"]["legacy"],
        "hidden_tool_count": manifest["counts"]["hidden"],
        "configuration_ready": configuration_ready,
        "tools": TOOL_NAMES,
        "endpoint_operation_count": coverage["operation_count"],
        "endpoint_callable_count": coverage.get("coverage_status_counts", {}).get("callable"),
        "endpoint_catalog_only_count": coverage.get("coverage_status_counts", {}).get(
            "catalog_only"
        ),
        "setup_status": status["setup_status"],
        "configuration": status,
    }


@mcp.custom_route("/health", methods=["GET"])
async def health_check(_: Request) -> JSONResponse:
    """Unauthenticated operational health check for routing and container smoke tests."""

    return JSONResponse(health_payload())


@mcp.tool(
    description=tool_descriptor("check_configuration")["description"],
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def check_configuration(
    verify_cloudflare_token: Annotated[
        bool,
        Field(
            description=(
                "When true, calls the Cloudflare user-token or account-token verify "
                "endpoint with the resolved API token. When false, only validates "
                "local/broker setup."
            ),
        ),
    ] = False,
) -> dict[str, Any]:
    """Use this when an agent needs to validate broker/provider setup without exposing secrets."""

    headers = _require_access()
    status = configuration_status(headers)
    status["service_access_valid"] = True

    if not verify_cloudflare_token:
        return status

    try:
        config = resolve_cloudflare_config(headers, require_token=True)
    except ProviderConfigurationError as exc:
        status["cloudflare_token_verification"] = {
            "checked": False,
            "ok": False,
            "message": str(exc),
        }
        return status

    verification, endpoint_type = await _verify_cloudflare_token(config)
    status["cloudflare_token_verification"] = {
        "checked": True,
        "ok": verification["ok"],
        "endpoint_type": endpoint_type,
        "status_code": verification["status_code"],
        "cloudflare_success": verification["cloudflare_success"],
        "response": verification["response"],
    }
    return status


@mcp.tool(
    description=tool_descriptor("list_capabilities")["description"],
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def list_capabilities(
    include_descriptors: Annotated[
        bool,
        Field(
            description=(
                "Return every lossless ToolManifest descriptor when true; omit the descriptor "
                "array from the compact summary when false."
            )
        ),
    ] = False,
) -> dict[str, Any]:
    """Use this when an agent needs the Cloudflare MCP capability map and safety model."""

    _require_access()
    manifest = build_tool_manifest()
    manifest["tools"] = manifest["tools"] if include_descriptors else []
    manifest["commonWorkflows"] = [
        "Validate secret-safe setup with check_configuration.",
        "Search the default agent-ready catalog with find_tools.",
        "Read a lossless descriptor with get_tool_usage.",
        "Inspect official operations with get_endpoint_coverage.",
        (
            "Use cloudflare_api_request only through the advanced legacy path after risk-specific "
            "review and, for ordinary mutations, external one-use approval."
        ),
    ]
    return manifest


@mcp.tool(
    description=tool_descriptor("get_endpoint_coverage")["description"],
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def get_endpoint_coverage(
    feature_area: Annotated[
        str | None,
        Field(description="Optional case-insensitive Cloudflare feature/tag filter."),
    ] = None,
    method: Annotated[
        Literal["GET", "POST", "PUT", "PATCH", "DELETE"] | None,
        Field(description="Optional HTTP method filter."),
    ] = None,
    path_contains: Annotated[
        str | None,
        Field(description="Optional case-insensitive substring to match endpoint paths."),
    ] = None,
    classification: Annotated[
        Literal["read", "write", "destructive"] | None,
        Field(description="Optional mutability/risk classification filter."),
    ] = None,
    limit: Annotated[
        int,
        Field(description="Maximum operations to return, capped at 200.", ge=1, le=200),
    ] = 50,
    offset: Annotated[
        int,
        Field(description="Pagination offset into the filtered coverage matrix.", ge=0),
    ] = 0,
) -> CoverageQueryResult:
    """Use this to inspect official Cloudflare endpoint coverage before selecting a request."""

    _require_access()
    return query_coverage(
        feature_area=feature_area,
        method=method,
        path_contains=path_contains,
        classification=classification,
        limit=limit,
        offset=offset,
    )


@mcp.tool(
    description=tool_descriptor("get_tool_usage")["description"],
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def get_tool_usage(
    tool_name: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Native name, cloudflare-prefixed canonical name, or exact alias of the tool "
                "to explain."
            ),
        ),
    ],
) -> dict[str, Any]:
    """Use this when an agent needs exact parameter, side-effect, and follow-up guidance."""

    _require_access()
    try:
        descriptor = tool_descriptor(tool_name)
    except KeyError as exc:
        raise ValueError(str(exc)) from exc

    usage: dict[str, dict[str, Any]] = {
        "check_configuration": {
            "use_when": ("Validate service access and optional Cloudflare token validity."),
            "side_effects": (
                "None. Optional token verification performs a read-only Cloudflare call."
            ),
            "required_setup": "Valid service access for the selected startup mode.",
            "follow_up": "Call list_capabilities or get_endpoint_coverage after setup is valid.",
        },
        "list_capabilities": {
            "use_when": "Discover available Cloudflare MCP tools, safety gates, and workflows.",
            "side_effects": "None.",
            "required_setup": "Valid service access for the selected startup mode.",
            "follow_up": "Call get_endpoint_coverage to locate a Cloudflare endpoint.",
        },
        "get_endpoint_coverage": {
            "use_when": (
                "Search official Cloudflare OpenAPI operations by feature, method, or path."
            ),
            "side_effects": "None.",
            "required_setup": "Valid service access for the selected startup mode.",
            "follow_up": "Call cloudflare_api_request with a covered method/path.",
        },
        "get_tool_usage": {
            "use_when": "Resolve one complete Cloudflare tool descriptor and usage reference.",
            "side_effects": "None.",
            "required_setup": "Valid service access for the selected startup mode.",
            "follow_up": "Use the descriptor schema to validate a later call or preview.",
        },
        "find_tools": {
            "use_when": "Rank Cloudflare tools from multi-token natural-language or alias search.",
            "side_effects": "None.",
            "required_setup": "Valid service access for the selected startup mode.",
            "follow_up": "Call get_tool_usage for the complete selected descriptor.",
        },
        "cloudflare_api_request": {
            "use_when": "Execute a documented Cloudflare REST API operation.",
            "side_effects": (
                "Reviewed reads execute directly. Ordinary mutations require an externally "
                "signed one-use approval. High-risk operations are permanently blocked."
            ),
            "required_setup": (
                "Valid service access and a request-scoped x-cloudflare-api-token header. "
                "Mutation approval additionally requires a separately controlled signing key."
            ),
            "follow_up": "Use response IDs/URLs for the next Cloudflare API request as needed.",
            "safety_gates": {
                "write": "externally signed, expiring, principal-bound one-use attestation",
                "destructive": "same attestation gate, consumed before the provider attempt",
                "high_risk": "permanently blocked from the generic dispatcher",
            },
        },
    }
    native_name = str(descriptor["nativeToolName"])
    return {"tool_name": native_name, "descriptor": descriptor, **usage[native_name]}


@mcp.tool(
    description=tool_descriptor("find_tools")["description"],
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def find_tools(
    query: Annotated[
        str,
        Field(
            min_length=1,
            description="Natural-language, category, alias, or tool-name search text.",
        ),
    ],
    categories: Annotated[
        list[str] | None,
        Field(description="Optional exact Cloudflare tool category filters."),
    ] = None,
    include_legacy: Annotated[
        bool,
        Field(description="Include advanced legacy tools when true."),
    ] = False,
    limit: Annotated[
        int,
        Field(description="Maximum ranked matches to return, from 1 through 25.", ge=1, le=25),
    ] = 8,
) -> dict[str, Any]:
    """Search provider-owned Cloudflare descriptors without contacting Cloudflare."""

    _require_access()
    return search_tools(
        query,
        categories=categories,
        include_legacy=include_legacy,
        limit=limit,
    )


@mcp.tool(
    description=tool_descriptor("cloudflare_api_request")["description"],
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
async def cloudflare_api_request(
    method: Annotated[
        Literal["GET", "POST", "PUT", "PATCH", "DELETE"],
        Field(description="Cloudflare REST method to execute."),
    ],
    path: Annotated[
        str,
        Field(
            min_length=1,
            description=(
                "Cloudflare API path, for example /zones or "
                "/zones/{zone_id}/dns_records with real IDs substituted. Full "
                "https://api.cloudflare.com/client/v4 URLs are also accepted."
            ),
        ),
    ],
    query: Annotated[
        dict[str, Any] | None,
        Field(description="Optional query parameters to send to Cloudflare."),
    ] = None,
    body: Annotated[
        dict[str, Any] | list[Any] | None,
        Field(description="Optional JSON body for POST, PUT, or PATCH requests."),
    ] = None,
    content_type: Annotated[
        Literal[
            "application/json",
            "application/merge-patch+json",
            "application/scim+json",
        ]
        | None,
        Field(
            description=(
                "Optional JSON media type. It must be advertised by the pinned operation; "
                "application/json is selected automatically when available."
            )
        ),
    ] = None,
    timeout_seconds: Annotated[
        float,
        Field(description="Cloudflare request timeout in seconds.", ge=1, le=120),
    ] = 30.0,
    max_response_bytes: Annotated[
        int,
        Field(
            description="Maximum redacted response payload bytes returned to the agent.",
            ge=4096,
            le=245_760,
        ),
    ] = 100_000,
) -> dict[str, Any]:
    """Preview or execute a pinned-schema JSON Cloudflare REST operation."""

    headers = _require_access()
    settings = runtime_settings()
    config = resolve_cloudflare_config(headers, require_token=False)
    return await call_cloudflare_api(
        config=config,
        method=method,
        path=path,
        query=query,
        body=body,
        content_type=content_type,
        approval_attestation=normalize_headers(headers).get(APPROVAL_ATTESTATION_HEADER, ""),
        approval_signing_key=settings.approval_signing_key,
        principal_fingerprint=_service_principal_fingerprint(headers, settings),
        timeout_seconds=timeout_seconds,
        max_response_bytes=min(max_response_bytes, settings.provider_response_max_bytes),
    )


def build_app() -> SecureMCPASGI:
    """Build the stateless, JSON-response ASGI application."""

    runtime_settings()
    app = mcp.http_app(
        path="/mcp",
        transport="streamable-http",
        json_response=True,
        stateless_http=True,
    )
    return SecureMCPASGI(app)


def main() -> None:
    """Run the Cloudflare MCP HTTP server."""

    settings = runtime_settings()
    uvicorn.run(
        build_app(),
        host=settings.host,
        port=settings.port,
        access_log=False,
    )


if __name__ == "__main__":
    main()
