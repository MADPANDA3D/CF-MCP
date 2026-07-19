"""Guarded Cloudflare API request utilities for the advanced MCP tool."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

import httpx

from cloudflare_mcp import __version__
from cloudflare_mcp.approval import (
    ApprovalError,
    ApprovalLedger,
    approval_ledger,
    fingerprint_secret,
)
from cloudflare_mcp.config import (
    DEFAULT_CLOUDFLARE_API_BASE_URL,
    MAX_PROVIDER_RESPONSE_BYTES,
    CloudflareConfig,
    ProviderConfigurationError,
)
from cloudflare_mcp.coverage import CoverageOperation, find_operation

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
JSON_REQUEST_MEDIA_TYPES = {
    "application/json",
    "application/merge-patch+json",
    "application/scim+json",
}
SECRET_KEY_PARTS = (
    "authorization",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "passphrase",
    "privkey",
    "streamkey",
    "stream_key",
    "cep_jwt",
    "private_credential",
    "key_base64",
    "key_jwk",
    "custom_key",
    "license_key",
    "md5_key",
    "pairing_key",
    "card_number",
    "payment_nonce",
    "validation_code",
    "invoice_pdf",
    "signed_url",
    "upload_url",
    "download_url",
    "ws_url",
    "web_socket_debugger_url",
    "devtools_frontend_url",
    "disable_for_time",
)
SECRET_CONTAINER_NAMES = frozenset(
    {
        "add_headers",
        "custom_headers",
        "extra_headers",
        "header",
        "headers",
    }
)
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_TOKENISH_PATTERN = re.compile(
    r"(?i)\b(?:api[_ -]?token|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|"
    r"license[_ -]?key|md5[_ -]?key|pairing[_ -]?key|card[_ -]?number|payment[_ -]?nonce|"
    r"validation[_ -]?code|invoice[_ -]?pdf|signed[_ -]?url|upload[_ -]?url|"
    r"download[_ -]?url|ws[_ -]?url|web[_ -]?socket[_ -]?debugger[_ -]?url|"
    r"devtools[_ -]?frontend[_ -]?url)"
    r"\s*[:=]\s*[^\s,;]+"
)
_NON_ALPHANUMERIC_KEY_RE = re.compile(r"[^a-z0-9]+")
_COMPACT_SECRET_KEY_PARTS = tuple(
    _NON_ALPHANUMERIC_KEY_RE.sub("", part.casefold()) for part in SECRET_KEY_PARTS
)
_COMPACT_SECRET_CONTAINER_NAMES = frozenset(
    _NON_ALPHANUMERIC_KEY_RE.sub("", name.casefold()) for name in SECRET_CONTAINER_NAMES
)
_PERCENT_ESCAPE_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
_UNRESERVED_PATH_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


class CloudflareRequestError(RuntimeError):
    """Raised when a Cloudflare operation is outside the reviewed contract."""


def normalize_cloudflare_path(path: str) -> str:
    """Normalize a Cloudflare path and reject alternate origins or ambiguous URLs."""

    candidate = path.strip()
    if not candidate:
        raise CloudflareRequestError("Cloudflare API path is required.")

    if candidate.startswith("http://") or candidate.startswith("https://"):
        parsed = urlparse(candidate)
        allowed_base = urlparse(DEFAULT_CLOUDFLARE_API_BASE_URL)
        if (
            parsed.scheme != "https"
            or parsed.hostname != allowed_base.hostname
            or parsed.port is not None
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise CloudflareRequestError(
                "Only https://api.cloudflare.com/client/v4 URLs are allowed."
            )
        if parsed.query or parsed.fragment:
            raise CloudflareRequestError(
                "Put query parameters in the query argument, not in the path URL."
            )
        candidate = parsed.path
        prefix = "/client/v4"
        if candidate == prefix:
            candidate = "/"
        elif candidate.startswith(f"{prefix}/"):
            candidate = candidate[len(prefix) :]
        else:
            raise CloudflareRequestError("Cloudflare URLs must use the /client/v4 API prefix.")
    elif "?" in candidate or "#" in candidate:
        raise CloudflareRequestError(
            "Put query parameters in the query argument; fragments are not allowed."
        )

    if any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in candidate
    ):
        raise CloudflareRequestError("Whitespace and control characters are not allowed in paths.")
    if "\\" in candidate:
        raise CloudflareRequestError("Backslashes are not allowed in Cloudflare API paths.")
    if "{" in candidate or "}" in candidate:
        raise CloudflareRequestError("Replace every OpenAPI path placeholder with a real ID.")

    def decode_unreserved_escape(match: re.Match[str]) -> str:
        value = int(match.group(0)[1:], 16)
        if value not in _UNRESERVED_PATH_BYTES:
            raise CloudflareRequestError(
                "Percent-encoded path delimiters and non-ASCII bytes are not allowed."
            )
        return chr(value)

    candidate = _PERCENT_ESCAPE_PATTERN.sub(decode_unreserved_escape, candidate)
    if "%" in candidate:
        raise CloudflareRequestError("Path contains an invalid percent escape.")
    if not candidate.startswith("/"):
        candidate = f"/{candidate}"
    if any(segment in {".", ".."} for segment in candidate.split("/")):
        raise CloudflareRequestError("Path traversal segments are not allowed.")
    if "//" in candidate:
        raise CloudflareRequestError("Empty path segments are not allowed.")
    return candidate


def canonical_request_sha256(
    *,
    method: str,
    path: str,
    query: dict[str, Any] | None,
    body: dict[str, Any] | list[Any] | None,
    content_type: str | None,
) -> str:
    """Bind an approval to the exact provider request without storing its body."""

    canonical = json.dumps(
        {
            "body": body,
            "content_type": content_type,
            "method": method.upper(),
            "path": normalize_cloudflare_path(path),
            "query": query,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _operation_request_media_types(operation: Mapping[str, Any]) -> tuple[str, ...]:
    values = operation.get("request_content_types", [])
    return tuple(str(value).lower() for value in values if str(value))


def validate_operation_contract(
    *,
    method: str,
    path: str,
    body: dict[str, Any] | list[Any] | None,
    content_type: str | None,
) -> tuple[CoverageOperation, str | None]:
    """Require a checked-in schema match and a JSON-compatible transport."""

    normalized_method = method.upper()
    if normalized_method not in ALLOWED_METHODS:
        raise CloudflareRequestError(
            f"Unsupported method {normalized_method}. Allowed methods: {sorted(ALLOWED_METHODS)}."
        )
    normalized_path = normalize_cloudflare_path(path)
    operation = find_operation(normalized_method, normalized_path)
    if operation is None:
        raise CloudflareRequestError(
            "This method/path is not present in the pinned Cloudflare schema snapshot."
        )
    if operation.get("coverage_status") != "callable":
        raise CloudflareRequestError(
            "This documented operation is catalog-only under the reviewed transport or security "
            "policy. Inspect get_endpoint_coverage for the exact exclusion reason."
        )

    supported_types = _operation_request_media_types(operation)
    selected_content_type = content_type.strip().lower() if content_type else None
    if body is None:
        if selected_content_type:
            raise CloudflareRequestError("content_type is only valid when body is provided.")
        if operation.get("request_body_required") is True:
            raise CloudflareRequestError("This operation requires a JSON request body.")
        return operation, None

    allowed_json_types = tuple(
        media_type for media_type in supported_types if media_type in JSON_REQUEST_MEDIA_TYPES
    )
    if not allowed_json_types:
        raise CloudflareRequestError("This operation does not accept a JSON request body.")
    if selected_content_type is None:
        selected_content_type = (
            "application/json"
            if "application/json" in allowed_json_types
            else allowed_json_types[0]
        )
    if selected_content_type not in allowed_json_types:
        raise CloudflareRequestError(
            "content_type must be one of the operation's supported JSON request media types: "
            f"{sorted(allowed_json_types)}."
        )
    return operation, selected_content_type


def redact_secrets(value: Any) -> Any:
    """Recursively redact likely credential material from provider output."""

    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            compact_key = _NON_ALPHANUMERIC_KEY_RE.sub("", key_text.casefold())
            if compact_key in _COMPACT_SECRET_CONTAINER_NAMES or any(
                part in compact_key for part in _COMPACT_SECRET_KEY_PARTS
            ):
                redacted[key_text] = "[REDACTED]"
            else:
                redacted[key_text] = redact_secrets(item)
        return redacted
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        sanitized = _BEARER_PATTERN.sub("Bearer [REDACTED]", value)
        return _TOKENISH_PATTERN.sub("[REDACTED]", sanitized)
    return value


def _json_media_type(content_type: str) -> bool:
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )


async def _read_bounded_response(
    response: httpx.Response,
    *,
    max_response_bytes: int,
) -> tuple[Any, dict[str, Any]]:
    """Stream at most the configured decoded bytes; never return a partial body."""

    metadata: dict[str, Any] = {
        "content_type": response.headers.get("content-type", "").split(";", 1)[0].strip(),
        "content_length": None,
        "bytes_read": 0,
        "body_omitted": False,
        "omission_reason": None,
    }
    declared = response.headers.get("content-length", "")
    if declared:
        try:
            metadata["content_length"] = int(declared)
        except ValueError:
            metadata["content_length"] = None
    if (
        isinstance(metadata["content_length"], int)
        and metadata["content_length"] > max_response_bytes
    ):
        metadata["body_omitted"] = True
        metadata["omission_reason"] = "declared_response_too_large"
        return None, metadata

    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > max_response_bytes:
            metadata["bytes_read"] = total
            metadata["body_omitted"] = True
            metadata["omission_reason"] = "streamed_response_too_large"
            return None, metadata
        chunks.append(chunk)
    metadata["bytes_read"] = total
    raw = b"".join(chunks)
    if not raw:
        return None, metadata
    if not _json_media_type(response.headers.get("content-type", "")):
        metadata["body_omitted"] = True
        metadata["omission_reason"] = "non_json_response"
        return None, metadata
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        metadata["body_omitted"] = True
        metadata["omission_reason"] = "invalid_json_response"
        return None, metadata

    redacted = redact_secrets(payload)
    encoded = json.dumps(redacted, ensure_ascii=True, separators=(",", ":"), default=str)
    if len(encoded.encode("utf-8")) > max_response_bytes:
        metadata["body_omitted"] = True
        metadata["omission_reason"] = "redacted_response_too_large"
        return None, metadata
    return redacted, metadata


async def call_cloudflare_api(
    *,
    config: CloudflareConfig,
    method: str,
    path: str,
    query: dict[str, Any] | None = None,
    body: dict[str, Any] | list[Any] | None = None,
    content_type: str | None = None,
    approval_attestation: str = "",
    approval_signing_key: str = "",
    principal_fingerprint: str = "",
    timeout_seconds: float = 30.0,
    max_response_bytes: int = 100_000,
    client: httpx.AsyncClient | None = None,
    ledger: ApprovalLedger = approval_ledger,
) -> dict[str, Any]:
    """Preview or execute one schema-covered JSON Cloudflare REST request."""

    normalized_method = method.upper()
    normalized_path = normalize_cloudflare_path(path)
    operation, selected_content_type = validate_operation_contract(
        method=normalized_method,
        path=normalized_path,
        body=body,
        content_type=content_type,
    )
    request_sha256 = canonical_request_sha256(
        method=normalized_method,
        path=normalized_path,
        query=query,
        body=body,
        content_type=selected_content_type,
    )
    classification = str(operation["classification"])
    operation_id = str(operation.get("operation_id") or "")
    if not 1 <= len(operation_id) <= 256:
        raise CloudflareRequestError(
            "The pinned operation has no valid approval identity; execution is disabled."
        )
    approval: dict[str, object] = {
        "required": classification != "read",
        "verified": classification == "read",
        "consumed": False,
        "operation_id": operation_id,
        "request_sha256": request_sha256,
        "mechanism": (
            "none" if classification == "read" else "externally_signed_one_time_attestation"
        ),
    }

    if operation.get("high_risk"):
        return {
            "ok": False,
            "executed": False,
            "status_code": None,
            "cloudflare_success": None,
            "method": normalized_method,
            "path": normalized_path,
            "classification": classification,
            "covered_by_schema": True,
            "operation": operation,
            "approval": approval,
            "response": None,
            "response_metadata": None,
            "error": {
                "type": "high_risk_operation_blocked",
                "message": (
                    "Credential, account-administration, billing, commerce, and other reviewed "
                    "high-risk operations are permanently blocked from the generic dispatcher."
                ),
            },
        }

    if not config.api_token:
        raise ProviderConfigurationError(
            "Missing Cloudflare API token. Provide x-cloudflare-api-token for this request."
        )
    if config.api_base_url != DEFAULT_CLOUDFLARE_API_BASE_URL:
        raise CloudflareRequestError("Cloudflare API origin must use the fixed reviewed base URL.")
    if not 1 <= timeout_seconds <= 120:
        raise CloudflareRequestError("timeout_seconds must be between 1 and 120.")
    if max_response_bytes < 4_096:
        raise CloudflareRequestError("max_response_bytes must be at least 4096.")
    if max_response_bytes > MAX_PROVIDER_RESPONSE_BYTES:
        raise CloudflareRequestError(
            f"max_response_bytes must not exceed {MAX_PROVIDER_RESPONSE_BYTES}."
        )

    provider_fingerprint = fingerprint_secret(
        "cloudflare-byok",
        "\0".join((config.api_token, config.account_id or "", config.zone_id or "")),
    )
    if classification != "read":
        if approval_signing_key and hmac.compare_digest(approval_signing_key, config.api_token):
            raise CloudflareRequestError(
                "Mutation approval signing key must be distinct from the provider credential."
            )
        if not approval_signing_key:
            return {
                "ok": False,
                "executed": False,
                "status_code": None,
                "cloudflare_success": None,
                "method": normalized_method,
                "path": normalized_path,
                "classification": classification,
                "covered_by_schema": True,
                "operation": operation,
                "approval": approval,
                "response": None,
                "response_metadata": None,
                "error": {
                    "type": "mutation_approval_unavailable",
                    "message": (
                        "This deployment is read-only until MCP_APPROVAL_SIGNING_KEY is configured."
                    ),
                },
            }
        if not approval_attestation:
            approval = {
                "required": True,
                "verified": False,
                "consumed": False,
                "operation_id": operation_id,
                "request_sha256": request_sha256,
                **ledger.issue(
                    request_sha256=request_sha256,
                    operation_id=operation_id,
                    principal_fingerprint=principal_fingerprint,
                    provider_fingerprint=provider_fingerprint,
                ),
            }
            return {
                "ok": False,
                "executed": False,
                "status_code": None,
                "cloudflare_success": None,
                "method": normalized_method,
                "path": normalized_path,
                "classification": classification,
                "covered_by_schema": True,
                "operation": operation,
                "approval": approval,
                "response": None,
                "response_metadata": None,
                "error": {
                    "type": "approval_required",
                    "message": (
                        "A trusted operator or Portal broker must review and externally sign the "
                        "one-use approval payload. Send the resulting attestation in the reported "
                        "approval header before it expires."
                    ),
                },
            }
        try:
            approval = ledger.consume(
                attestation=approval_attestation,
                signing_key=approval_signing_key,
                request_sha256=request_sha256,
                operation_id=operation_id,
                principal_fingerprint=principal_fingerprint,
                provider_fingerprint=provider_fingerprint,
            )
        except ApprovalError as exc:
            return {
                "ok": False,
                "executed": False,
                "status_code": None,
                "cloudflare_success": None,
                "method": normalized_method,
                "path": normalized_path,
                "classification": classification,
                "covered_by_schema": True,
                "operation": operation,
                "approval": approval,
                "response": None,
                "response_metadata": None,
                "error": {"type": exc.code, "message": str(exc)},
            }

    headers = {
        "Authorization": f"Bearer {config.api_token}",
        "Accept": "application/json",
        "User-Agent": f"madpanda-cloudflare-mcp/{__version__}",
    }
    if body is not None and selected_content_type:
        headers["Content-Type"] = selected_content_type

    owns_client = client is None
    active_client = client or httpx.AsyncClient(
        base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        follow_redirects=False,
        trust_env=False,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    )
    response_payload: Any = None
    response_metadata: dict[str, Any]
    status_code: int
    try:
        try:
            async with active_client.stream(
                normalized_method,
                normalized_path,
                params=query,
                json=body,
                headers=headers,
                timeout=httpx.Timeout(timeout_seconds),
                follow_redirects=False,
            ) as response:
                status_code = response.status_code
                response_payload, response_metadata = await _read_bounded_response(
                    response,
                    max_response_bytes=max_response_bytes,
                )
        except httpx.HTTPError:
            raise CloudflareRequestError(
                "Cloudflare request failed before a reviewed response was available. "
                "For mutations, reconcile provider state before any manual retry."
            ) from None
    finally:
        if owns_client:
            await active_client.aclose()

    cloudflare_success = (
        response_payload.get("success") if isinstance(response_payload, dict) else None
    )
    http_ok = 200 <= status_code < 300
    semantic_ok = cloudflare_success is not False
    ok = http_ok and semantic_ok and not response_metadata["body_omitted"]
    error = None
    if not ok:
        if response_metadata["body_omitted"]:
            error = {
                "type": "provider_response_omitted",
                "message": "Cloudflare returned a body outside the reviewed JSON/size contract.",
            }
        elif http_ok and not semantic_ok:
            error = {
                "type": "cloudflare_api_error",
                "message": "Cloudflare reported a failed operation.",
            }
        else:
            error = {
                "type": "cloudflare_api_error",
                "message": "Cloudflare returned an unsuccessful HTTP status.",
            }

    returned_response = response_payload
    if classification != "read":
        returned_response = None
        response_metadata = {
            **response_metadata,
            "body_omitted_by_policy": response_payload is not None,
            "omission_policy": "mutation_outcome_envelope",
        }

    return {
        "ok": ok,
        "executed": True,
        "status_code": status_code,
        "cloudflare_success": cloudflare_success,
        "method": normalized_method,
        "path": normalized_path,
        "classification": classification,
        "covered_by_schema": True,
        "operation": operation,
        "approval": approval,
        "response": returned_response,
        "response_metadata": response_metadata,
        "error": error,
    }
