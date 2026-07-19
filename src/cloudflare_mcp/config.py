"""Runtime configuration and request-scoped credential handling."""

from __future__ import annotations

import hmac
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass

PORTAL_GRANT_HEADER = "x-madpanda-portal-grant"
DEFAULT_TENANT_ID_HEADER = "x-madpanda-user-id"
CLOUDFLARE_TOKEN_HEADER = "x-cloudflare-api-token"
CLOUDFLARE_ACCOUNT_HEADER = "x-cloudflare-account-id"
CLOUDFLARE_ZONE_HEADER = "x-cloudflare-zone-id"

DEFAULT_CLOUDFLARE_API_BASE_URL = "https://api.cloudflare.com/client/v4"
DEFAULT_ALLOWED_HOSTS = "localhost,127.0.0.1,[::1],testserver,cloudflare-mcp"
MIN_SERVICE_TOKEN_LENGTH = 32
MAX_SERVICE_TOKEN_LENGTH = 4096
MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024
MAX_MCP_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PROVIDER_RESPONSE_BYTES = 245_760
MCP_RESPONSE_RESERVED_BYTES = 32_768
PROVIDER_RESPONSE_EXPANSION_FACTOR = 8
_SAFE_SECRET_PATTERN = re.compile(r"^[\x21-\x7e]+$")
_SAFE_HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_SAFE_PROVIDER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_SAFE_TENANT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_RESERVED_TENANT_HEADERS = frozenset(
    {
        "authorization",
        "content-type",
        "content-length",
        "host",
        "mcp-protocol-version",
        "mcp-session-id",
        "origin",
        "transfer-encoding",
        PORTAL_GRANT_HEADER,
        CLOUDFLARE_TOKEN_HEADER,
        CLOUDFLARE_ACCOUNT_HEADER,
        CLOUDFLARE_ZONE_HEADER,
        "x-mcp-approval-attestation",
    }
)
_KNOWN_SECRET_SENTINELS = (
    "change-me",
    "changeme",
    "example-token",
    "replace-with",
    "your-token",
)


class RuntimeConfigurationError(RuntimeError):
    """Raised when startup security configuration is invalid."""


class ServiceAuthError(PermissionError):
    """Raised when service-level authentication is missing or invalid."""


class ProviderConfigurationError(RuntimeError):
    """Raised when a request-scoped Cloudflare credential is missing."""


@dataclass(frozen=True)
class RuntimeSettings:
    """Validated process-level settings that never contain provider credentials."""

    mode: str
    host: str
    port: int
    access_token: str
    portal_grant_token: str
    tenant_id_header: str
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    request_body_max_bytes: int
    mcp_response_max_bytes: int
    provider_response_max_bytes: int
    approval_signing_key: str
    build_sha: str
    source_fingerprint: str
    image_reference: str


@dataclass(frozen=True)
class CloudflareConfig:
    """Resolved request-scoped Cloudflare configuration without exposing secrets."""

    api_base_url: str
    api_token: str
    api_token_source: str
    account_id: str | None = None
    zone_id: str | None = None


def normalize_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Return a lower-case HTTP header dictionary."""

    if not headers:
        return {}
    return {str(key).lower(): str(value) for key, value in headers.items()}


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeConfigurationError(f"{name} must be an integer.") from exc
    if not minimum <= value <= maximum:
        raise RuntimeConfigurationError(f"{name} must be between {minimum} and {maximum} bytes.")
    return value


def _split_env(name: str, default: str = "") -> tuple[str, ...]:
    return tuple(part.strip() for part in os.getenv(name, default).split(",") if part.strip())


def _valid_build_sha(value: str) -> bool:
    return value == "development" or bool(re.fullmatch(r"[A-Za-z0-9._-]{7,128}", value))


def _valid_source_fingerprint(value: str) -> bool:
    return value == "development" or bool(re.fullmatch(r"[0-9a-fA-F]{64}", value))


def _valid_image_reference(value: str) -> bool:
    return value == "development" or bool(re.fullmatch(r"[^\s@]+@sha256:[0-9a-fA-F]{64}", value))


def _valid_secret(value: str) -> bool:
    """Reject blank, oversized, control-bearing, whitespace, and documented sentinel secrets."""

    if not MIN_SERVICE_TOKEN_LENGTH <= len(value) <= MAX_SERVICE_TOKEN_LENGTH:
        return False
    if not _SAFE_SECRET_PATTERN.fullmatch(value):
        return False
    if "<" in value or ">" in value or (value.startswith("${") and value.endswith("}")):
        return False
    lowered = value.lower()
    return not any(sentinel in lowered for sentinel in _KNOWN_SECRET_SENTINELS)


def _validate_optional_provider_id(name: str, value: str) -> str | None:
    if not value:
        return None
    if not _SAFE_PROVIDER_ID_PATTERN.fullmatch(value):
        raise ProviderConfigurationError(
            f"{name} must be 1-128 URL-safe ASCII letters, digits, underscores, or hyphens."
        )
    return value


def runtime_settings(*, validate: bool = True) -> RuntimeSettings:
    """Read process settings and optionally enforce the startup contract."""

    settings = RuntimeSettings(
        mode=os.getenv("MCP_MODE", "standalone").strip().lower(),
        host=os.getenv("MCP_HOST", "0.0.0.0").strip(),
        port=_bounded_env_int("MCP_PORT", 8000, 1, 65535),
        access_token=os.getenv("MCP_ACCESS_TOKEN", ""),
        portal_grant_token=os.getenv("MCP_PORTAL_GRANT_TOKEN", ""),
        tenant_id_header=(
            os.getenv("MCP_TENANT_ID_HEADER", DEFAULT_TENANT_ID_HEADER).strip().lower()
            or DEFAULT_TENANT_ID_HEADER
        ),
        allowed_hosts=tuple(
            host.lower() for host in _split_env("MCP_ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS)
        ),
        allowed_origins=_split_env("MCP_ALLOWED_ORIGINS"),
        request_body_max_bytes=_bounded_env_int(
            "MCP_REQUEST_BODY_MAX_BYTES",
            131_072,
            1_024,
            MAX_REQUEST_BODY_BYTES,
        ),
        mcp_response_max_bytes=_bounded_env_int(
            "MCP_RESPONSE_BODY_MAX_BYTES",
            1_048_576,
            16_384,
            MAX_MCP_RESPONSE_BYTES,
        ),
        provider_response_max_bytes=_bounded_env_int(
            "MCP_PROVIDER_RESPONSE_MAX_BYTES",
            65_536,
            4_096,
            MAX_PROVIDER_RESPONSE_BYTES,
        ),
        approval_signing_key=os.getenv("MCP_APPROVAL_SIGNING_KEY", ""),
        build_sha=os.getenv("MCP_BUILD_SHA", "development").strip() or "development",
        source_fingerprint=os.getenv("MCP_SOURCE_FINGERPRINT", "development").strip()
        or "development",
        image_reference=os.getenv("MCP_IMAGE_REFERENCE", "development").strip() or "development",
    )
    if validate:
        validate_runtime_settings(settings)
    return settings


def validate_runtime_settings(settings: RuntimeSettings) -> None:
    """Fail closed on an unknown mode or incomplete security configuration."""

    if settings.mode not in {"standalone", "portal"}:
        raise RuntimeConfigurationError("MCP_MODE must be either standalone or portal.")
    if not _SAFE_HEADER_NAME_PATTERN.fullmatch(settings.tenant_id_header):
        raise RuntimeConfigurationError("MCP_TENANT_ID_HEADER must be a valid HTTP header name.")
    if settings.tenant_id_header in _RESERVED_TENANT_HEADERS:
        raise RuntimeConfigurationError(
            "MCP_TENANT_ID_HEADER must use a unique, non-reserved HTTP security header."
        )
    if not settings.host:
        raise RuntimeConfigurationError("MCP_HOST cannot be empty.")
    if not settings.allowed_hosts or any("*" in host for host in settings.allowed_hosts):
        raise RuntimeConfigurationError(
            "MCP_ALLOWED_HOSTS must contain an explicit host allowlist without wildcards."
        )
    if settings.mode == "standalone" and not _valid_secret(settings.access_token):
        raise RuntimeConfigurationError(
            "Standalone mode requires a non-placeholder MCP_ACCESS_TOKEN with 32-4096 "
            "visible ASCII characters and no whitespace."
        )
    if settings.mode == "portal" and not _valid_secret(settings.portal_grant_token):
        raise RuntimeConfigurationError(
            "Portal mode requires a non-placeholder MCP_PORTAL_GRANT_TOKEN with 32-4096 "
            "visible ASCII characters and no whitespace."
        )
    if settings.approval_signing_key and not _valid_secret(settings.approval_signing_key):
        raise RuntimeConfigurationError(
            "MCP_APPROVAL_SIGNING_KEY must be blank or a non-placeholder secret with 32-4096 "
            "visible ASCII characters and no whitespace."
        )
    service_credential = (
        settings.access_token if settings.mode == "standalone" else settings.portal_grant_token
    )
    if settings.approval_signing_key and hmac.compare_digest(
        settings.approval_signing_key, service_credential
    ):
        raise RuntimeConfigurationError(
            "MCP_APPROVAL_SIGNING_KEY must be distinct from the selected service credential."
        )
    required_mcp_response_bytes = (
        settings.provider_response_max_bytes * PROVIDER_RESPONSE_EXPANSION_FACTOR
        + MCP_RESPONSE_RESERVED_BYTES
    )
    if settings.mcp_response_max_bytes < required_mcp_response_bytes:
        raise RuntimeConfigurationError(
            "MCP_RESPONSE_BODY_MAX_BYTES must be at least "
            f"{required_mcp_response_bytes} for the configured provider-response limit."
        )
    if not _valid_build_sha(settings.build_sha):
        raise RuntimeConfigurationError("MCP_BUILD_SHA has an invalid format.")
    if not _valid_source_fingerprint(settings.source_fingerprint):
        raise RuntimeConfigurationError(
            "MCP_SOURCE_FINGERPRINT must be development or a 64-character hexadecimal digest."
        )
    if not _valid_image_reference(settings.image_reference):
        raise RuntimeConfigurationError(
            "MCP_IMAGE_REFERENCE must be development or an immutable sha256 image reference."
        )


def required_service_headers(settings: RuntimeSettings) -> list[str]:
    """Return the service authentication headers for the selected mode."""

    return (
        ["authorization"]
        if settings.mode == "standalone"
        else [PORTAL_GRANT_HEADER, settings.tenant_id_header]
    )


def require_service_access(
    headers: Mapping[str, str] | None,
    settings: RuntimeSettings | None = None,
) -> None:
    """Validate standalone Bearer or Portal grant authentication in constant time."""

    active = settings or runtime_settings()
    normalized = normalize_headers(headers)
    if active.mode == "portal":
        supplied = normalized.get(PORTAL_GRANT_HEADER, "")
        if not supplied:
            raise ServiceAuthError("Missing required header: x-madpanda-portal-grant.")
        if not hmac.compare_digest(supplied, active.portal_grant_token):
            raise ServiceAuthError("Invalid portal grant token.")
        tenant_id = normalized.get(active.tenant_id_header, "")
        if not tenant_id:
            raise ServiceAuthError(f"Missing required header: {active.tenant_id_header}.")
        if not _SAFE_TENANT_ID_PATTERN.fullmatch(tenant_id):
            raise ServiceAuthError(
                f"Invalid {active.tenant_id_header}; expected a 1-128 character broker-derived "
                "tenant identifier."
            )
        return

    authorization = normalized.get("authorization", "")
    scheme, separator, supplied = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not supplied:
        raise ServiceAuthError("Missing required Authorization Bearer token.")
    if supplied != supplied.strip() or not hmac.compare_digest(supplied, active.access_token):
        raise ServiceAuthError("Invalid Authorization Bearer token.")


def resolve_cloudflare_config(
    headers: Mapping[str, str] | None,
    *,
    require_token: bool = True,
) -> CloudflareConfig:
    """Resolve a Cloudflare credential from the current request only."""

    normalized = normalize_headers(headers)
    api_token = normalized.get(CLOUDFLARE_TOKEN_HEADER, "")
    if require_token and not api_token:
        raise ProviderConfigurationError(
            "Missing Cloudflare API token. Provide x-cloudflare-api-token for this request."
        )

    if api_token and (
        len(api_token) > MAX_SERVICE_TOKEN_LENGTH or not _SAFE_SECRET_PATTERN.fullmatch(api_token)
    ):
        raise ProviderConfigurationError(
            "x-cloudflare-api-token must contain at most 4096 visible ASCII characters "
            "without whitespace."
        )

    return CloudflareConfig(
        api_base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        api_token=api_token,
        api_token_source="request_header" if api_token else "missing",
        account_id=_validate_optional_provider_id(
            CLOUDFLARE_ACCOUNT_HEADER, normalized.get(CLOUDFLARE_ACCOUNT_HEADER, "")
        ),
        zone_id=_validate_optional_provider_id(
            CLOUDFLARE_ZONE_HEADER, normalized.get(CLOUDFLARE_ZONE_HEADER, "")
        ),
    )


def configuration_status(
    headers: Mapping[str, str] | None = None,
    settings: RuntimeSettings | None = None,
) -> dict[str, object]:
    """Return secret-safe service and request-scoped provider readiness."""

    active = settings or runtime_settings(validate=False)
    normalized = normalize_headers(headers)
    provider = resolve_cloudflare_config(normalized, require_token=False)
    service_auth_configured = (
        _valid_secret(active.access_token)
        if active.mode == "standalone"
        else _valid_secret(active.portal_grant_token)
    )
    return {
        "service": "cloudflare-mcp",
        "setup_status": "ready" if service_auth_configured else "setup_required",
        "ready": service_auth_configured,
        "mode": active.mode,
        "service_auth_configured": service_auth_configured,
        "required_service_headers": required_service_headers(active),
        "portal_tenant_partitioning_required": active.mode == "portal",
        "portal_tenant_header": active.tenant_id_header if active.mode == "portal" else None,
        "provider_credentials_mode": "per_request_byok",
        "cloudflare_api_token_present": bool(provider.api_token),
        "cloudflare_api_token_source": provider.api_token_source,
        "cloudflare_account_id_present": bool(provider.account_id),
        "cloudflare_zone_id_present": bool(provider.zone_id),
        "cloudflare_api_base_url": DEFAULT_CLOUDFLARE_API_BASE_URL,
        "mutation_approval_configured": _valid_secret(active.approval_signing_key),
        "high_risk_operation_policy": "permanently_blocked",
        "limits": {
            "request_body_max_bytes": active.request_body_max_bytes,
            "mcp_response_max_bytes": active.mcp_response_max_bytes,
            "provider_response_max_bytes": active.provider_response_max_bytes,
            "provider_response_expansion_factor": PROVIDER_RESPONSE_EXPANSION_FACTOR,
            "mcp_response_reserved_bytes": MCP_RESPONSE_RESERVED_BYTES,
        },
    }
