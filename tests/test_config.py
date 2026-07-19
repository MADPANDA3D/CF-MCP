from __future__ import annotations

import json
from pathlib import Path

import pytest

from cloudflare_mcp.config import (
    DEFAULT_CLOUDFLARE_API_BASE_URL,
    CloudflareConfig,
    ProviderConfigurationError,
    RuntimeConfigurationError,
    ServiceAuthError,
    configuration_status,
    require_service_access,
    resolve_cloudflare_config,
    runtime_settings,
)
from cloudflare_mcp.server import _cloudflare_token_verify_paths

ACCESS_TOKEN = "standalone-access-token-000000000000000000000000"
PORTAL_TOKEN = "portal-grant-token-000000000000000000000000000"
PORTAL_TENANT = "tenant_01:project-a"


def configure_runtime(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    monkeypatch.setenv("MCP_MODE", mode)
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver,cloudflare-mcp")
    monkeypatch.setenv("MCP_BUILD_SHA", "development")
    monkeypatch.setenv("MCP_SOURCE_FINGERPRINT", "development")
    monkeypatch.setenv("MCP_IMAGE_REFERENCE", "development")
    monkeypatch.setenv("MCP_TENANT_ID_HEADER", "x-madpanda-user-id")
    monkeypatch.delenv("MCP_APPROVAL_SIGNING_KEY", raising=False)
    if mode == "standalone":
        monkeypatch.setenv("MCP_ACCESS_TOKEN", ACCESS_TOKEN)
        monkeypatch.delenv("MCP_PORTAL_GRANT_TOKEN", raising=False)
    elif mode == "portal":
        monkeypatch.setenv("MCP_PORTAL_GRANT_TOKEN", PORTAL_TOKEN)
        monkeypatch.delenv("MCP_ACCESS_TOKEN", raising=False)


def test_unknown_mode_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_runtime(monkeypatch, "standalone")
    monkeypatch.setenv("MCP_MODE", "public")

    with pytest.raises(RuntimeConfigurationError, match="standalone or portal"):
        runtime_settings()


def test_mode_requires_only_its_own_service_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_runtime(monkeypatch, "standalone")
    standalone = runtime_settings()
    assert standalone.mode == "standalone"
    assert standalone.portal_grant_token == ""

    configure_runtime(monkeypatch, "portal")
    portal = runtime_settings()
    assert portal.mode == "portal"
    assert portal.access_token == ""


def test_standalone_bearer_authentication(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_runtime(monkeypatch, "standalone")
    settings = runtime_settings()

    with pytest.raises(ServiceAuthError, match="Missing required Authorization"):
        require_service_access({}, settings)
    with pytest.raises(ServiceAuthError, match="Invalid Authorization"):
        require_service_access({"authorization": "Bearer wrong"}, settings)

    require_service_access({"Authorization": f"Bearer {ACCESS_TOKEN}"}, settings)


def test_portal_grant_authentication(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_runtime(monkeypatch, "portal")
    settings = runtime_settings()

    with pytest.raises(ServiceAuthError, match="Missing required header"):
        require_service_access({}, settings)
    with pytest.raises(ServiceAuthError, match="Invalid portal grant"):
        require_service_access({"x-madpanda-portal-grant": "wrong"}, settings)
    with pytest.raises(ServiceAuthError, match="x-madpanda-user-id"):
        require_service_access({"X-MADPANDA-PORTAL-GRANT": PORTAL_TOKEN}, settings)
    with pytest.raises(ServiceAuthError, match="Invalid x-madpanda-user-id"):
        require_service_access(
            {
                "X-MADPANDA-PORTAL-GRANT": PORTAL_TOKEN,
                "X-MADPANDA-USER-ID": "../../tenant",
            },
            settings,
        )

    require_service_access(
        {
            "X-MADPANDA-PORTAL-GRANT": PORTAL_TOKEN,
            "X-MADPANDA-USER-ID": PORTAL_TENANT,
        },
        settings,
    )


@pytest.mark.parametrize(
    "header",
    [
        "authorization",
        "content-type",
        "mcp-protocol-version",
        "mcp-session-id",
        "x-madpanda-portal-grant",
        "x-cloudflare-api-token",
        "bad header",
    ],
)
def test_portal_tenant_header_must_be_unique_and_valid(
    monkeypatch: pytest.MonkeyPatch,
    header: str,
) -> None:
    configure_runtime(monkeypatch, "portal")
    monkeypatch.setenv("MCP_TENANT_ID_HEADER", header)

    with pytest.raises(RuntimeConfigurationError, match="MCP_TENANT_ID_HEADER"):
        runtime_settings()


@pytest.mark.parametrize(
    "tenant_id",
    ["", " " * 3, "a" * 129, "../tenant", "tenant/value", "tenant\nother"],
)
def test_portal_tenant_identity_is_required_bounded_and_canonical(
    monkeypatch: pytest.MonkeyPatch,
    tenant_id: str,
) -> None:
    configure_runtime(monkeypatch, "portal")
    settings = runtime_settings()
    headers = {
        "X-MADPANDA-PORTAL-GRANT": PORTAL_TOKEN,
        "X-MADPANDA-USER-ID": tenant_id,
    }

    with pytest.raises(ServiceAuthError, match="x-madpanda-user-id"):
        require_service_access(headers, settings)


def test_provider_token_is_request_scoped_and_origin_is_fixed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "ignored-environment-token")
    with pytest.raises(ProviderConfigurationError, match="x-cloudflare-api-token"):
        resolve_cloudflare_config({})

    config = resolve_cloudflare_config(
        {
            "x-cloudflare-api-token": "request-token",
            "x-cloudflare-account-id": "account-placeholder",
            "x-cloudflare-zone-id": "zone-placeholder",
        }
    )

    assert config.api_base_url == DEFAULT_CLOUDFLARE_API_BASE_URL
    assert config.api_token == "request-token"
    assert config.api_token_source == "request_header"
    assert config.account_id == "account-placeholder"
    assert config.zone_id == "zone-placeholder"


def test_configuration_status_is_secret_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_runtime(monkeypatch, "portal")
    approval_key = "approval-signing-key-000000000000000000000000"
    monkeypatch.setenv("MCP_APPROVAL_SIGNING_KEY", approval_key)
    status = configuration_status(
        {
            "x-madpanda-portal-grant": PORTAL_TOKEN,
            "x-madpanda-user-id": PORTAL_TENANT,
            "x-cloudflare-api-token": "provider-secret-value",
        }
    )
    encoded = json.dumps(status)

    assert status["ready"] is True
    assert status["mode"] == "portal"
    assert status["provider_credentials_mode"] == "per_request_byok"
    assert status["cloudflare_api_token_present"] is True
    assert status["mutation_approval_configured"] is True
    assert status["required_service_headers"] == [
        "x-madpanda-portal-grant",
        "x-madpanda-user-id",
    ]
    assert status["portal_tenant_partitioning_required"] is True
    assert PORTAL_TOKEN not in encoded
    assert approval_key not in encoded
    assert "provider-secret-value" not in encoded


def test_runtime_size_bounds_are_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    configure_runtime(monkeypatch, "standalone")
    monkeypatch.setenv("MCP_REQUEST_BODY_MAX_BYTES", "999999999")

    with pytest.raises(RuntimeConfigurationError, match="MCP_REQUEST_BODY_MAX_BYTES"):
        runtime_settings()


def test_known_placeholder_and_unmodified_example_fail_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_runtime(monkeypatch, "standalone")
    monkeypatch.setenv("MCP_ACCESS_TOKEN", "replace-with-at-least-32-random-characters")
    with pytest.raises(RuntimeConfigurationError, match="non-placeholder"):
        runtime_settings()

    example = Path(".env.example").read_text(encoding="utf-8")
    values = {
        key: value
        for line in example.splitlines()
        if line and not line.startswith("#") and "=" in line
        for key, value in [line.split("=", 1)]
    }
    monkeypatch.setenv("MCP_MODE", values["MCP_MODE"])
    monkeypatch.setenv("MCP_ACCESS_TOKEN", values["MCP_ACCESS_TOKEN"])
    with pytest.raises(RuntimeConfigurationError, match="MCP_ACCESS_TOKEN"):
        runtime_settings()


@pytest.mark.parametrize(
    ("mode", "name", "value"),
    [
        (
            "portal",
            "MCP_PORTAL_GRANT_TOKEN",
            "<UNIQUE_SERVICE_GRANT_OF_AT_LEAST_32_CHARACTERS>",
        ),
        (
            "standalone",
            "MCP_ACCESS_TOKEN",
            "${MCP_ACCESS_TOKEN_FROM_A_SECRET_STORE}",
        ),
        (
            "portal",
            "MCP_APPROVAL_SIGNING_KEY",
            "<SEPARATELY_CONTROLLED_BROKER_SIGNING_KEY>",
        ),
    ],
)
def test_documented_secret_placeholders_fail_startup(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    name: str,
    value: str,
) -> None:
    configure_runtime(monkeypatch, mode)
    monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeConfigurationError, match=name):
        runtime_settings()


def test_approval_key_must_be_distinct_from_service_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_runtime(monkeypatch, "standalone")
    monkeypatch.setenv("MCP_APPROVAL_SIGNING_KEY", ACCESS_TOKEN)

    with pytest.raises(RuntimeConfigurationError, match="must be distinct"):
        runtime_settings()


def test_provider_and_mcp_response_limits_have_a_safe_cross_layer_invariant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_runtime(monkeypatch, "standalone")
    monkeypatch.setenv("MCP_RESPONSE_BODY_MAX_BYTES", "16384")
    monkeypatch.setenv("MCP_PROVIDER_RESPONSE_MAX_BYTES", "1048576")

    with pytest.raises(RuntimeConfigurationError, match="MCP_PROVIDER_RESPONSE_MAX_BYTES"):
        runtime_settings()

    monkeypatch.setenv("MCP_PROVIDER_RESPONSE_MAX_BYTES", "4096")
    with pytest.raises(RuntimeConfigurationError, match="must be at least 65536"):
        runtime_settings()


def test_provider_headers_reject_controls_oversize_and_unsafe_path_hints() -> None:
    with pytest.raises(ProviderConfigurationError, match="visible ASCII"):
        resolve_cloudflare_config({"x-cloudflare-api-token": "token with spaces"})
    with pytest.raises(ProviderConfigurationError, match="1-128 URL-safe"):
        resolve_cloudflare_config(
            {
                "x-cloudflare-api-token": "provider-token",
                "x-cloudflare-account-id": "../unsafe",
            }
        )


def test_account_owned_token_verification_uses_account_endpoint_first() -> None:
    config = CloudflareConfig(
        api_base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        api_token="cfat_example",
        api_token_source="request_header",
        account_id="account-placeholder",
    )
    assert _cloudflare_token_verify_paths(config) == [
        ("/accounts/account-placeholder/tokens/verify", "account")
    ]


def test_user_token_verification_keeps_user_endpoint_first() -> None:
    config = CloudflareConfig(
        api_base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        api_token="cfut_example",
        api_token_source="request_header",
        account_id="account-placeholder",
    )
    assert _cloudflare_token_verify_paths(config) == [
        ("/user/tokens/verify", "user"),
        ("/accounts/account-placeholder/tokens/verify", "account"),
    ]
