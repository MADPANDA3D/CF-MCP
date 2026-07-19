from __future__ import annotations

import json

import httpx
import pytest

from cloudflare_mcp.approval import ApprovalLedger, sign_approval_payload
from cloudflare_mcp.cloudflare import (
    CloudflareRequestError,
    call_cloudflare_api,
    normalize_cloudflare_path,
    validate_operation_contract,
)
from cloudflare_mcp.config import (
    DEFAULT_CLOUDFLARE_API_BASE_URL,
    CloudflareConfig,
    ProviderConfigurationError,
)

APPROVAL_KEY = "approval-signing-key-000000000000000000000000"
PRINCIPAL = "a" * 64


def provider_config(token: str = "synthetic-provider-token") -> CloudflareConfig:
    return CloudflareConfig(
        api_base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        api_token=token,
        api_token_source="request_header",
    )


def test_normalize_cloudflare_path_accepts_only_fixed_api_origin() -> None:
    assert normalize_cloudflare_path("zones") == "/zones"
    assert normalize_cloudflare_path("https://api.cloudflare.com/client/v4/zones") == "/zones"

    for unsafe in (
        "https://example.com/client/v4/zones",
        "https://api.cloudflare.com:444/client/v4/zones",
        "https://api.cloudflare.com/client/v4/zones?page=2",
        "/zones/../accounts",
        "/zones/%2e%2e/accounts",
        "/zones/%252e%252e/accounts",
        "/zones/%2faccounts",
        "/zones/{zone_id}",
        "/zones\\accounts",
        "/zones/with space",
    ):
        with pytest.raises(CloudflareRequestError):
            normalize_cloudflare_path(unsafe)

    assert normalize_cloudflare_path("/zones/%7eexample") == "/zones/~example"


def test_dispatcher_rejects_unmatched_and_catalog_only_operations() -> None:
    with pytest.raises(CloudflareRequestError, match="not present in the pinned"):
        validate_operation_contract(
            method="POST",
            path="/not-in-schema",
            body={},
            content_type="application/json",
        )

    with pytest.raises(CloudflareRequestError, match="catalog-only"):
        validate_operation_contract(
            method="GET",
            path="/accounts/example/access/saml_certificates/example/pem",
            body=None,
            content_type=None,
        )


@pytest.mark.asyncio
async def test_write_requires_external_one_use_approval_bound_to_exact_request() -> None:
    calls = 0
    ledger = ApprovalLedger()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.headers["authorization"] == "Bearer synthetic-provider-token"
        return httpx.Response(200, json={"success": True, "result": {"id": "zone-id"}})

    body = {"name": "example.invalid", "account": {"id": "account-placeholder"}}
    preview = await call_cloudflare_api(
        config=provider_config(),
        method="POST",
        path="/zones",
        body=body,
        approval_signing_key=APPROVAL_KEY,
        principal_fingerprint=PRINCIPAL,
        ledger=ledger,
    )

    assert preview["executed"] is False
    assert preview["error"]["type"] == "approval_required"
    assert preview["approval"]["mechanism"] == "externally_signed_one_time_attestation"
    assert calls == 0
    attestation = sign_approval_payload(preview["approval"]["approval_payload"], APPROVAL_KEY)

    async with httpx.AsyncClient(
        base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        transport=httpx.MockTransport(handler),
    ) as client:
        changed = await call_cloudflare_api(
            config=provider_config(),
            method="POST",
            path="/zones",
            body={**body, "name": "changed.invalid"},
            approval_attestation=attestation,
            approval_signing_key=APPROVAL_KEY,
            principal_fingerprint=PRINCIPAL,
            client=client,
            ledger=ledger,
        )
        result = await call_cloudflare_api(
            config=provider_config(),
            method="POST",
            path="/zones",
            body=body,
            approval_attestation=attestation,
            approval_signing_key=APPROVAL_KEY,
            principal_fingerprint=PRINCIPAL,
            client=client,
            ledger=ledger,
        )
        replay = await call_cloudflare_api(
            config=provider_config(),
            method="POST",
            path="/zones",
            body=body,
            approval_attestation=attestation,
            approval_signing_key=APPROVAL_KEY,
            principal_fingerprint=PRINCIPAL,
            client=client,
            ledger=ledger,
        )

    assert changed["error"]["type"] == "approval_binding_mismatch"
    assert result["ok"] is True
    assert result["executed"] is True
    assert result["approval"]["consumed"] is True
    assert result["response"] is None
    assert result["response_metadata"]["omission_policy"] == "mutation_outcome_envelope"
    assert replay["error"]["type"] == "approval_replayed"
    assert replay["executed"] is False
    assert calls == 1


@pytest.mark.asyncio
async def test_destructive_preview_needs_provider_credential_and_external_approval() -> None:
    with pytest.raises(ProviderConfigurationError, match="x-cloudflare-api-token"):
        await call_cloudflare_api(
            config=provider_config(token=""),
            method="DELETE",
            path="/accounts/account-placeholder/access/apps/app-placeholder",
            approval_signing_key=APPROVAL_KEY,
            principal_fingerprint=PRINCIPAL,
        )

    preview = await call_cloudflare_api(
        config=provider_config(),
        method="DELETE",
        path="/accounts/account-placeholder/access/apps/app-placeholder",
        approval_signing_key=APPROVAL_KEY,
        principal_fingerprint=PRINCIPAL,
    )
    assert preview["executed"] is False
    assert preview["classification"] == "destructive"
    assert preview["error"]["type"] == "approval_required"

    with pytest.raises(CloudflareRequestError, match="distinct from the provider"):
        await call_cloudflare_api(
            config=provider_config(),
            method="DELETE",
            path="/accounts/account-placeholder/access/apps/app-placeholder",
            approval_signing_key="synthetic-provider-token",
            principal_fingerprint=PRINCIPAL,
        )


@pytest.mark.asyncio
async def test_high_risk_mutation_is_permanently_blocked_without_provider_call() -> None:
    result = await call_cloudflare_api(
        config=provider_config(),
        method="DELETE",
        path="/accounts/account-placeholder",
    )

    assert result["executed"] is False
    assert result["error"]["type"] == "high_risk_operation_blocked"
    assert result["operation"]["risk_flags"] == ["account_administration"]


@pytest.mark.asyncio
async def test_credential_and_side_effecting_get_overrides_never_contact_provider() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"success": True, "result": "credential"})

    async with httpx.AsyncClient(
        base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        transport=httpx.MockTransport(handler),
    ) as client:
        for path in (
            "/accounts/account-id/alerting/v3/destinations/pagerduty/connect/token-id",
            "/accounts/account-id/cni/interconnects/example-icon/loa",
            "/accounts/account-id/cfd_tunnel/tunnel-id/token",
            "/accounts/account-id/containers/instances/instance-id/ssh",
            "/accounts/account-id/warp_connector/tunnel-id/token",
        ):
            with pytest.raises(CloudflareRequestError, match="catalog-only"):
                await call_cloudflare_api(
                    config=provider_config(), method="GET", path=path, client=client
                )

    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/signed-url", None),
        ("POST", "/internal/submit", {}),
        (
            "GET",
            "/accounts/account-id/artifacts/namespaces/example/repos/repo/tokens",
            None,
        ),
    ],
)
async def test_unknown_success_contracts_never_contact_provider(
    method: str,
    path: str,
    body: dict[str, object] | None,
) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"success": True})

    async with httpx.AsyncClient(
        base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(CloudflareRequestError, match="catalog-only"):
            await call_cloudflare_api(
                config=provider_config(),
                method=method,
                path=path,
                body=body,
                client=client,
            )

    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        (
            "GET",
            "/accounts/account-id/stream/live_inputs/live-input-id",
            None,
        ),
        (
            "POST",
            "/accounts/account-id/stream/live_inputs",
            {},
        ),
        (
            "POST",
            "/accounts/account-id/challenges/widgets",
            {},
        ),
        (
            "GET",
            "/zones/zone-id/dnssec/zsk",
            None,
        ),
        ("GET", "/accounts/account-id/addressing/prefixes", None),
        ("GET", "/accounts/account-id/realtime/kit/app-id/livestreams", None),
        (
            "POST",
            "/accounts/account-id/realtime/kit/app-id/meetings/meeting-id/participants",
            {},
        ),
        (
            "POST",
            "/accounts/account-id/ai-gateway/gateways/gateway-id/provider_configs",
            {},
        ),
        ("POST", "/accounts/account-id/pipelines", {}),
        ("POST", "/accounts/account-id/containers/registries", {}),
        ("GET", "/accounts/account-id/magic/connectors", None),
        ("GET", "/accounts/account-id/billing/profile", None),
        ("POST", "/accounts/account-id/cni/interconnects", {}),
        ("POST", "/accounts/account-id/d1/database/database-id/export", {}),
        ("POST", "/accounts/account-id/images/v2/direct_upload", {}),
        ("POST", "/accounts/account-id/browser-rendering/devtools/browser", {}),
        ("GET", "/accounts/account-id/ai-gateway/gateways", None),
        ("GET", "/accounts/account-id/ai-gateway/billing/invoice-history", None),
        (
            "GET",
            "/accounts/account-id/realtime/kit/app-id/sessions/session-id/transcript",
            None,
        ),
        (
            "POST",
            "/accounts/account-id/workers/observability/telemetry/live-tail",
            {},
        ),
        ("GET", "/accounts/account-id/devices/device-id/override_codes", None),
        ("GET", "/accounts/account-id/workers/observability/destinations", None),
        ("GET", "/accounts/account-id/load_balancers/monitors", None),
        ("GET", "/accounts/account-id/rulesets/ruleset-id", None),
        ("GET", "/accounts/account-id/gateway/pacfiles", None),
        ("GET", "/zones/zone-id/logpush/edge/jobs", None),
        ("GET", "/accounts/account-id/ai-search/instances", None),
        ("GET", "/accounts/account-id/gateway/rules", None),
        ("POST", "/accounts/account-id/ai/run", {}),
        ("POST", "/accounts/account-id/urlscanner/scan", {}),
        ("POST", "/zones/zone-id/waiting_rooms/preview", {}),
        (
            "GET",
            "/accounts/account-id/magic/cloud/providers/provider-id/initial_setup",
            None,
        ),
        ("GET", "/accounts/account-id/images/v1/keys", None),
    ],
)
async def test_schema_sensitive_operations_fail_closed_before_provider_call(
    method: str,
    path: str,
    body: dict[str, object] | None,
) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"success": True, "result": "credential"})

    async with httpx.AsyncClient(
        base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(CloudflareRequestError, match="catalog-only"):
            await call_cloudflare_api(
                config=provider_config(),
                method=method,
                path=path,
                body=body,
                client=client,
            )

    assert calls == 0


@pytest.mark.asyncio
async def test_read_response_is_redacted_and_never_contains_provider_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer synthetic-provider-token"
        return httpx.Response(
            200,
            json={
                "success": True,
                "result": {
                    "id": "zone-id",
                    "token": "new-secret",
                    "streamKey": "stream-secret",
                    "stream_key": "underscore-stream-secret",
                    "cep_jwt": "signed-preview-token",
                    "private_credential": "registry-password",
                    "passphrase": "passphrase-secret",
                    "privkey": "private-key-material",
                    "key_base64": "base64-key-material",
                    "key_jwk": {"k": "jwk-key-material"},
                    "custom_key": "custom-key-material",
                    "licenseKey": "license-secret",
                    "md5_key": "routing-authentication-secret",
                    "pairing_key": "pairing-secret",
                    "cardNumber": "4111111111111111",
                    "payment_nonce": "payment-secret",
                    "validationCode": "validation-secret",
                    "invoice_pdf": "invoice-capability",
                    "signedUrl": "signed-capability",
                    "uploadURL": "upload-capability",
                    "audio_download_url": "download-capability",
                    "wsUrl": "websocket-capability",
                    "webSocketDebuggerUrl": "debugger-capability",
                    "devtoolsFrontendUrl": "devtools-capability",
                    "disable_for_time": {"1": "override-code"},
                    "headers": {"X-Credential": "header-secret"},
                    "nested": {"x-api-key": "also-secret"},
                    "message": "Authorization: Bearer should-not-escape",
                    "labeled": "license key=should-also-not-escape",
                },
            },
        )

    async with httpx.AsyncClient(
        base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await call_cloudflare_api(
            config=provider_config(),
            method="GET",
            path="/zones",
            client=client,
        )

    encoded = json.dumps(result)
    assert result["ok"] is True
    assert result["response"]["result"]["token"] == "[REDACTED]"
    assert result["response"]["result"]["streamKey"] == "[REDACTED]"
    assert result["response"]["result"]["stream_key"] == "[REDACTED]"
    assert result["response"]["result"]["cep_jwt"] == "[REDACTED]"
    assert result["response"]["result"]["private_credential"] == "[REDACTED]"
    assert result["response"]["result"]["passphrase"] == "[REDACTED]"
    assert result["response"]["result"]["privkey"] == "[REDACTED]"
    assert result["response"]["result"]["key_base64"] == "[REDACTED]"
    assert result["response"]["result"]["key_jwk"] == "[REDACTED]"
    assert result["response"]["result"]["custom_key"] == "[REDACTED]"
    for key in (
        "licenseKey",
        "md5_key",
        "pairing_key",
        "cardNumber",
        "payment_nonce",
        "validationCode",
        "invoice_pdf",
        "signedUrl",
        "uploadURL",
        "audio_download_url",
        "wsUrl",
        "webSocketDebuggerUrl",
        "devtoolsFrontendUrl",
        "disable_for_time",
        "headers",
    ):
        assert result["response"]["result"][key] == "[REDACTED]"
    assert result["response"]["result"]["nested"]["x-api-key"] == "[REDACTED]"
    assert "synthetic-provider-token" not in encoded
    assert "should-not-escape" not in encoded
    assert "should-also-not-escape" not in encoded


@pytest.mark.asyncio
async def test_provider_response_is_stream_bounded_without_partial_preview() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b'"' + (b"x" * 5000) + b'"',
        )

    async with httpx.AsyncClient(
        base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await call_cloudflare_api(
            config=provider_config(),
            method="GET",
            path="/zones",
            max_response_bytes=4096,
            client=client,
        )

    assert result["ok"] is False
    assert result["response"] is None
    assert result["response_metadata"]["body_omitted"] is True
    assert result["error"]["type"] == "provider_response_omitted"
    assert "xxxx" not in json.dumps(result)


@pytest.mark.asyncio
async def test_successful_mutation_uses_compact_outcome_envelope_below_outer_minimum() -> None:
    ledger = ApprovalLedger()
    body = {"name": "example.invalid", "account": {"id": "account-placeholder"}}
    preview = await call_cloudflare_api(
        config=provider_config(),
        method="POST",
        path="/zones",
        body=body,
        approval_signing_key=APPROVAL_KEY,
        principal_fingerprint=PRINCIPAL,
        ledger=ledger,
    )
    attestation = sign_approval_payload(preview["approval"]["approval_payload"], APPROVAL_KEY)

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"success": True, "result": {"large": "x" * 60_000}},
        )

    async with httpx.AsyncClient(
        base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await call_cloudflare_api(
            config=provider_config(),
            method="POST",
            path="/zones",
            body=body,
            approval_attestation=attestation,
            approval_signing_key=APPROVAL_KEY,
            principal_fingerprint=PRINCIPAL,
            max_response_bytes=65_536,
            client=client,
            ledger=ledger,
        )

    assert result["ok"] is True
    assert result["executed"] is True
    assert result["response"] is None
    assert result["response_metadata"]["body_omitted_by_policy"] is True
    assert len(json.dumps(result).encode()) < 16_384


@pytest.mark.asyncio
async def test_cloudflare_semantic_failure_is_not_reported_as_success() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "success": False,
                "errors": [{"code": 10000, "message": "Authentication error"}],
                "result": None,
            },
        )

    async with httpx.AsyncClient(
        base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await call_cloudflare_api(
            config=provider_config(),
            method="GET",
            path="/zones",
            client=client,
        )

    assert result["status_code"] == 200
    assert result["cloudflare_success"] is False
    assert result["ok"] is False
    assert result["error"]["type"] == "cloudflare_api_error"


@pytest.mark.asyncio
async def test_provider_transport_errors_are_normalized_without_request_details() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            f"failed request containing {request.url} and synthetic-provider-token",
            request=request,
        )

    async with httpx.AsyncClient(
        base_url=DEFAULT_CLOUDFLARE_API_BASE_URL,
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(CloudflareRequestError) as captured:
            await call_cloudflare_api(
                config=provider_config(),
                method="GET",
                path="/zones",
                query={"account": "sensitive-placeholder"},
                client=client,
            )

    rendered = str(captured.value)
    assert "failed before a reviewed response" in rendered
    assert "sensitive-placeholder" not in rendered
    assert "synthetic-provider-token" not in rendered
