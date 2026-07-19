"""Cloudflare endpoint coverage loading and matching."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib.resources import files
from typing import Any, Final, Literal, TypedDict, cast

READ_METHODS = {"GET", "HEAD", "OPTIONS"}
WRITE_METHODS = {"POST", "PUT", "PATCH"}
DESTRUCTIVE_WORDS = {
    "abort",
    "ban",
    "cancel",
    "clear",
    "deactivate",
    "delete",
    "detach",
    "disconnect",
    "disassociate",
    "destroy",
    "disable",
    "drop",
    "erase",
    "expire",
    "invalidate",
    "relinquish",
    "purge",
    "remove",
    "revoke",
    "reset",
    "restore",
    "rollback",
    "rotate",
    "stop",
    "suspend",
    "terminate",
    "unassign",
    "undeploy",
    "uninstall",
    "unpublish",
    "unregister",
    "wipe",
}
_WORD_RE = re.compile(r"[a-z0-9]+")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ACCOUNT_ADMIN_PATH_RE = re.compile(r"^/accounts(?:/move|/\{[^/{}]+\}(?:/move|/profile)?)?/?$")
_MEMBERSHIP_PATH_RE = re.compile(r"/(?:members|memberships|roles)(?=[:/]|$)")
ENDPOINT_POLICY_VERSION = "2026.07.19.3"


class ReviewedOperationOverride(TypedDict):
    """Explicit policy decision for an OpenAPI operation whose method is misleading."""

    policy_id: str
    classification: Literal["read", "write", "destructive"]
    risk_flags: tuple[str, ...]
    force_catalog_only: bool
    reason: str


_AI_WEBSOCKET_GET_PATHS: Final[tuple[str, ...]] = (
    "/accounts/{account_id}/ai/run/@cf/deepgram/aura",
    "/accounts/{account_id}/ai/run/@cf/deepgram/aura-1",
    "/accounts/{account_id}/ai/run/@cf/deepgram/aura-1-internal",
    "/accounts/{account_id}/ai/run/@cf/deepgram/aura-2",
    "/accounts/{account_id}/ai/run/@cf/deepgram/aura-2-en",
    "/accounts/{account_id}/ai/run/@cf/deepgram/aura-2-en-ws",
    "/accounts/{account_id}/ai/run/@cf/deepgram/aura-2-es",
    "/accounts/{account_id}/ai/run/@cf/deepgram/flux",
    "/accounts/{account_id}/ai/run/@cf/deepgram/nova-3",
    "/accounts/{account_id}/ai/run/@cf/deepgram/nova-3-internal",
    "/accounts/{account_id}/ai/run/@cf/deepgram/nova-3-ws",
    "/accounts/{account_id}/ai/run/@cf/nvidia/nemotron-speech-streaming-en-0.6b",
    "/accounts/{account_id}/ai/run/@cf/pipecat-ai/smart-turn-v2",
    "/accounts/{account_id}/ai/run/@cf/pipecat-ai/smart-turn-v3",
    "/accounts/{account_id}/ai/run/@cf/sven/test-pipe-http",
    "/accounts/{account_id}/ai/run/@cf/test/hello-world-cog",
)


def _ai_websocket_get_override() -> ReviewedOperationOverride:
    return {
        "policy_id": "side_effecting_get.ai_websocket_connection",
        "classification": "write",
        "risk_flags": ("side_effecting_get",),
        "force_catalog_only": True,
        "reason": (
            "Reviewed GET opens a billable WebSocket model session; the JSON dispatcher must "
            "not execute protocol-upgrade operations."
        ),
    }


def _credential_context_overrides() -> dict[tuple[str, str], ReviewedOperationOverride]:
    """Build exact catalog-only policy for credential-capable endpoint contexts."""

    groups: tuple[
        tuple[str, str, tuple[tuple[str, str], ...]],
        ...,
    ] = (
        (
            "credential_response.zero_trust_override_codes",
            "One-time admin override codes have numeric or arbitrary-map field names that the "
            "generic dispatcher cannot safely project.",
            (
                (
                    "GET",
                    "/accounts/{account_id}/devices/registrations/{registration_id}/override_codes",
                ),
                ("GET", "/accounts/{account_id}/devices/{device_id}/override_codes"),
            ),
        ),
        (
            "credential_configuration.workers_observability_headers",
            "Workers Observability destination headers store collector API keys and tokens under "
            "arbitrary names; generic transport and redaction are not safe projections.",
            (
                ("GET", "/accounts/{account_id}/workers/observability/destinations"),
                ("POST", "/accounts/{account_id}/workers/observability/destinations"),
                (
                    "PATCH",
                    "/accounts/{account_id}/workers/observability/destinations/{slug}",
                ),
            ),
        ),
        (
            "credential_configuration.outbound_health_headers",
            "Outbound monitor, health-check, and trace header values may contain origin "
            "authentication or pre-shared keys under arbitrary names.",
            (
                ("GET", "/accounts/{account_id}/load_balancers/monitors"),
                ("POST", "/accounts/{account_id}/load_balancers/monitors"),
                ("GET", "/accounts/{account_id}/load_balancers/monitors/{monitor_id}"),
                ("PATCH", "/accounts/{account_id}/load_balancers/monitors/{monitor_id}"),
                ("PUT", "/accounts/{account_id}/load_balancers/monitors/{monitor_id}"),
                (
                    "POST",
                    "/accounts/{account_id}/load_balancers/monitors/{monitor_id}/preview",
                ),
                (
                    "POST",
                    "/accounts/{account_id}/load_balancers/pools/{pool_id}/preview",
                ),
                ("GET", "/user/load_balancers/monitors"),
                ("POST", "/user/load_balancers/monitors"),
                ("GET", "/user/load_balancers/monitors/{monitor_id}"),
                ("PATCH", "/user/load_balancers/monitors/{monitor_id}"),
                ("PUT", "/user/load_balancers/monitors/{monitor_id}"),
                ("POST", "/user/load_balancers/monitors/{monitor_id}/preview"),
                ("POST", "/user/load_balancers/pools/{pool_id}/preview"),
                ("GET", "/zones/{zone_id}/healthchecks"),
                ("POST", "/zones/{zone_id}/healthchecks"),
                ("POST", "/zones/{zone_id}/healthchecks/preview"),
                ("GET", "/zones/{zone_id}/healthchecks/preview/{healthcheck_id}"),
                ("GET", "/zones/{zone_id}/healthchecks/{healthcheck_id}"),
                ("PATCH", "/zones/{zone_id}/healthchecks/{healthcheck_id}"),
                ("PUT", "/zones/{zone_id}/healthchecks/{healthcheck_id}"),
                ("GET", "/zones/{zone_id}/smart_shield/healthchecks"),
                ("POST", "/zones/{zone_id}/smart_shield/healthchecks"),
                (
                    "GET",
                    "/zones/{zone_id}/smart_shield/healthchecks/{healthcheck_id}",
                ),
                (
                    "PATCH",
                    "/zones/{zone_id}/smart_shield/healthchecks/{healthcheck_id}",
                ),
                (
                    "PUT",
                    "/zones/{zone_id}/smart_shield/healthchecks/{healthcheck_id}",
                ),
                ("POST", "/accounts/{account_id}/request-tracer/trace"),
            ),
        ),
        (
            "credential_configuration.ruleset_rewrite_headers",
            "Ruleset static request-header rewrite values can contain origin credentials and "
            "read operations can return those stored values.",
            (
                ("POST", "/accounts/{account_id}/rulesets"),
                (
                    "GET",
                    "/accounts/{account_id}/rulesets/phases/{ruleset_phase}/entrypoint",
                ),
                (
                    "PUT",
                    "/accounts/{account_id}/rulesets/phases/{ruleset_phase}/entrypoint",
                ),
                (
                    "GET",
                    "/accounts/{account_id}/rulesets/phases/{ruleset_phase}/entrypoint/versions/"
                    "{ruleset_version}",
                ),
                ("GET", "/accounts/{account_id}/rulesets/{ruleset_id}"),
                ("PUT", "/accounts/{account_id}/rulesets/{ruleset_id}"),
                ("POST", "/accounts/{account_id}/rulesets/{ruleset_id}/rules"),
                (
                    "DELETE",
                    "/accounts/{account_id}/rulesets/{ruleset_id}/rules/{rule_id}",
                ),
                (
                    "PATCH",
                    "/accounts/{account_id}/rulesets/{ruleset_id}/rules/{rule_id}",
                ),
                (
                    "GET",
                    "/accounts/{account_id}/rulesets/{ruleset_id}/versions/{ruleset_version}",
                ),
                (
                    "GET",
                    "/accounts/{account_id}/rulesets/{ruleset_id}/versions/{ruleset_version}/"
                    "by_tag/{rule_tag}",
                ),
                ("POST", "/zones/{zone_id}/rulesets"),
                (
                    "GET",
                    "/zones/{zone_id}/rulesets/phases/{ruleset_phase}/entrypoint",
                ),
                (
                    "PUT",
                    "/zones/{zone_id}/rulesets/phases/{ruleset_phase}/entrypoint",
                ),
                (
                    "GET",
                    "/zones/{zone_id}/rulesets/phases/{ruleset_phase}/entrypoint/versions/"
                    "{ruleset_version}",
                ),
                ("GET", "/zones/{zone_id}/rulesets/{ruleset_id}"),
                ("PUT", "/zones/{zone_id}/rulesets/{ruleset_id}"),
                ("POST", "/zones/{zone_id}/rulesets/{ruleset_id}/rules"),
                (
                    "DELETE",
                    "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
                ),
                ("PATCH", "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}"),
                (
                    "GET",
                    "/zones/{zone_id}/rulesets/{ruleset_id}/versions/{ruleset_version}",
                ),
                (
                    "GET",
                    "/zones/{zone_id}/rulesets/{ruleset_id}/versions/{ruleset_version}/by_tag/"
                    "{rule_tag}",
                ),
            ),
        ),
        (
            "credential_response.pac_download_url",
            "PAC file operations return unique download URLs that require an endpoint-specific "
            "safe projection.",
            (
                ("GET", "/accounts/{account_id}/gateway/pacfiles"),
                ("POST", "/accounts/{account_id}/gateway/pacfiles"),
                ("GET", "/accounts/{account_id}/gateway/pacfiles/{pacfile_id}"),
                ("PUT", "/accounts/{account_id}/gateway/pacfiles/{pacfile_id}"),
            ),
        ),
        (
            "credential_response.instant_logs_session",
            "Instant Logs destination configuration contains a direct WebSocket session address.",
            (
                ("GET", "/zones/{zone_id}/logpush/edge/jobs"),
                ("POST", "/zones/{zone_id}/logpush/edge/jobs"),
            ),
        ),
        (
            "credential_configuration.ai_search_headers",
            "AI Search crawl headers can contain origin credentials under arbitrary names and "
            "are stored in instance responses.",
            (
                ("GET", "/accounts/{account_id}/ai-search/instances"),
                ("POST", "/accounts/{account_id}/ai-search/instances"),
                ("DELETE", "/accounts/{account_id}/ai-search/instances/{id}"),
                ("GET", "/accounts/{account_id}/ai-search/instances/{id}"),
                ("PUT", "/accounts/{account_id}/ai-search/instances/{id}"),
                (
                    "GET",
                    "/accounts/{account_id}/ai-search/namespaces/{name}/instances",
                ),
                (
                    "POST",
                    "/accounts/{account_id}/ai-search/namespaces/{name}/instances",
                ),
                (
                    "DELETE",
                    "/accounts/{account_id}/ai-search/namespaces/{name}/instances/{id}",
                ),
                (
                    "GET",
                    "/accounts/{account_id}/ai-search/namespaces/{name}/instances/{id}",
                ),
                (
                    "PUT",
                    "/accounts/{account_id}/ai-search/namespaces/{name}/instances/{id}",
                ),
            ),
        ),
        (
            "credential_configuration.gateway_rule_headers",
            "Gateway rule add_headers values can inject credentials into allowed requests and "
            "are returned by rule reads.",
            (
                ("GET", "/accounts/{account_id}/gateway/rules"),
                ("PATCH", "/accounts/{account_id}/gateway/rules"),
                ("POST", "/accounts/{account_id}/gateway/rules"),
                ("GET", "/accounts/{account_id}/gateway/rules/tenant"),
                ("GET", "/accounts/{account_id}/gateway/rules/{rule_id}"),
                ("PATCH", "/accounts/{account_id}/gateway/rules/{rule_id}"),
                ("PUT", "/accounts/{account_id}/gateway/rules/{rule_id}"),
                (
                    "POST",
                    "/accounts/{account_id}/gateway/rules/{rule_id}/reset_expiration",
                ),
            ),
        ),
        (
            "credential_configuration.ai_provider_headers",
            "Generic AI model extra headers can carry provider credentials under arbitrary names.",
            (("POST", "/accounts/{account_id}/ai/run"),),
        ),
        (
            "credential_configuration.url_scanner_headers",
            "URL Scanner custom outbound headers can carry target credentials under arbitrary "
            "names.",
            (
                ("POST", "/accounts/{account_id}/urlscanner/scan"),
                ("POST", "/accounts/{account_id}/urlscanner/v2/bulk"),
                ("POST", "/accounts/{account_id}/urlscanner/v2/scan"),
            ),
        ),
        (
            "credential_response.waiting_room_preview_url",
            "Waiting Room preview returns a temporary privileged preview URL.",
            (("POST", "/zones/{zone_id}/waiting_rooms/preview"),),
        ),
        (
            "credential_response.azure_consent_url",
            "Magic Cloud initial setup returns a provider-consent URL in a credential setup flow.",
            (
                (
                    "GET",
                    "/accounts/{account_id}/magic/cloud/providers/{provider_id}/initial_setup",
                ),
            ),
        ),
        (
            "credential_response.image_signing_key",
            "Images signing-key operations expose raw key material under a generic value field.",
            (
                ("GET", "/accounts/{account_id}/images/v1/keys"),
                ("DELETE", "/accounts/{account_id}/images/v1/keys/{signing_key_name}"),
                ("PUT", "/accounts/{account_id}/images/v1/keys/{signing_key_name}"),
            ),
        ),
    )

    overrides: dict[tuple[str, str], ReviewedOperationOverride] = {}
    for policy_id, reason, operations in groups:
        for method, path_template in operations:
            key = (method, path_template)
            if key in overrides:
                raise RuntimeError(
                    f"Duplicate credential context override: {method} {path_template}"
                )
            classification: Literal["read", "write", "destructive"]
            if method == "GET":
                classification = "read"
            elif method == "DELETE" or path_template.endswith("/reset_expiration"):
                classification = "destructive"
            else:
                classification = "write"
            overrides[key] = {
                "policy_id": policy_id,
                "classification": classification,
                "risk_flags": ("credentials",),
                "force_catalog_only": True,
                "reason": reason,
            }
    return overrides


_CREDENTIAL_CONTEXT_OVERRIDES: Final[dict[tuple[str, str], ReviewedOperationOverride]] = (
    _credential_context_overrides()
)


REVIEWED_OPERATION_OVERRIDES: Final[dict[tuple[str, str], ReviewedOperationOverride]] = {
    **{("GET", path): _ai_websocket_get_override() for path in _AI_WEBSOCKET_GET_PATHS},
    **_CREDENTIAL_CONTEXT_OVERRIDES,
    (
        "GET",
        "/accounts/{account_id}/alerting/v3/destinations/pagerduty/connect/{token_id}",
    ): {
        "policy_id": "side_effecting_get.pagerduty_connect",
        "classification": "write",
        "risk_flags": ("credentials", "side_effecting_get"),
        "force_catalog_only": False,
        "reason": (
            "Reviewed GET performs the PagerDuty connection action; require the mutation and "
            "high-risk gates."
        ),
    },
    (
        "GET",
        "/accounts/{account_id}/browser-rendering/devtools/browser",
    ): {
        "policy_id": "side_effecting_get.browser_session_acquire",
        "classification": "write",
        "risk_flags": ("side_effecting_get",),
        "force_catalog_only": True,
        "reason": (
            "Reviewed GET acquires a browser session and upgrades to WebSocket; the JSON "
            "dispatcher must not execute it."
        ),
    },
    (
        "GET",
        "/accounts/{account_id}/browser-rendering/devtools/browser/{session_id}",
    ): {
        "policy_id": "side_effecting_get.browser_session_connect",
        "classification": "write",
        "risk_flags": ("side_effecting_get",),
        "force_catalog_only": True,
        "reason": (
            "Reviewed GET connects to a browser session and upgrades to WebSocket; the JSON "
            "dispatcher must not execute it."
        ),
    },
    (
        "GET",
        "/accounts/{account_id}/browser-rendering/devtools/browser/{session_id}/json/activate/"
        "{target_id}",
    ): {
        "policy_id": "side_effecting_get.browser_target_activate",
        "classification": "write",
        "risk_flags": ("side_effecting_get",),
        "force_catalog_only": False,
        "reason": (
            "Reviewed GET activates a browser target; require the mutation and high-risk gates."
        ),
    },
    (
        "GET",
        "/accounts/{account_id}/browser-rendering/devtools/browser/{session_id}/json/close/"
        "{target_id}",
    ): {
        "policy_id": "side_effecting_get.browser_target_close",
        "classification": "destructive",
        "risk_flags": ("side_effecting_get",),
        "force_catalog_only": False,
        "reason": (
            "Reviewed GET closes a browser target; require the destructive and high-risk gates."
        ),
    },
    (
        "GET",
        "/accounts/{account_id}/browser-rendering/devtools/browser/{session_id}/page/{target_id}",
    ): {
        "policy_id": "side_effecting_get.browser_page_connect",
        "classification": "write",
        "risk_flags": ("side_effecting_get",),
        "force_catalog_only": True,
        "reason": (
            "Reviewed GET connects to a DevTools page and upgrades to WebSocket; the JSON "
            "dispatcher must not execute it."
        ),
    },
    (
        "GET",
        "/accounts/{account_id}/cni/interconnects/{icon}/loa",
    ): {
        "policy_id": "side_effecting_get.interconnect_loa_generate",
        "classification": "write",
        "risk_flags": ("side_effecting_get",),
        "force_catalog_only": True,
        "reason": (
            "Reviewed GET generates a Letter of Authorization document; the generic JSON "
            "dispatcher must not trigger document generation through read semantics."
        ),
    },
    (
        "GET",
        "/accounts/{account_id}/email-security/investigate",
    ): {
        "policy_id": "response_header.location_continuation",
        "classification": "read",
        "risk_flags": (),
        "force_catalog_only": True,
        "reason": (
            "The 202 response requires its Location header to poll for results, but the generic "
            "dispatcher intentionally omits provider response headers."
        ),
    },
    (
        "POST",
        "/accounts/{account_id}/teamnet/routes/network/{ip_network_encoded}",
    ): {
        "policy_id": "transport.path_encoded_cidr_unsupported",
        "classification": "write",
        "risk_flags": (),
        "force_catalog_only": True,
        "reason": (
            "The CIDR path value requires an encoded slash, which the reviewed path normalizer "
            "rejects to prevent ambiguous path traversal."
        ),
    },
    (
        "PATCH",
        "/accounts/{account_id}/teamnet/routes/network/{ip_network_encoded}",
    ): {
        "policy_id": "transport.path_encoded_cidr_unsupported",
        "classification": "write",
        "risk_flags": (),
        "force_catalog_only": True,
        "reason": (
            "The CIDR path value requires an encoded slash, which the reviewed path normalizer "
            "rejects to prevent ambiguous path traversal."
        ),
    },
    (
        "DELETE",
        "/accounts/{account_id}/teamnet/routes/network/{ip_network_encoded}",
    ): {
        "policy_id": "transport.path_encoded_cidr_unsupported",
        "classification": "destructive",
        "risk_flags": (),
        "force_catalog_only": True,
        "reason": (
            "The CIDR path value requires an encoded slash, which the reviewed path normalizer "
            "rejects to prevent ambiguous path traversal."
        ),
    },
    (
        "GET",
        "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token",
    ): {
        "policy_id": "credential_response.cloudflare_tunnel_token",
        "classification": "read",
        "risk_flags": ("credentials",),
        "force_catalog_only": True,
        "reason": (
            "Credential-returning operation; generic redaction cannot safely project a scalar "
            "tunnel token."
        ),
    },
    (
        "GET",
        "/accounts/{account_id}/containers/instances/{instance_id}/ssh",
    ): {
        "policy_id": "credential_response.container_ssh",
        "classification": "read",
        "risk_flags": ("credentials",),
        "force_catalog_only": True,
        "reason": (
            "Credential-returning operation; SSH connection material requires an "
            "endpoint-specific safe projection."
        ),
    },
    (
        "GET",
        "/accounts/{account_id}/warp_connector/{tunnel_id}/token",
    ): {
        "policy_id": "credential_response.warp_connector_token",
        "classification": "read",
        "risk_flags": ("credentials",),
        "force_catalog_only": True,
        "reason": (
            "Credential-returning operation; generic redaction cannot safely project a scalar "
            "WARP connector token."
        ),
    },
}


class CoverageOperation(TypedDict):
    """Generated metadata for one Cloudflare OpenAPI operation."""

    method: str
    path_template: str
    feature_area: str
    tags: list[str]
    operation_id: str
    summary: str
    classification: str
    risk_flags: list[str]
    high_risk: bool
    request_content_types: list[str]
    request_body_required: bool
    required_provider_headers: list[str]
    token_auth_compatible: bool
    auth_compatibility_evidence: str
    unconstrained_request_json_schema: bool
    success_response_content_types: list[str]
    declared_success_response: bool
    ambiguous_bodyless_success_response: bool
    unconstrained_success_json_schema: bool
    transport_support: str
    auth_config_required: str
    mcp_tool: str | None
    coverage_status: str
    notes: str
    policy_override: str | None
    policy_reason: str | None
    sensitive_request_schema: bool
    sensitive_success_response_schema: bool
    sensitive_schema_findings: list[dict[str, str]]
    schema_policy_id: str | None
    schema_policy_reason: str | None


class CoverageQueryResult(TypedDict):
    """Paginated result returned by the endpoint catalog."""

    source: dict[str, Any]
    operation_count: int
    filtered_count: int
    limit: int
    offset: int
    operations: list[CoverageOperation]


def _word_tokens(text: str) -> tuple[str, ...]:
    """Tokenize prose, paths, snake case, kebab case, and camel case exactly."""

    expanded = _CAMEL_BOUNDARY_RE.sub(" ", text)
    return tuple(_WORD_RE.findall(expanded.casefold()))


def _contains_phrase(tokens: tuple[str, ...], phrase: tuple[str, ...]) -> bool:
    width = len(phrase)
    return any(tokens[index : index + width] == phrase for index in range(len(tokens) - width + 1))


def reviewed_operation_override(
    method: str, path_template: str
) -> ReviewedOperationOverride | None:
    """Return the exact reviewed policy override for one method/path pair."""

    return REVIEWED_OPERATION_OVERRIDES.get((method.upper(), path_template))


def classify_operation(method: str, text: str = "") -> str:
    """Classify an operation as read, write, or destructive."""

    normalized_method = method.upper()
    if normalized_method == "DELETE":
        return "destructive"
    if normalized_method in READ_METHODS:
        return "read"
    if set(_word_tokens(text)) & DESTRUCTIVE_WORDS:
        return "destructive"
    if normalized_method in WRITE_METHODS:
        return "write"
    return "write"


def operation_risk_flags(
    method: str,
    *,
    summary: str = "",
    operation_id: str = "",
    path_template: str = "",
) -> list[str]:
    """Return stable high-risk categories for a non-read operation."""

    if method.upper() in READ_METHODS:
        return []

    semantic_tokens = _word_tokens(f"{summary} {operation_id}")
    path_tokens = _word_tokens(path_template)
    all_tokens = semantic_tokens + path_tokens
    token_set = set(all_tokens)
    flags: list[str] = []

    credential_terms = {
        "credential",
        "credentials",
        "password",
        "passwords",
        "secret",
        "secrets",
        "token",
        "tokens",
    }
    semantic_token_set = set(semantic_tokens)
    key_terms = {"key", "keys"}
    data_key_context = {
        "kv",
        "namespace",
        "namespaces",
        "object",
        "objects",
        "value",
        "values",
    }
    key_is_sensitive = (
        bool(semantic_token_set & key_terms)
        and not bool(semantic_token_set & data_key_context)
        and not ("list" in semantic_token_set and len(semantic_token_set & key_terms) == 1)
    )
    if token_set & credential_terms or key_is_sensitive:
        flags.append("credentials")

    commerce_terms = {
        "billing",
        "billings",
        "payment",
        "payments",
        "purchase",
        "purchases",
        "registrar",
        "registrars",
        "topup",
        "topups",
    }
    paid_subscription_path = bool(
        re.fullmatch(
            r"/(?:accounts/\{[^/{}]+\}|user)/subscriptions(?:/[^/]+)?|"
            r"/zones/\{[^/{}]+\}/subscription",
            path_template.rstrip("/"),
        )
    )
    order_operation = "order" in semantic_token_set and (
        semantic_tokens[:1] == ("order",)
        or bool(semantic_token_set & {"billing", "certificate", "domain", "payment", "purchase"})
    )
    if (
        token_set & commerce_terms
        or paid_subscription_path
        or order_operation
        or _contains_phrase(all_tokens, ("top", "up"))
        or _contains_phrase(all_tokens, ("domain", "registration"))
        or _contains_phrase(all_tokens, ("domain", "registrations"))
    ):
        flags.append("billing_or_commerce")

    normalized_path = path_template.rstrip("/") or "/"
    ownership_actions = {
        "assign",
        "change",
        "delete",
        "move",
        "remove",
        "replace",
        "set",
        "transfer",
        "update",
    }
    account_admin = bool(_ACCOUNT_ADMIN_PATH_RE.fullmatch(normalized_path))
    membership_admin = bool(_MEMBERSHIP_PATH_RE.search(normalized_path))
    iam_admin = "/iam/" in normalized_path
    ownership_admin = "ownership" in semantic_tokens and bool(
        set(semantic_tokens) & ownership_actions
    )
    if account_admin or membership_admin or iam_admin or ownership_admin:
        flags.append("account_administration")

    return flags


@lru_cache(maxsize=1)
def load_coverage() -> dict[str, Any]:
    """Load generated endpoint coverage data from package resources."""

    coverage_path = files("cloudflare_mcp.data").joinpath("endpoint_coverage.json")
    with coverage_path.open("r", encoding="utf-8") as handle:
        return cast(dict[str, Any], json.load(handle))


def query_coverage(
    *,
    feature_area: str | None = None,
    method: str | None = None,
    path_contains: str | None = None,
    classification: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> CoverageQueryResult:
    """Return a filtered slice of the generated endpoint coverage matrix."""

    data = load_coverage()
    operations = cast(list[CoverageOperation], data["operations"])
    filtered = operations

    if feature_area:
        needle = feature_area.casefold()
        filtered = [
            op
            for op in filtered
            if needle in op["feature_area"].casefold()
            or any(needle in tag.casefold() for tag in op.get("tags", []))
        ]
    if method:
        normalized_method = method.upper()
        filtered = [op for op in filtered if op["method"] == normalized_method]
    if path_contains:
        needle = path_contains.casefold()
        filtered = [op for op in filtered if needle in op["path_template"].casefold()]
    if classification:
        filtered = [op for op in filtered if op["classification"] == classification]

    safe_limit = min(max(limit, 1), 200)
    safe_offset = max(offset, 0)
    page = filtered[safe_offset : safe_offset + safe_limit]

    return {
        "source": data["source"],
        "operation_count": data["operation_count"],
        "filtered_count": len(filtered),
        "limit": safe_limit,
        "offset": safe_offset,
        "operations": page,
    }


def path_template_to_regex(path_template: str) -> re.Pattern[str]:
    """Convert an OpenAPI path template into a matcher for concrete paths."""

    escaped = re.escape(path_template)
    pattern = re.sub(r"\\\{[^/]+\\\}", r"[^/]+", escaped)
    return re.compile(f"^{pattern}$")


@lru_cache(maxsize=4096)
def _compiled_path(path_template: str) -> re.Pattern[str]:
    return path_template_to_regex(path_template)


def find_operation(method: str, path: str) -> CoverageOperation | None:
    """Find the generated coverage operation matching a concrete request path."""

    normalized_method = method.upper()
    matches: list[CoverageOperation] = []
    for operation in load_coverage()["operations"]:
        if operation["method"] != normalized_method:
            continue
        if _compiled_path(operation["path_template"]).match(path):
            matches.append(cast(CoverageOperation, operation))
    if not matches:
        return None

    def specificity(operation: CoverageOperation) -> int:
        return sum(
            not (segment.startswith("{") and segment.endswith("}"))
            for segment in operation["path_template"].split("/")
        )

    highest_specificity = max(specificity(operation) for operation in matches)
    best_matches = [
        operation for operation in matches if specificity(operation) == highest_specificity
    ]
    return best_matches[0] if len(best_matches) == 1 else None
