from __future__ import annotations

from cloudflare_mcp.coverage import (
    ENDPOINT_POLICY_VERSION,
    REVIEWED_OPERATION_OVERRIDES,
    classify_operation,
    find_operation,
    load_coverage,
    operation_risk_flags,
    query_coverage,
    reviewed_operation_override,
)


def test_generated_coverage_loads_official_schema_inventory() -> None:
    coverage = load_coverage()

    assert coverage["source"]["provider"] == "Cloudflare"
    assert coverage["source"]["openapi"] == "3.0.3"
    assert coverage["source"]["commit"] == "aefa753f1190c85866f65dcc7f348e18c7a1ca4a"
    assert (
        coverage["source"]["sha256"]
        == "6c141cf38b45a514fcba04d322d43916eaba179a4442c8d91afaf5e7a66c8f1f"
    )
    assert coverage["source"]["license"] == "BSD-3-Clause"
    assert coverage["operation_count"] == 3148
    assert coverage["policy_version"] == ENDPOINT_POLICY_VERSION == "2026.07.19.3"
    assert coverage["reviewed_override_count"] == len(REVIEWED_OPERATION_OVERRIDES) == 117
    assert coverage["classification_counts"] == {
        "destructive": 448,
        "read": 1499,
        "write": 1201,
    }
    assert coverage["coverage_status_counts"] == {"callable": 2356, "catalog_only": 792}
    assert coverage["catalog_only_reason_counts"] == {
        "ambiguous_bodyless_success_response": 15,
        "incompatible_bearer_token_auth": 87,
        "no_declared_success_response": 49,
        "required_provider_headers": 2,
        "reviewed_policy_override": 114,
        "sensitive_schema": 263,
        "unconstrained_request_json_schema": 127,
        "unconstrained_success_json_schema": 120,
        "unsupported_request_media": 41,
        "unsupported_success_response_media": 103,
    }
    assert coverage["sensitive_schema_operation_count"] == 263
    assert coverage["sensitive_request_schema_operation_count"] == 104
    assert coverage["sensitive_success_response_schema_operation_count"] == 206
    assert coverage["sensitive_schema_signal_operation_counts"] == {
        "credential_like_read_only": 1,
        "credential_like_write_only": 53,
        "credential_semantics": 172,
        "format_password": 2,
        "x_sensitive": 172,
    }
    assert coverage["high_risk_operation_count"] == 469
    assert coverage["risk_flag_counts"] == {
        "account_administration": 25,
        "billing_or_commerce": 18,
        "credentials": 405,
        "side_effecting_get": 23,
    }

    approval_gated = [
        operation
        for operation in coverage["operations"]
        if operation["coverage_status"] == "callable" and operation["classification"] != "read"
    ]
    assert approval_gated
    assert all(1 <= len(operation["operation_id"]) <= 256 for operation in approval_gated)
    assert all(operation["operation_id"] for operation in coverage["operations"])


def test_query_coverage_filters_by_method_and_path() -> None:
    page = query_coverage(method="GET", path_contains="/accounts", limit=5)

    assert page["filtered_count"] > 0
    assert page["operations"]
    assert all(operation["method"] == "GET" for operation in page["operations"])
    assert all("/accounts" in operation["path_template"] for operation in page["operations"])


def test_residual_pinned_contract_mismatches_are_fail_closed() -> None:
    operations = load_coverage()["operations"]
    by_key = {(row["method"], row["path_template"]): row for row in operations}

    raw_log_paths = (
        "/accounts/{account_id}/ai-gateway/gateways/{gateway_id}/logs/{id}/request",
        "/accounts/{account_id}/ai-gateway/gateways/{gateway_id}/logs/{id}/response",
    )
    for path in raw_log_paths:
        row = by_key[("GET", path)]
        assert row["unconstrained_success_json_schema"] is True
        assert row["coverage_status"] == "catalog_only"

    md5_paths = (
        "/accounts/{account_id}/cni/cnis",
        "/accounts/{account_id}/cni/cnis/{cni}",
        "/accounts/{account_id}/magic/gre_tunnels",
        "/accounts/{account_id}/magic/gre_tunnels/{gre_tunnel_id}",
        "/accounts/{account_id}/magic/ipsec_tunnels",
        "/accounts/{account_id}/magic/ipsec_tunnels/{ipsec_tunnel_id}",
    )
    for path in md5_paths:
        row = by_key[("GET", path)]
        assert row["coverage_status"] == "catalog_only"
        assert any("md5_key" in finding["location"] for finding in row["sensitive_schema_findings"])

    r2 = by_key[("PATCH", "/accounts/{account_id}/r2/buckets/{bucket_name}")]
    stream = by_key[("POST", "/accounts/{account_id}/stream")]
    assert r2["required_provider_headers"] == ["cf-r2-storage-class"]
    assert stream["required_provider_headers"] == ["Tus-Resumable", "Upload-Length"]
    assert r2["coverage_status"] == stream["coverage_status"] == "catalog_only"

    binary = by_key[("GET", "/accounts/{account_id}/cloudforce-one/binary/{hash}")]
    assert binary["ambiguous_bodyless_success_response"] is True
    assert binary["coverage_status"] == "catalog_only"

    incompatible_auth = [row for row in operations if not row["token_auth_compatible"]]
    assert len(incompatible_auth) == 87
    assert all(row["coverage_status"] == "catalog_only" for row in incompatible_auth)

    investigate = by_key[("GET", "/accounts/{account_id}/email-security/investigate")]
    assert investigate["policy_override"] == "response_header.location_continuation"
    assert investigate["coverage_status"] == "catalog_only"

    encoded_cidr_path = "/accounts/{account_id}/teamnet/routes/network/{ip_network_encoded}"
    for method in ("POST", "PATCH", "DELETE"):
        row = by_key[(method, encoded_cidr_path)]
        assert row["policy_override"] == "transport.path_encoded_cidr_unsupported"
        assert row["coverage_status"] == "catalog_only"


def test_find_operation_matches_openapi_path_templates() -> None:
    operation = find_operation("GET", "/accounts/example-account-id")

    assert operation is not None
    assert operation["path_template"] == "/accounts/{account_id}"
    assert operation["classification"] == "read"
    assert operation["coverage_status"] == "callable"


def test_find_operation_prefers_static_routes_and_rejects_equal_specificity_ambiguity() -> None:
    static = find_operation("GET", "/zones/example-zone/dns_records/export")
    ambiguous = find_operation("DELETE", "/accounts/example-account/stream/keys/downloads")

    assert static is not None
    assert static["path_template"] == "/zones/{zone_id}/dns_records/export"
    assert static["coverage_status"] == "catalog_only"
    assert ambiguous is None


def test_catalog_only_operations_explain_unsupported_transport() -> None:
    upload = find_operation("POST", "/accounts/example-account-id/images/v1")
    download = find_operation(
        "GET",
        "/accounts/example-account-id/addressing/loa_documents/example-document/download",
    )

    assert upload is not None
    assert upload["request_content_types"] == ["multipart/form-data"]
    assert upload["transport_support"] == "catalog_only"
    assert upload["coverage_status"] == "catalog_only"
    assert upload["mcp_tool"] is None
    assert "unsupported request media types" in upload["notes"]

    assert download is not None
    assert download["success_response_content_types"] == ["application/pdf"]
    assert download["coverage_status"] == "catalog_only"
    assert "unsupported successful-response media types" in download["notes"]


def test_every_sensitive_schema_operation_is_fail_closed() -> None:
    sensitive = [
        operation
        for operation in load_coverage()["operations"]
        if operation["sensitive_schema_findings"]
    ]

    assert len(sensitive) == 263
    for operation in sensitive:
        assert operation["coverage_status"] == "catalog_only"
        assert operation["transport_support"] == "catalog_only"
        assert operation["mcp_tool"] is None
        assert operation["high_risk"] is True
        assert "credentials" in operation["risk_flags"]
        assert operation["schema_policy_id"] == "schema.credentials.no_generic_projection"
        assert "endpoint-specific safe projection" in operation["schema_policy_reason"]


def test_required_sensitive_provider_contracts_are_catalog_only() -> None:
    expected = {
        (
            "GET",
            "/accounts/example-account/stream/live_inputs/example-live-input",
        ): (False, True, "x_sensitive"),
        (
            "POST",
            "/accounts/example-account/stream/live_inputs",
        ): (False, True, "x_sensitive"),
        (
            "POST",
            "/accounts/example-account/challenges/widgets",
        ): (False, True, "x_sensitive"),
        (
            "GET",
            "/zones/example-zone/dnssec/zsk",
        ): (False, True, "credential_like_read_only"),
        (
            "POST",
            "/accounts/example-account/dlp/datasets",
        ): (False, True, "format_password"),
        (
            "POST",
            "/accounts/example-account/intel/sinkholes",
        ): (True, False, "credential_like_write_only"),
        (
            "POST",
            "/accounts/example-account/realtime/kit/example-app/recordings",
        ): (True, True, "credential_like_write_only"),
        (
            "POST",
            "/accounts/example-account/vuln_scanner/credential_sets/example-set/credentials",
        ): (True, False, "x_sensitive"),
    }

    for (method, path), (request_sensitive, response_sensitive, signal) in expected.items():
        operation = find_operation(method, path)
        assert operation is not None
        assert operation["coverage_status"] == "catalog_only"
        assert operation["mcp_tool"] is None
        assert operation["sensitive_request_schema"] is request_sensitive
        assert operation["sensitive_success_response_schema"] is response_sensitive
        assert signal in {finding["signal"] for finding in operation["sensitive_schema_findings"]}


def test_reviewed_unmarked_credential_contracts_are_catalog_only() -> None:
    expected = {
        ("GET", "/accounts/example/addressing/prefixes"),
        ("POST", "/accounts/example/addressing/prefixes"),
        ("GET", "/accounts/example/addressing/prefixes/prefix-id"),
        ("PATCH", "/accounts/example/addressing/prefixes/prefix-id"),
        ("POST", "/accounts/example/addressing/prefixes/prefix-id/validate"),
        ("GET", "/accounts/example/realtime/kit/app/livestreams"),
        ("POST", "/accounts/example/realtime/kit/app/livestreams"),
        ("GET", "/accounts/example/realtime/kit/app/livestreams/live"),
        (
            "GET",
            "/accounts/example/realtime/kit/app/livestreams/live/active-livestream-session",
        ),
        ("GET", "/accounts/example/realtime/kit/app/meetings/meeting/active-livestream"),
        ("GET", "/accounts/example/realtime/kit/app/meetings/meeting/livestream"),
        ("POST", "/accounts/example/realtime/kit/app/meetings/meeting/livestreams"),
        ("POST", "/accounts/example/realtime/kit/app/meetings/meeting/participants"),
        (
            "PATCH",
            "/accounts/example/realtime/kit/app/meetings/meeting/participants/participant",
        ),
        (
            "PUT",
            "/accounts/example/realtime/kit/app/meetings/meeting/participants/participant",
        ),
        ("POST", "/accounts/example/ai-gateway/gateways/gateway/provider_configs"),
        ("PUT", "/accounts/example/ai-gateway/gateways/gateway/provider_configs/config"),
        ("POST", "/accounts/example/pipelines"),
        ("PUT", "/accounts/example/pipelines/pipeline"),
        ("POST", "/accounts/example/containers/registries"),
        (
            "GET",
            "/accounts/example/alerting/v3/destinations/pagerduty/connect/integration-token",
        ),
        ("POST", "/accounts/example/builds/tokens"),
        ("POST", "/accounts/example/r2-catalog/bucket/credential"),
        ("POST", "/accounts/example/custom_pages/preview_tokens"),
        ("POST", "/zones/example/custom_pages/preview_tokens"),
        ("POST", "/accounts/example/ai-gateway/billing/topup"),
        ("POST", "/accounts/example/containers/registries/domain/credentials"),
        (
            "POST",
            "/accounts/example/realtime/kit/app/meetings/meeting/participants/participant/token",
        ),
        ("GET", "/accounts/example/realtime/kit/app/meetings"),
        ("POST", "/accounts/example/realtime/kit/app/meetings"),
        ("GET", "/accounts/example/realtime/kit/app/meetings/meeting"),
        ("PATCH", "/accounts/example/realtime/kit/app/meetings/meeting"),
        ("PUT", "/accounts/example/realtime/kit/app/meetings/meeting"),
        ("GET", "/accounts/example/realtime/kit/app/recordings"),
        ("POST", "/accounts/example/realtime/kit/app/recordings"),
        ("GET", "/accounts/example/realtime/kit/app/recordings/recording"),
        ("PUT", "/accounts/example/realtime/kit/app/recordings/recording"),
        ("GET", "/zones/example/access/apps"),
        ("POST", "/zones/example/access/apps"),
        ("GET", "/zones/example/access/apps/app"),
        ("PUT", "/zones/example/access/apps/app"),
        ("GET", "/zones/example/dnssec/zsk"),
        ("POST", "/accounts/example/intel/sinkholes"),
        ("PUT", "/accounts/example/intel/sinkholes/sinkhole"),
    }

    assert len(expected) == 44
    for method, path in expected:
        operation = find_operation(method, path)
        assert operation is not None, (method, path)
        assert operation["coverage_status"] == "catalog_only", (method, path)
        assert operation["mcp_tool"] is None, (method, path)
        assert operation["high_risk"] is True, (method, path)
        assert "credentials" in operation["risk_flags"], (method, path)
        assert "credential_semantics" in {
            finding["signal"] for finding in operation["sensitive_schema_findings"]
        }, (method, path)


def test_v5_payment_and_capability_contracts_are_catalog_only() -> None:
    expected = {
        ("GET", "/accounts/{account_id}/ai-gateway/billing/invoice-history"),
        ("GET", "/accounts/{account_id}/ai-gateway/gateways"),
        ("POST", "/accounts/{account_id}/ai-gateway/gateways"),
        ("DELETE", "/accounts/{account_id}/ai-gateway/gateways/{id}"),
        ("GET", "/accounts/{account_id}/ai-gateway/gateways/{id}"),
        ("PUT", "/accounts/{account_id}/ai-gateway/gateways/{id}"),
        ("GET", "/accounts/{account_id}/billing/profile"),
        ("POST", "/accounts/{account_id}/browser-rendering/devtools/browser"),
        (
            "GET",
            "/accounts/{account_id}/browser-rendering/devtools/browser/{session_id}/json",
        ),
        (
            "GET",
            "/accounts/{account_id}/browser-rendering/devtools/browser/{session_id}/json/list",
        ),
        (
            "GET",
            "/accounts/{account_id}/browser-rendering/devtools/browser/{session_id}/json/list/"
            "{target_id}",
        ),
        (
            "PUT",
            "/accounts/{account_id}/browser-rendering/devtools/browser/{session_id}/json/new",
        ),
        (
            "GET",
            "/accounts/{account_id}/browser-rendering/devtools/browser/{session_id}/json/version",
        ),
        ("GET", "/accounts/{account_id}/browser-rendering/devtools/session"),
        (
            "GET",
            "/accounts/{account_id}/browser-rendering/devtools/session/{session_id}",
        ),
        ("POST", "/accounts/{account_id}/cni/interconnects"),
        ("POST", "/accounts/{account_id}/d1/database/{database_id}/export"),
        ("POST", "/accounts/{account_id}/d1/database/{database_id}/import"),
        ("POST", "/accounts/{account_id}/images/v2/direct_upload"),
        ("GET", "/accounts/{account_id}/magic/connectors"),
        ("POST", "/accounts/{account_id}/magic/connectors"),
        ("DELETE", "/accounts/{account_id}/magic/connectors/{connector_id}"),
        ("GET", "/accounts/{account_id}/magic/connectors/{connector_id}"),
        ("PATCH", "/accounts/{account_id}/magic/connectors/{connector_id}"),
        ("PUT", "/accounts/{account_id}/magic/connectors/{connector_id}"),
        (
            "GET",
            "/accounts/{account_id}/realtime/kit/{app_id}/recordings/active-recording/{meeting_id}",
        ),
        ("POST", "/accounts/{account_id}/realtime/kit/{app_id}/recordings/track"),
        (
            "GET",
            "/accounts/{account_id}/realtime/kit/{app_id}/sessions/{session_id}/chat",
        ),
        (
            "GET",
            "/accounts/{account_id}/realtime/kit/{app_id}/sessions/{session_id}/summary",
        ),
        (
            "GET",
            "/accounts/{account_id}/realtime/kit/{app_id}/sessions/{session_id}/transcript",
        ),
        ("POST", "/accounts/{account_id}/stream/direct_upload"),
        (
            "POST",
            "/accounts/{account_id}/workers/observability/telemetry/live-tail",
        ),
        ("GET", "/user/billing/profile"),
    }
    operations = {
        (operation["method"], operation["path_template"]): operation
        for operation in load_coverage()["operations"]
    }

    assert len(expected) == 33
    for key in expected:
        operation = operations[key]
        assert operation["coverage_status"] == "catalog_only", key
        assert operation["mcp_tool"] is None, key
        assert operation["high_risk"] is True, key
        assert "credentials" in operation["risk_flags"], key
        assert "credential_semantics" in {
            finding["signal"] for finding in operation["sensitive_schema_findings"]
        }, key


def test_v5_exact_credential_context_policy_is_complete_and_fail_closed() -> None:
    expected: set[tuple[str, str]] = {
        (
            "GET",
            "/accounts/{account_id}/devices/registrations/{registration_id}/override_codes",
        ),
        ("GET", "/accounts/{account_id}/devices/{device_id}/override_codes"),
        ("GET", "/accounts/{account_id}/workers/observability/destinations"),
        ("POST", "/accounts/{account_id}/workers/observability/destinations"),
        (
            "PATCH",
            "/accounts/{account_id}/workers/observability/destinations/{slug}",
        ),
    }
    monitor_suffixes = {
        ("GET", "/load_balancers/monitors"),
        ("POST", "/load_balancers/monitors"),
        ("GET", "/load_balancers/monitors/{monitor_id}"),
        ("PATCH", "/load_balancers/monitors/{monitor_id}"),
        ("PUT", "/load_balancers/monitors/{monitor_id}"),
        ("POST", "/load_balancers/monitors/{monitor_id}/preview"),
        ("POST", "/load_balancers/pools/{pool_id}/preview"),
    }
    for scope in ("/accounts/{account_id}", "/user"):
        expected.update((method, f"{scope}{suffix}") for method, suffix in monitor_suffixes)
    expected.update(
        {
            ("GET", "/zones/{zone_id}/healthchecks"),
            ("POST", "/zones/{zone_id}/healthchecks"),
            ("POST", "/zones/{zone_id}/healthchecks/preview"),
            ("GET", "/zones/{zone_id}/healthchecks/preview/{healthcheck_id}"),
            ("GET", "/zones/{zone_id}/healthchecks/{healthcheck_id}"),
            ("PATCH", "/zones/{zone_id}/healthchecks/{healthcheck_id}"),
            ("PUT", "/zones/{zone_id}/healthchecks/{healthcheck_id}"),
            ("GET", "/zones/{zone_id}/smart_shield/healthchecks"),
            ("POST", "/zones/{zone_id}/smart_shield/healthchecks"),
            ("GET", "/zones/{zone_id}/smart_shield/healthchecks/{healthcheck_id}"),
            ("PATCH", "/zones/{zone_id}/smart_shield/healthchecks/{healthcheck_id}"),
            ("PUT", "/zones/{zone_id}/smart_shield/healthchecks/{healthcheck_id}"),
            ("POST", "/accounts/{account_id}/request-tracer/trace"),
        }
    )
    ruleset_suffixes = {
        ("POST", "/rulesets"),
        ("GET", "/rulesets/phases/{ruleset_phase}/entrypoint"),
        ("PUT", "/rulesets/phases/{ruleset_phase}/entrypoint"),
        (
            "GET",
            "/rulesets/phases/{ruleset_phase}/entrypoint/versions/{ruleset_version}",
        ),
        ("GET", "/rulesets/{ruleset_id}"),
        ("PUT", "/rulesets/{ruleset_id}"),
        ("POST", "/rulesets/{ruleset_id}/rules"),
        ("DELETE", "/rulesets/{ruleset_id}/rules/{rule_id}"),
        ("PATCH", "/rulesets/{ruleset_id}/rules/{rule_id}"),
        ("GET", "/rulesets/{ruleset_id}/versions/{ruleset_version}"),
        (
            "GET",
            "/rulesets/{ruleset_id}/versions/{ruleset_version}/by_tag/{rule_tag}",
        ),
    }
    for scope in ("/accounts/{account_id}", "/zones/{zone_id}"):
        expected.update((method, f"{scope}{suffix}") for method, suffix in ruleset_suffixes)
    expected.update(
        {
            ("GET", "/accounts/{account_id}/gateway/pacfiles"),
            ("POST", "/accounts/{account_id}/gateway/pacfiles"),
            ("GET", "/accounts/{account_id}/gateway/pacfiles/{pacfile_id}"),
            ("PUT", "/accounts/{account_id}/gateway/pacfiles/{pacfile_id}"),
            ("GET", "/zones/{zone_id}/logpush/edge/jobs"),
            ("POST", "/zones/{zone_id}/logpush/edge/jobs"),
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
            ("POST", "/accounts/{account_id}/ai/run"),
            ("POST", "/accounts/{account_id}/urlscanner/scan"),
            ("POST", "/accounts/{account_id}/urlscanner/v2/bulk"),
            ("POST", "/accounts/{account_id}/urlscanner/v2/scan"),
            ("POST", "/zones/{zone_id}/waiting_rooms/preview"),
            (
                "GET",
                "/accounts/{account_id}/magic/cloud/providers/{provider_id}/initial_setup",
            ),
            ("GET", "/accounts/{account_id}/images/v1/keys"),
            ("DELETE", "/accounts/{account_id}/images/v1/keys/{signing_key_name}"),
            ("PUT", "/accounts/{account_id}/images/v1/keys/{signing_key_name}"),
        }
    )
    context_policy_ids = {
        "credential_configuration.ai_provider_headers",
        "credential_configuration.ai_search_headers",
        "credential_configuration.gateway_rule_headers",
        "credential_configuration.outbound_health_headers",
        "credential_configuration.ruleset_rewrite_headers",
        "credential_configuration.url_scanner_headers",
        "credential_configuration.workers_observability_headers",
        "credential_response.azure_consent_url",
        "credential_response.image_signing_key",
        "credential_response.instant_logs_session",
        "credential_response.pac_download_url",
        "credential_response.waiting_room_preview_url",
        "credential_response.zero_trust_override_codes",
    }
    actual = {
        key
        for key, policy in REVIEWED_OPERATION_OVERRIDES.items()
        if policy["policy_id"] in context_policy_ids
    }
    operations = {
        (operation["method"], operation["path_template"]): operation
        for operation in load_coverage()["operations"]
    }

    assert len(expected) == 87
    assert actual == expected
    for key in expected:
        policy = REVIEWED_OPERATION_OVERRIDES[key]
        operation = operations[key]
        assert policy["force_catalog_only"] is True, key
        assert policy["risk_flags"] == ("credentials",), key
        assert operation["policy_override"] == policy["policy_id"], key
        assert operation["coverage_status"] == "catalog_only", key
        assert operation["mcp_tool"] is None, key
        assert operation["high_risk"] is True, key


def test_reviewed_side_effecting_gets_are_mutation_and_high_risk_gated() -> None:
    pagerduty = find_operation(
        "GET",
        "/accounts/example-account/alerting/v3/destinations/pagerduty/connect/example-token",
    )
    browser_activate = find_operation(
        "GET",
        "/accounts/example-account/browser-rendering/devtools/browser/example-session/"
        "json/activate/example-target",
    )
    browser_close = find_operation(
        "GET",
        "/accounts/example-account/browser-rendering/devtools/browser/example-session/"
        "json/close/example-target",
    )
    ai_websocket = find_operation("GET", "/accounts/example-account/ai/run/@cf/deepgram/aura")
    interconnect_loa = find_operation(
        "GET", "/accounts/example-account/cni/interconnects/example-icon/loa"
    )

    assert pagerduty is not None
    assert pagerduty["classification"] == "write"
    assert pagerduty["risk_flags"] == ["credentials", "side_effecting_get"]
    assert pagerduty["high_risk"] is True
    assert pagerduty["coverage_status"] == "catalog_only"
    assert pagerduty["mcp_tool"] is None
    assert pagerduty["policy_override"] == "side_effecting_get.pagerduty_connect"

    assert browser_activate is not None
    assert browser_activate["classification"] == "write"
    assert browser_activate["risk_flags"] == ["side_effecting_get"]
    assert browser_activate["high_risk"] is True
    assert browser_activate["coverage_status"] == "callable"
    assert browser_activate["policy_override"] == "side_effecting_get.browser_target_activate"

    assert browser_close is not None
    assert browser_close["classification"] == "destructive"
    assert browser_close["risk_flags"] == ["side_effecting_get"]
    assert browser_close["high_risk"] is True
    assert browser_close["coverage_status"] == "callable"
    assert browser_close["policy_override"] == "side_effecting_get.browser_target_close"

    assert ai_websocket is not None
    assert ai_websocket["classification"] == "write"
    assert ai_websocket["risk_flags"] == ["side_effecting_get"]
    assert ai_websocket["high_risk"] is True
    assert ai_websocket["coverage_status"] == "catalog_only"
    assert ai_websocket["mcp_tool"] is None
    assert ai_websocket["policy_override"] == "side_effecting_get.ai_websocket_connection"

    assert interconnect_loa is not None
    assert interconnect_loa["classification"] == "write"
    assert interconnect_loa["risk_flags"] == ["side_effecting_get"]
    assert interconnect_loa["high_risk"] is True
    assert interconnect_loa["coverage_status"] == "catalog_only"
    assert interconnect_loa["mcp_tool"] is None
    assert interconnect_loa["policy_override"] == "side_effecting_get.interconnect_loa_generate"


def test_reviewed_credential_responses_are_catalog_only() -> None:
    expected = {
        "/accounts/example-account/cfd_tunnel/example-tunnel/token": (
            "credential_response.cloudflare_tunnel_token"
        ),
        "/accounts/example-account/containers/instances/example-instance/ssh": (
            "credential_response.container_ssh"
        ),
        "/accounts/example-account/warp_connector/example-tunnel/token": (
            "credential_response.warp_connector_token"
        ),
    }

    for path, policy_id in expected.items():
        operation = find_operation("GET", path)
        assert operation is not None
        assert operation["classification"] == "read"
        assert operation["risk_flags"] == ["credentials"]
        assert operation["high_risk"] is True
        assert operation["transport_support"] == "catalog_only"
        assert operation["coverage_status"] == "catalog_only"
        assert operation["mcp_tool"] is None
        assert operation["policy_override"] == policy_id
        assert operation["policy_reason"] is not None
        assert "Credential-returning operation" in operation["policy_reason"]


def test_every_reviewed_override_is_present_in_generated_catalog() -> None:
    coverage = load_coverage()
    generated = {
        (operation["method"], operation["path_template"]): operation
        for operation in coverage["operations"]
        if operation["policy_override"] is not None
    }

    assert set(generated) == set(REVIEWED_OPERATION_OVERRIDES)
    for key, expected in REVIEWED_OPERATION_OVERRIDES.items():
        operation = generated[key]
        assert operation["policy_override"] == expected["policy_id"]
        assert operation["policy_reason"] == expected["reason"]
        assert operation["classification"] == expected["classification"]
        assert operation["risk_flags"] == list(expected["risk_flags"])
        if expected["force_catalog_only"]:
            assert operation["coverage_status"] == "catalog_only"
            assert operation["mcp_tool"] is None


def test_reviewed_override_lookup_is_exact_method_and_path() -> None:
    exact = reviewed_operation_override(
        "get", "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token"
    )

    assert exact is not None
    assert exact["policy_id"] == "credential_response.cloudflare_tunnel_token"
    assert (
        reviewed_operation_override(
            "GET", "/accounts/example-account/cfd_tunnel/example-tunnel/token"
        )
        is None
    )
    assert (
        reviewed_operation_override("POST", "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token")
        is None
    )


def test_destructive_and_risk_classification_use_exact_tokens() -> None:
    assert classify_operation("POST", "Cancel build") == "destructive"
    assert classify_operation("POST", "Restore database") == "destructive"
    assert classify_operation("POST", "Create a preset") == "write"
    assert operation_risk_flags(
        "POST",
        summary="Create Subscription",
        operation_id="account-subscriptions-create-subscription",
        path_template="/accounts/{account_id}/subscriptions",
    ) == ["billing_or_commerce"]
    assert (
        operation_risk_flags(
            "DELETE",
            summary="Delete flag",
            operation_id="flagship_delete_flag",
            path_template="/accounts/{account_id}/flagship/apps/{app_id}/flags/{flag_key}",
        )
        == []
    )
