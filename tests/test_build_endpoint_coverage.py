from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def _load_builder() -> ModuleType:
    script_path = Path(__file__).parents[1] / "scripts" / "build_endpoint_coverage.py"
    spec = importlib.util.spec_from_file_location("build_endpoint_coverage", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = _load_builder()


def test_load_pinned_schema_rejects_unreviewed_bytes(tmp_path: Path) -> None:
    schema = tmp_path / "openapi.json"
    schema.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="schema SHA256 mismatch"):
        builder.load_pinned_schema(schema)


def test_media_metadata_resolves_local_json_pointer_refs() -> None:
    spec: dict[str, Any] = {
        "components": {
            "requestBodies": {
                "Payload": {"content": {"application/merge-patch+json": {}}},
            },
            "responses": {
                "Success": {"content": {"application/scim+json": {}}},
            },
        }
    }
    operation = {
        "requestBody": {"$ref": "#/components/requestBodies/Payload"},
        "responses": {"200": {"$ref": "#/components/responses/Success"}},
    }

    request_types = builder.request_content_types(spec, operation)
    response_types = builder.success_response_content_types(spec, operation)

    assert request_types == ["application/merge-patch+json"]
    assert response_types == ["application/scim+json"]
    assert builder.transport_metadata(
        request_types,
        response_types,
        required_headers=[],
        token_auth_compatible=True,
        unconstrained_request_json_schema=False,
        declared_success_response=True,
        ambiguous_bodyless_success_response=False,
        unconstrained_success_json_schema=False,
    )[:2] == (
        "json",
        "callable",
    )


def test_operation_without_explicit_2xx_response_is_catalog_only() -> None:
    operation = {
        "operationId": "internal-default-only",
        "summary": "Internal default-only route",
        "responses": {"default": {"content": {"application/json": {}}}},
    }
    spec: dict[str, Any] = {"paths": {"/internal": {"get": operation}}}

    row = builder.operation_rows(spec, require_all_overrides=False)[0]

    assert builder.has_declared_success_response(operation) is False
    assert row["declared_success_response"] is False
    assert row["transport_support"] == "catalog_only"
    assert row["coverage_status"] == "catalog_only"
    assert row["mcp_tool"] is None
    assert "no explicit 2xx" in row["notes"]


def test_operation_with_empty_request_json_schema_is_catalog_only() -> None:
    operation = {
        "operationId": "unknown-json-request",
        "summary": "Accept an unknown JSON contract",
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": {}}},
        },
        "responses": {
            "200": {
                "content": {
                    "application/json": {
                        "schema": {
                            "properties": {"ok": {"type": "boolean"}},
                            "type": "object",
                        }
                    }
                }
            }
        },
    }
    spec: dict[str, Any] = {"paths": {"/unknown-request": {"post": operation}}}

    row = builder.operation_rows(spec, require_all_overrides=False)[0]

    assert builder.request_body_required(spec, operation) is True
    assert builder.has_unconstrained_request_json_schema(spec, operation) is True
    assert row["request_body_required"] is True
    assert row["unconstrained_request_json_schema"] is True
    assert row["coverage_status"] == "catalog_only"
    assert row["mcp_tool"] is None
    assert "no reviewable schema" in row["notes"]


def test_operation_with_empty_success_json_schema_is_catalog_only() -> None:
    operation = {
        "operationId": "unknown-json-response",
        "summary": "Return an unknown JSON contract",
        "responses": {"200": {"content": {"application/json": {"schema": {}}}}},
    }
    spec: dict[str, Any] = {"paths": {"/unknown-json": {"get": operation}}}

    row = builder.operation_rows(spec, require_all_overrides=False)[0]

    assert builder.has_declared_success_response(operation) is True
    assert builder.has_unconstrained_success_json_schema(spec, operation) is True
    assert row["unconstrained_success_json_schema"] is True
    assert row["transport_support"] == "catalog_only"
    assert row["coverage_status"] == "catalog_only"
    assert row["mcp_tool"] is None
    assert "no reviewable schema" in row["notes"]


def test_bare_object_success_schema_is_catalog_only() -> None:
    operation = {
        "summary": "Return arbitrary original payload",
        "responses": {
            "200": {
                "content": {
                    "application/json": {
                        "schema": {"description": "Original request", "type": "object"}
                    }
                }
            }
        },
    }
    spec: dict[str, Any] = {"paths": {"/raw": {"get": operation}}}

    row = builder.operation_rows(spec, require_all_overrides=False)[0]

    assert builder.schema_is_effectively_unconstrained(spec, {"type": "object"}) is True
    assert row["unconstrained_success_json_schema"] is True
    assert row["coverage_status"] == "catalog_only"


def test_required_provider_headers_are_catalog_only() -> None:
    operation = {
        "parameters": [
            {"in": "header", "name": "Tus-Resumable", "required": True},
            {"in": "header", "name": "Optional-Header"},
        ],
        "responses": {"204": {"description": "Accepted"}},
        "summary": "Initiate upload",
    }
    spec: dict[str, Any] = {"paths": {"/upload": {"post": operation}}}

    row = builder.operation_rows(spec, require_all_overrides=False)[0]

    assert row["required_provider_headers"] == ["Tus-Resumable"]
    assert row["coverage_status"] == "catalog_only"
    assert "Tus-Resumable" in row["notes"]


def test_legacy_key_only_auth_is_catalog_only_without_token_evidence() -> None:
    operation: dict[str, Any] = {
        "security": [{"api_email": [], "api_key": []}],
        "responses": {
            "200": {
                "content": {
                    "application/json": {
                        "schema": {"properties": {"ok": {"type": "boolean"}}, "type": "object"}
                    }
                }
            }
        },
        "summary": "Legacy auth only",
        "x-api-token-group": None,
    }
    spec: dict[str, Any] = {"paths": {"/legacy": {"get": operation}}}

    row = builder.operation_rows(spec, require_all_overrides=False)[0]

    assert row["token_auth_compatible"] is False
    assert row["auth_compatibility_evidence"] == "no_bearer_token_evidence"
    assert row["coverage_status"] == "catalog_only"


def test_provider_token_group_is_bearer_compatibility_evidence() -> None:
    operation = {
        "security": [{"api_email": [], "api_key": []}],
        "responses": {"204": {"description": "Done"}},
        "summary": "Token-compatible route",
        "x-api-token-group": ["Example Read"],
    }
    spec: dict[str, Any] = {"paths": {"/token-compatible": {"get": operation}}}

    row = builder.operation_rows(spec, require_all_overrides=False)[0]

    assert row["token_auth_compatible"] is True
    assert row["auth_compatibility_evidence"] == "provider_token_group"
    assert row["coverage_status"] == "callable"


def test_non_204_bodyless_success_contract_is_catalog_only() -> None:
    operation = {
        "responses": {"200": {"description": "Potential binary or header-only result"}},
        "summary": "Return ambiguous success",
    }
    spec: dict[str, Any] = {"paths": {"/ambiguous": {"get": operation}}}

    row = builder.operation_rows(spec, require_all_overrides=False)[0]

    assert builder.has_ambiguous_bodyless_success_response(spec, operation) is True
    assert row["ambiguous_bodyless_success_response"] is True
    assert row["coverage_status"] == "catalog_only"
    assert "non-204/205" in row["notes"]


def test_operation_rows_apply_reviewed_mutation_and_credential_policies() -> None:
    spec: dict[str, Any] = {
        "paths": {
            "/accounts/{account_id}/alerting/v3/destinations/pagerduty/connect/{token_id}": {
                "get": {
                    "operationId": (
                        "notification-destinations-with-pager-duty-connect-pager-duty-token"
                    ),
                    "parameters": [
                        {
                            "in": "path",
                            "name": "token_id",
                            "required": True,
                            "schema": {
                                "description": "The token integration key",
                                "type": "string",
                            },
                        }
                    ],
                    "summary": "Connect PagerDuty",
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "properties": {"ok": {"type": "boolean"}},
                                        "type": "object",
                                    }
                                }
                            }
                        }
                    },
                }
            },
            "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token": {
                "get": {
                    "operationId": "cloudflare-tunnel-get-a-cloudflare-tunnel-token",
                    "summary": "Get a Cloudflare Tunnel token",
                    "responses": {"200": {"content": {"application/json": {}}}},
                }
            },
        }
    }

    rows = builder.operation_rows(spec, require_all_overrides=False)
    by_path = {row["path_template"]: row for row in rows}
    pagerduty = by_path[
        "/accounts/{account_id}/alerting/v3/destinations/pagerduty/connect/{token_id}"
    ]
    tunnel_token = by_path["/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token"]

    assert pagerduty["classification"] == "write"
    assert pagerduty["risk_flags"] == ["credentials", "side_effecting_get"]
    assert pagerduty["high_risk"] is True
    assert pagerduty["coverage_status"] == "catalog_only"
    assert pagerduty["mcp_tool"] is None
    assert {finding["signal"] for finding in pagerduty["sensitive_schema_findings"]} == {
        "credential_semantics"
    }

    assert tunnel_token["classification"] == "read"
    assert tunnel_token["risk_flags"] == ["credentials"]
    assert tunnel_token["high_risk"] is True
    assert tunnel_token["transport_support"] == "catalog_only"
    assert tunnel_token["coverage_status"] == "catalog_only"
    assert tunnel_token["mcp_tool"] is None
    assert tunnel_token["policy_override"] == "credential_response.cloudflare_tunnel_token"


def test_operation_rows_reject_stale_reviewed_overrides() -> None:
    with pytest.raises(ValueError, match="Reviewed operation overrides missing from pinned schema"):
        builder.operation_rows({"paths": {}})


def test_operation_rows_reject_unreviewed_side_effecting_get() -> None:
    spec: dict[str, Any] = {
        "paths": {
            "/accounts/{account_id}/new-action": {
                "get": {
                    "operationId": "new-close-action",
                    "summary": "Close a newly introduced resource",
                    "responses": {"200": {"content": {"application/json": {}}}},
                }
            }
        }
    }

    assert builder.is_side_effecting_get_candidate("GET", "Close a newly introduced resource")
    assert builder.is_side_effecting_get_candidate("GET", "Generate a new authorization document")
    with pytest.raises(ValueError, match="Unreviewed side-effecting GET operations"):
        builder.operation_rows(spec, require_all_overrides=False)


def test_missing_operation_id_gets_stable_bounded_method_path_identity() -> None:
    spec: dict[str, Any] = {
        "paths": {
            "/accounts/{account_id}/widgets/{widget_id}": {
                "post": {
                    "summary": "Create widget",
                    "responses": {"200": {"content": {"application/json": {}}}},
                }
            }
        }
    }

    first = builder.operation_rows(spec, require_all_overrides=False)[0]
    second = builder.operation_rows(spec, require_all_overrides=False)[0]

    assert first["operation_id"] == second["operation_id"]
    assert first["operation_id"].startswith("generated-post-accounts-account-id-widgets-widget-id-")
    assert 1 <= len(first["operation_id"]) <= 256


def test_operation_identity_fallback_is_method_and_path_specific() -> None:
    post = builder.stable_operation_id("post", "/widgets/{widget_id}", "")
    delete = builder.stable_operation_id("delete", "/widgets/{widget_id}", "")
    other_path = builder.stable_operation_id("post", "/widgets/{other_id}", "")

    assert len({post, delete, other_path}) == 3
    assert builder.stable_operation_id("post", "/widgets", "upstream-id") == "upstream-id"


def test_sensitive_schema_walks_every_supported_contract_shape() -> None:
    spec: dict[str, Any] = {
        "components": {
            "parameters": {
                "CredentialHeader": {
                    "in": "header",
                    "name": "X-Credential",
                    "schema": {"$ref": "#/components/schemas/ScalarSecret"},
                }
            },
            "requestBodies": {
                "Payload": {
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Composite"}}
                    }
                }
            },
            "headers": {
                "ResponseCredential": {"schema": {"$ref": "#/components/schemas/ScalarSecret"}}
            },
            "responses": {
                "Success": {
                    "headers": {
                        "X-Response-Credential": {"$ref": "#/components/headers/ResponseCredential"}
                    },
                    "content": {
                        "application/json": {
                            "schema": {
                                "properties": {
                                    "items": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/ScalarSecret"},
                                    }
                                },
                                "type": "object",
                            }
                        }
                    },
                }
            },
            "schemas": {
                "ScalarSecret": {"type": "string", "x-sensitive": True},
                "Composite": {
                    "allOf": [
                        {
                            "properties": {
                                "password": {"format": "password", "type": "string"},
                                "credential_value": {
                                    "description": "API token value",
                                    "type": "string",
                                    "writeOnly": True,
                                },
                                "private_material": {
                                    "additionalProperties": {
                                        "$ref": "#/components/schemas/ScalarSecret"
                                    },
                                    "type": "object",
                                },
                            },
                            "type": "object",
                        },
                        {"oneOf": [{"anyOf": [{"$ref": "#/components/schemas/ScalarSecret"}]}]},
                    ]
                },
            },
        },
        "paths": {
            "/sensitive": {
                "parameters": [{"$ref": "#/components/parameters/CredentialHeader"}],
                "post": {
                    "summary": "Create resource",
                    "requestBody": {"$ref": "#/components/requestBodies/Payload"},
                    "responses": {
                        "201": {"$ref": "#/components/responses/Success"},
                        "default": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ScalarSecret"}
                                }
                            }
                        },
                    },
                },
            }
        },
    }

    row = builder.operation_rows(spec, require_all_overrides=False)[0]
    signals = {finding["signal"] for finding in row["sensitive_schema_findings"]}
    locations = {finding["location"] for finding in row["sensitive_schema_findings"]}

    assert signals == {
        "credential_semantics",
        "credential_like_write_only",
        "format_password",
        "x_sensitive",
    }
    assert row["sensitive_request_schema"] is True
    assert row["sensitive_success_response_schema"] is True
    assert row["coverage_status"] == "catalog_only"
    assert row["mcp_tool"] is None
    assert row["risk_flags"] == ["credentials"]
    assert row["schema_policy_id"] == builder.SCHEMA_SENSITIVITY_POLICY_ID
    assert any("additionalProperties" in location for location in locations)
    assert any(".items" in location for location in locations)
    assert any(".oneOf" in location and ".anyOf" in location for location in locations)
    assert any("headers" in location for location in locations)
    assert any('success_response["default"]' in location for location in locations)


def test_schema_descriptions_examples_and_unrelated_write_only_fields_do_not_trigger() -> None:
    spec: dict[str, Any] = {
        "paths": {
            "/safe": {
                "post": {
                    "summary": "Create resource",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "ordinary": {
                                            "description": "Example secret password token text",
                                            "example": "secret-token",
                                            "type": "string",
                                        },
                                        "migration_order": {
                                            "description": "Migration ordering field",
                                            "type": "integer",
                                            "writeOnly": True,
                                        },
                                    },
                                    "type": "object",
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "properties": {"ok": {"type": "boolean"}},
                                        "type": "object",
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    row = builder.operation_rows(spec, require_all_overrides=False)[0]

    assert row["sensitive_schema_findings"] == []
    assert row["sensitive_request_schema"] is False
    assert row["sensitive_success_response_schema"] is False
    assert row["coverage_status"] == "callable"
    assert row["schema_policy_id"] is None


def test_unmarked_semantic_credentials_trigger_without_known_false_positives() -> None:
    spec: dict[str, Any] = {
        "paths": {
            "/semantic": {
                "post": {
                    "summary": "Create resource",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "secret": {"type": "string"},
                                        "secret_access_key": {"type": "string"},
                                        "private_credential": {
                                            "oneOf": [
                                                {"type": "string"},
                                                {
                                                    "properties": {
                                                        "secret_name": {
                                                            "description": (
                                                                "Name of the secret being "
                                                                "referenced"
                                                            ),
                                                            "type": "string",
                                                        }
                                                    },
                                                    "type": "object",
                                                },
                                            ]
                                        },
                                        "is_secret": {"type": "boolean"},
                                        "public_key": {"type": "string"},
                                        "password_expression": {"type": "string"},
                                    },
                                    "type": "object",
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "properties": {
                                            "stream_key": {"type": "string"},
                                            "token": {
                                                "description": "Participant auth token",
                                                "type": "string",
                                            },
                                            "ownership_validation_token": {"type": "string"},
                                            "cep_jwt": {"type": "string"},
                                        },
                                        "type": "object",
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    row = builder.operation_rows(spec, require_all_overrides=False)[0]
    semantic_locations = {
        finding["location"]
        for finding in row["sensitive_schema_findings"]
        if finding["signal"] == "credential_semantics"
    }

    assert len(semantic_locations) == 7
    assert any('properties["private_credential"].oneOf[0]' in item for item in semantic_locations)
    assert not any("secret_name" in item for item in semantic_locations)
    assert not any("is_secret" in item for item in semantic_locations)
    assert not any("public_key" in item for item in semantic_locations)
    assert not any("password_expression" in item for item in semantic_locations)
    assert row["sensitive_request_schema"] is True
    assert row["sensitive_success_response_schema"] is True
    assert row["coverage_status"] == "catalog_only"


def test_unmarked_payment_and_capability_fields_trigger_semantic_policy() -> None:
    sensitive_properties = {
        "authorization": {"type": "string"},
        "card_number": {"type": "string"},
        "devtoolsFrontendUrl": {"type": "string"},
        "download_url": {"type": "string"},
        "invoice_pdf": {"type": "string"},
        "license_key": {"type": "string"},
        "md5_key": {"type": "string"},
        "payment_nonce": {"type": "string"},
        "signed_url": {"type": "string"},
        "summaryDownloadUrl": {"type": "string"},
        "uploadURL": {"type": "string"},
        "validation_code": {"type": "string"},
        "webSocketDebuggerUrl": {"type": "string"},
        "wsUrl": {"type": "string"},
    }
    spec: dict[str, Any] = {
        "paths": {
            "/capability": {
                "post": {
                    "summary": "Create capability",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {"pairing_key": {"type": "string"}},
                                    "type": "object",
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "properties": sensitive_properties,
                                        "type": "object",
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    row = builder.operation_rows(spec, require_all_overrides=False)[0]
    semantic_locations = {
        finding["location"]
        for finding in row["sensitive_schema_findings"]
        if finding["signal"] == "credential_semantics"
    }

    assert len(semantic_locations) == len(sensitive_properties) + 1
    for property_name in (*sensitive_properties, "pairing_key"):
        assert any(f'properties["{property_name}"]' in item for item in semantic_locations)
    assert row["sensitive_request_schema"] is True
    assert row["sensitive_success_response_schema"] is True
    assert row["coverage_status"] == "catalog_only"


def test_capability_field_false_positive_controls_remain_callable() -> None:
    safe_properties = {
        "auth_url": {"type": "string"},
        "authorization": {
            "properties": {"status": {"type": "string"}},
            "type": "object",
        },
        "download_href": {"type": "string"},
        "keys_url": {"type": "string"},
        "public_key": {"type": "string"},
        "signature": {"type": "string"},
        "site_token": {"type": "string"},
        "token_url": {"type": "string"},
        "verification_key": {"type": "string"},
    }
    spec: dict[str, Any] = {
        "paths": {
            "/safe-capability-metadata": {
                "get": {
                    "summary": "Get public metadata",
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "properties": safe_properties,
                                        "type": "object",
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    row = builder.operation_rows(spec, require_all_overrides=False)[0]

    assert row["sensitive_schema_findings"] == []
    assert row["coverage_status"] == "callable"


def test_sensitive_schema_walk_rejects_stale_refs_and_invariant_rejects_callable_rows() -> None:
    with pytest.raises(ValueError, match="Unresolvable OpenAPI reference"):
        builder.sensitive_schema_findings(
            {},
            {"$ref": "#/components/schemas/Missing"},
            direction="request",
            location="request.body.schema",
        )

    spec: dict[str, Any] = {
        "paths": {
            "/sensitive": {
                "post": {
                    "summary": "Create resource",
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"type": "string", "x-sensitive": True}}
                        }
                    },
                    "responses": {"200": {"content": {"application/json": {}}}},
                }
            }
        }
    }
    row = builder.operation_rows(spec, require_all_overrides=False)[0]
    row["coverage_status"] = "callable"
    row["mcp_tool"] = "cloudflare_api_request"

    with pytest.raises(ValueError, match="Sensitive schema policy invariant failed"):
        builder.validate_sensitive_schema_policy([row])
