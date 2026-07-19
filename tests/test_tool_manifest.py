from __future__ import annotations

import hashlib
import json

import pytest
from jsonschema import Draft202012Validator

import cloudflare_mcp.server as server
from cloudflare_mcp.server import mcp
from cloudflare_mcp.tool_manifest import (
    TOOL_CATALOG_VERSION,
    build_tool_manifest,
    search_tools,
    tool_descriptor,
)

ACCESS_TOKEN = "standalone-access-token-000000000000000000000000"


def _sha256(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _configure_live_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_MODE", "standalone")
    monkeypatch.setenv("MCP_ACCESS_TOKEN", ACCESS_TOKEN)
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", "localhost")
    monkeypatch.setenv("MCP_ALLOWED_ORIGINS", "")
    monkeypatch.setenv("MCP_BUILD_SHA", "development")
    monkeypatch.setenv("MCP_SOURCE_FINGERPRINT", "development")
    monkeypatch.setenv("MCP_IMAGE_REFERENCE", "development")
    monkeypatch.setenv("MCP_APPROVAL_SIGNING_KEY", "approval-signing-key-000000000000000000000000")
    monkeypatch.setattr(
        server,
        "_http_headers",
        lambda: {
            "authorization": f"Bearer {ACCESS_TOKEN}",
            "x-cloudflare-api-token": "synthetic-provider-token",
        },
    )


@pytest.mark.asyncio
async def test_manifest_is_deterministic_lossless_and_matches_native_registry() -> None:
    manifest = build_tool_manifest("build-one")
    other_build = build_tool_manifest("build-two")
    registered = {tool.name: tool for tool in await mcp.list_tools(run_middleware=False)}

    assert manifest["schemaVersion"] == "1.0.0"
    assert manifest["serviceId"] == "cloudflare"
    assert manifest["catalogVersion"] == TOOL_CATALOG_VERSION
    assert manifest["buildSha"] == "build-one"
    assert manifest["counts"] == {
        "raw": 6,
        "agentReady": 5,
        "legacy": 1,
        "hidden": 0,
    }
    assert manifest["descriptorHash"] == other_build["descriptorHash"]
    assert manifest["descriptorHash"] == _sha256(manifest["tools"])
    assert [item["nativeToolName"] for item in manifest["tools"]] == sorted(registered)

    required_fields = {
        "serviceId",
        "nativeToolName",
        "canonicalName",
        "aliases",
        "title",
        "description",
        "category",
        "deprecation",
        "inputSchema",
        "outputSchema",
        "annotations",
        "confirmation",
        "documentationUrl",
        "navigationRole",
        "catalogVersion",
        "tier",
        "descriptorHash",
    }
    annotation_fields = {
        "readOnlyHint",
        "destructiveHint",
        "openWorldHint",
        "idempotentHint",
    }
    for descriptor in manifest["tools"]:
        native_name = descriptor["nativeToolName"]
        unhashed = {key: value for key, value in descriptor.items() if key != "descriptorHash"}
        assert set(descriptor) == required_fields
        assert descriptor["canonicalName"] == f"cloudflare.{native_name}"
        assert descriptor["catalogVersion"] == TOOL_CATALOG_VERSION
        assert descriptor["description"] == registered[native_name].description
        assert descriptor["inputSchema"] == registered[native_name].parameters
        assert descriptor["outputSchema"]["type"] == "object"
        assert set(descriptor["annotations"]) == annotation_fields
        assert descriptor["descriptorHash"] == _sha256(unhashed)
        for parameter in descriptor["inputSchema"]["properties"].values():
            assert isinstance(parameter.get("description"), str)
            assert parameter["description"].strip()


@pytest.mark.asyncio
async def test_representative_live_results_match_advertised_output_schemas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_live_runtime(monkeypatch)
    results: dict[str, list[object]] = {
        "check_configuration": [await server.check_configuration()],
        "list_capabilities": [
            await server.list_capabilities(include_descriptors=False),
            await server.list_capabilities(include_descriptors=True),
        ],
        "get_endpoint_coverage": [
            await server.get_endpoint_coverage(method="GET", path_contains="/zones", limit=1)
        ],
        "get_tool_usage": [
            await server.get_tool_usage(tool_name) for tool_name in server.TOOL_NAMES
        ],
        "find_tools": [
            await server.find_tools("configuration"),
            await server.find_tools("advanced api request", include_legacy=True),
        ],
        "cloudflare_api_request": [
            await server.cloudflare_api_request(
                method="POST",
                path="/zones",
                body={"name": "example.invalid", "account": {"id": "account-placeholder"}},
            )
        ],
    }
    advertised = {
        str(descriptor["nativeToolName"]): descriptor["outputSchema"]
        for descriptor in build_tool_manifest()["tools"]
    }

    assert set(results) == set(advertised)
    for tool_name, live_results in results.items():
        schema = advertised[tool_name]
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for result in live_results:
            validator.validate(result)


def test_generic_dispatcher_is_legacy_and_declares_mixed_risk_truthfully() -> None:
    descriptor = tool_descriptor("cloudflare_api_request")

    assert descriptor["tier"] == "legacy"
    assert descriptor["annotations"] == {
        "readOnlyHint": False,
        "destructiveHint": True,
        "openWorldHint": True,
        "idempotentHint": False,
    }
    assert descriptor["confirmation"]["required"] is True
    assert descriptor["confirmation"]["parameter"] == "x-mcp-approval-attestation"
    assert descriptor["confirmation"]["exactPhrase"] is None
    assert "one-use approval" in descriptor["confirmation"]["when"]
    assert "read, write, and destructive" in descriptor["description"]


def test_usage_schema_describes_approval_and_permanent_high_risk_denial() -> None:
    schema = tool_descriptor("get_tool_usage")["outputSchema"]
    gates = schema["properties"]["safety_gates"]["properties"]

    assert "External signed one-use approval" in gates["write"]["description"]
    assert "External signed one-use approval" in gates["destructive"]["description"]
    assert "Permanent denial" in gates["high_risk"]["description"]
    assert "startup" not in gates["high_risk"]["description"].lower()


def test_search_is_multi_token_punctuation_normalized_and_legacy_opt_in() -> None:
    alias = search_tools("configuration-health")
    default_advanced = search_tools("advanced api request")
    advanced = search_tools("advanced/api-request", include_legacy=True)
    negative = search_tools("publish wordpress blog")

    assert alias["results"][0]["toolName"] == "check_configuration"
    assert all(result["tier"] == "agent_ready" for result in default_advanced["results"])
    assert not any(
        result["toolName"] == "cloudflare_api_request" for result in default_advanced["results"]
    )
    assert advanced["results"][0]["toolName"] == "cloudflare_api_request"
    assert advanced["results"][0]["tier"] == "legacy"
    assert advanced["results"][0]["risk"] == "destructive"
    assert negative["results"] == []


def test_alias_reference_is_lossless() -> None:
    assert tool_descriptor("discover_tools")["nativeToolName"] == "find_tools"
    assert tool_descriptor("tool_reference")["nativeToolName"] == "get_tool_usage"
