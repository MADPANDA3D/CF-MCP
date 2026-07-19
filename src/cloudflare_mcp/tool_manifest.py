"""Deterministic provider-owned ToolManifest for Cloudflare MCP."""

from __future__ import annotations

import hashlib
import json
import os
import re
from functools import lru_cache
from typing import Any

TOOL_MANIFEST_SCHEMA_VERSION = "1.0.0"
TOOL_CATALOG_VERSION = "2026.07.19.3"
SERVICE_ID = "cloudflare"
CLOUDFLARE_DOCS_URL = "https://developers.cloudflare.com/api/"
CLOUDFLARE_SCHEMA_URL = "https://github.com/cloudflare/api-schemas"

_DEPRECATION = {
    "deprecated": False,
    "since": None,
    "replacement": None,
    "sunsetAt": None,
    "message": None,
}


def _object_schema(
    properties: dict[str, dict[str, Any]],
    *,
    required: list[str] | None = None,
    description: str,
    additional_properties: bool = False,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "description": description,
        "properties": properties,
        "additionalProperties": additional_properties,
    }
    if required:
        schema["required"] = required
    return schema


def _tool_input_schema(
    properties: dict[str, dict[str, Any]],
    *,
    required: list[str] | None = None,
) -> dict[str, Any]:
    """Build the exact root shape FastMCP exposes for a native tool input."""

    schema: dict[str, Any] = {
        "additionalProperties": False,
        "properties": properties,
        "type": "object",
    }
    if required:
        schema["required"] = required
    return schema


def _optional_tool_input(
    variants: list[dict[str, Any]],
    *,
    description: str,
) -> dict[str, Any]:
    """Build the exact nullable/default shape emitted by Pydantic for FastMCP."""

    return {
        "anyOf": [*variants, {"type": "null"}],
        "default": None,
        "description": description,
    }


def _nullable(schema: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "anyOf": [schema, {"type": "null"}],
        "default": None,
    }
    description = schema.get("description")
    if isinstance(description, str) and description:
        result["description"] = description
    return result


def _json_value_schema(description: str) -> dict[str, Any]:
    return {
        "description": description,
        "anyOf": [
            {"type": "object", "additionalProperties": True},
            {"type": "array", "items": {}},
            {"type": "string"},
            {"type": "number"},
            {"type": "boolean"},
            {"type": "null"},
        ],
    }


def _annotations(
    *, read_only: bool, destructive: bool, open_world: bool, idempotent: bool
) -> dict[str, bool]:
    return {
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "openWorldHint": open_world,
        "idempotentHint": idempotent,
    }


def _confirmation(
    *,
    required: bool = False,
    parameter: str | None = None,
    exact_phrase: str | None = None,
    when: str | None = None,
) -> dict[str, str | bool | None]:
    return {
        "required": required,
        "parameter": parameter,
        "exactPhrase": exact_phrase,
        "when": when,
    }


def _hash(payload: Any) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _descriptor(
    *,
    native_tool_name: str,
    aliases: list[str],
    title: str,
    description: str,
    category: str,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any],
    annotations: dict[str, bool],
    confirmation: dict[str, str | bool | None],
    documentation_url: str,
    navigation_role: str | None,
    tier: str,
) -> dict[str, Any]:
    base = {
        "serviceId": SERVICE_ID,
        "nativeToolName": native_tool_name,
        "canonicalName": f"{SERVICE_ID}.{native_tool_name}",
        "aliases": sorted(set(aliases)),
        "title": title,
        "description": description,
        "category": category,
        "deprecation": dict(_DEPRECATION),
        "inputSchema": input_schema,
        "outputSchema": output_schema,
        "annotations": annotations,
        "confirmation": confirmation,
        "documentationUrl": documentation_url,
        "navigationRole": navigation_role,
        "catalogVersion": TOOL_CATALOG_VERSION,
        "tier": tier,
    }
    return {**base, "descriptorHash": _hash(base)}


def _configuration_output_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "service": {"type": "string", "description": "Cloudflare MCP service identity."},
            "setup_status": {
                "type": "string",
                "description": "Whether authentication for the selected service mode is ready.",
            },
            "mode": {
                "type": "string",
                "description": "Startup-selected standalone or Portal access mode.",
            },
            "service_access_valid": {
                "type": "boolean",
                "description": "Whether this request passed mode-specific service authentication.",
            },
            "cloudflare_token_verification": _nullable(
                {
                    "type": "object",
                    "description": "Secret-safe result of optional Cloudflare token verification.",
                    "additionalProperties": True,
                }
            ),
        },
        required=["service", "setup_status", "mode", "service_access_valid"],
        description="Secret-safe Cloudflare MCP configuration status.",
        additional_properties=True,
    )


def _manifest_output_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "schemaVersion": {
                "type": "string",
                "description": "ToolManifest wire schema version.",
            },
            "serviceId": {"type": "string", "description": "Canonical Portal service ID."},
            "catalogVersion": {
                "type": "string",
                "description": "Immutable provider catalog version.",
            },
            "buildSha": {
                "type": "string",
                "description": "Source revision used by the running service.",
            },
            "descriptorHash": {
                "type": "string",
                "description": "SHA-256 over the canonical descriptor array.",
            },
            "counts": {
                "type": "object",
                "description": "Raw, agent-ready, legacy, and hidden descriptor counts.",
                "additionalProperties": {"type": "integer"},
            },
            "tools": {
                "type": "array",
                "description": "Lossless descriptors when include_descriptors is true.",
                "items": {"type": "object", "additionalProperties": True},
            },
            "commonWorkflows": {
                "type": "array",
                "description": "Recommended safe Cloudflare navigation flow.",
                "items": {"type": "string"},
            },
        },
        description="Cloudflare capabilities summary or lossless ToolManifest.",
        additional_properties=True,
    )


def _coverage_output_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "source": {
                "type": "object",
                "description": "Official Cloudflare OpenAPI source metadata.",
                "additionalProperties": True,
            },
            "operation_count": {
                "type": "integer",
                "description": "Total operations in the checked-in official schema snapshot.",
            },
            "filtered_count": {
                "type": "integer",
                "description": "Operations matching the supplied filters.",
            },
            "limit": {"type": "integer", "description": "Applied page size."},
            "offset": {"type": "integer", "description": "Applied result offset."},
            "operations": {
                "type": "array",
                "description": "Matching method/path/risk operation records.",
                "items": {"type": "object", "additionalProperties": True},
            },
        },
        required=["source", "operation_count", "filtered_count", "limit", "offset", "operations"],
        description="Filtered Cloudflare endpoint coverage page.",
    )


def _usage_output_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "tool_name": {"type": "string", "description": "Resolved native tool name."},
            "descriptor": {
                "type": "object",
                "description": "Complete lossless ToolManifest descriptor.",
                "additionalProperties": True,
            },
            "use_when": {"type": "string", "description": "When this tool is appropriate."},
            "side_effects": {
                "type": "string",
                "description": "State changes or external calls the tool may perform.",
            },
            "required_setup": {
                "type": "string",
                "description": "Configuration required before execution.",
            },
            "follow_up": {"type": "string", "description": "Recommended next agent action."},
            "safety_gates": {
                "type": "object",
                "description": (
                    "Risk-specific execution gates when the resolved tool can mutate provider "
                    "state."
                ),
                "properties": {
                    "write": {
                        "type": "string",
                        "description": "External signed one-use approval for write operations.",
                    },
                    "destructive": {
                        "type": "string",
                        "description": (
                            "External signed one-use approval for destructive operations."
                        ),
                    },
                    "high_risk": {
                        "type": "string",
                        "description": (
                            "Permanent denial of high-risk operations by the generic dispatcher."
                        ),
                    },
                },
                "required": ["write", "destructive", "high_risk"],
                "additionalProperties": False,
            },
        },
        required=[
            "tool_name",
            "descriptor",
            "use_when",
            "side_effects",
            "required_setup",
            "follow_up",
        ],
        description="Lossless Cloudflare tool reference and usage guidance.",
    )


def _search_output_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "query": {"type": "string", "description": "Normalized search request."},
            "include_legacy": {
                "type": "boolean",
                "description": "Whether legacy tools were eligible for matching.",
            },
            "count": {"type": "integer", "description": "Returned result count."},
            "results": {
                "type": "array",
                "description": "Deterministically ranked matching tool summaries.",
                "items": {
                    "type": "object",
                    "properties": {
                        "toolName": {"type": "string"},
                        "canonicalName": {"type": "string"},
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "category": {"type": "string"},
                        "tier": {"type": "string"},
                        "risk": {"type": "string"},
                        "score": {"type": "integer"},
                    },
                    "required": [
                        "toolName",
                        "canonicalName",
                        "title",
                        "description",
                        "category",
                        "tier",
                        "risk",
                        "score",
                    ],
                    "additionalProperties": False,
                },
            },
        },
        required=["query", "include_legacy", "count", "results"],
        description="Ranked Cloudflare MCP tool search results.",
    )


def _provider_output_schema() -> dict[str, Any]:
    return _object_schema(
        {
            "ok": {
                "type": "boolean",
                "description": "True only for a successful HTTP and Cloudflare semantic result.",
            },
            "executed": {
                "type": "boolean",
                "description": "Whether a provider request was actually sent.",
            },
            "status_code": _nullable(
                {"type": "integer", "description": "Cloudflare HTTP status code after execution."}
            ),
            "cloudflare_success": _nullable(
                {
                    "type": "boolean",
                    "description": "Cloudflare response success flag when present.",
                }
            ),
            "method": {"type": "string", "description": "Normalized request method."},
            "path": {"type": "string", "description": "Normalized Cloudflare API path."},
            "classification": {
                "type": "string",
                "description": "Schema-derived read, write, or destructive classification.",
            },
            "covered_by_schema": {
                "type": "boolean",
                "description": "Whether the path matched the official checked-in schema.",
            },
            "operation": _nullable(
                {
                    "type": "object",
                    "description": "Matched official operation metadata.",
                    "additionalProperties": True,
                }
            ),
            "approval": {
                "type": "object",
                "description": (
                    "External one-use mutation approval state and public signable payload."
                ),
                "additionalProperties": True,
            },
            "response": _json_value_schema("Secret-redacted and size-bounded provider response."),
            "response_metadata": _nullable(
                {
                    "type": "object",
                    "description": "Safe response media, size, and omission metadata.",
                    "additionalProperties": True,
                }
            ),
            "error": _nullable(
                {
                    "type": "object",
                    "description": "Safe semantic failure summary when ok is false.",
                    "additionalProperties": True,
                }
            ),
        },
        required=[
            "ok",
            "executed",
            "status_code",
            "cloudflare_success",
            "method",
            "path",
            "classification",
            "covered_by_schema",
            "operation",
            "approval",
            "response",
            "response_metadata",
            "error",
        ],
        description="Secret-safe Cloudflare REST response envelope.",
    )


def _build_descriptors() -> list[dict[str, Any]]:
    descriptors = [
        _descriptor(
            native_tool_name="check_configuration",
            aliases=["check_config", "configuration_health"],
            title="Check Cloudflare Configuration",
            description=(
                "Use this to verify mode-specific MCP service access and request-scoped provider "
                "credential routing without returning credential values. Set "
                "verify_cloudflare_token=true only when a live, read-only Cloudflare token check "
                "is needed. The default performs no provider request and changes no state."
            ),
            category="configuration",
            input_schema=_tool_input_schema(
                {
                    "verify_cloudflare_token": {
                        "type": "boolean",
                        "default": False,
                        "description": (
                            "When true, calls the Cloudflare user-token or account-token verify "
                            "endpoint with the resolved API token. When false, only validates "
                            "local/broker setup."
                        ),
                    }
                }
            ),
            output_schema=_configuration_output_schema(),
            annotations=_annotations(
                read_only=True, destructive=False, open_world=True, idempotent=True
            ),
            confirmation=_confirmation(),
            documentation_url=CLOUDFLARE_DOCS_URL,
            navigation_role="configuration_check",
            tier="agent_ready",
        ),
        _descriptor(
            native_tool_name="list_capabilities",
            aliases=["capability_list", "tool_manifest"],
            title="List Cloudflare MCP Capabilities",
            description=(
                "Use this to inspect Cloudflare MCP catalog counts, safe workflows, and the "
                "provider-owned ToolManifest. Set include_descriptors=true when the Portal or an "
                "advanced agent needs every lossless schema and annotation. This is local, "
                "read-only, and requires no Cloudflare provider credential."
            ),
            category="discovery",
            input_schema=_tool_input_schema(
                {
                    "include_descriptors": {
                        "type": "boolean",
                        "default": False,
                        "description": (
                            "Return every lossless ToolManifest descriptor when true; omit the "
                            "descriptor array from the compact summary when false."
                        ),
                    }
                }
            ),
            output_schema=_manifest_output_schema(),
            annotations=_annotations(
                read_only=True, destructive=False, open_world=False, idempotent=True
            ),
            confirmation=_confirmation(),
            documentation_url=CLOUDFLARE_DOCS_URL,
            navigation_role="capability_index",
            tier="agent_ready",
        ),
        _descriptor(
            native_tool_name="get_endpoint_coverage",
            aliases=["endpoint_coverage", "find_cloudflare_endpoints"],
            title="Get Cloudflare Endpoint Coverage",
            description=(
                "Use this to search the checked-in official Cloudflare OpenAPI inventory by "
                "feature, method, path text, or risk before considering an advanced API request. "
                "It returns a paginated local coverage page, performs no provider request, and "
                "does not imply that the mixed-risk legacy dispatcher is safe for default use."
            ),
            category="operations",
            input_schema=_tool_input_schema(
                {
                    "feature_area": _optional_tool_input(
                        [{"type": "string"}],
                        description="Optional case-insensitive Cloudflare feature/tag filter.",
                    ),
                    "method": _optional_tool_input(
                        [
                            {
                                "type": "string",
                                "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                            }
                        ],
                        description="Optional HTTP method filter.",
                    ),
                    "path_contains": _optional_tool_input(
                        [{"type": "string"}],
                        description=(
                            "Optional case-insensitive substring to match endpoint paths."
                        ),
                    ),
                    "classification": _optional_tool_input(
                        [
                            {
                                "type": "string",
                                "enum": ["read", "write", "destructive"],
                            }
                        ],
                        description="Optional mutability/risk classification filter.",
                    ),
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                        "default": 50,
                        "description": "Maximum operations to return, capped at 200.",
                    },
                    "offset": {
                        "type": "integer",
                        "minimum": 0,
                        "default": 0,
                        "description": "Pagination offset into the filtered coverage matrix.",
                    },
                }
            ),
            output_schema=_coverage_output_schema(),
            annotations=_annotations(
                read_only=True, destructive=False, open_world=False, idempotent=True
            ),
            confirmation=_confirmation(),
            documentation_url=CLOUDFLARE_SCHEMA_URL,
            navigation_role="coverage_lookup",
            tier="agent_ready",
        ),
        _descriptor(
            native_tool_name="get_tool_usage",
            aliases=["tool_reference", "describe_tool"],
            title="Get Cloudflare Tool Usage",
            description=(
                "Use this when an agent already has a Cloudflare native name, canonical name, or "
                "exact alias and needs its complete descriptor, setup, side effects, and next "
                "step. "
                "This resolves local catalog metadata only and performs no Cloudflare request."
            ),
            category="reference",
            input_schema=_tool_input_schema(
                {
                    "tool_name": {
                        "type": "string",
                        "minLength": 1,
                        "description": (
                            "Native name, cloudflare-prefixed canonical name, or exact alias of "
                            "the tool to explain."
                        ),
                    }
                },
                required=["tool_name"],
            ),
            output_schema=_usage_output_schema(),
            annotations=_annotations(
                read_only=True, destructive=False, open_world=False, idempotent=True
            ),
            confirmation=_confirmation(),
            documentation_url=CLOUDFLARE_DOCS_URL,
            navigation_role="usage_reference",
            tier="agent_ready",
        ),
        _descriptor(
            native_tool_name="find_tools",
            aliases=["search_tools", "discover_tools"],
            title="Find Cloudflare Tools",
            description=(
                "Use this for deterministic punctuation-normalized, multi-token search across "
                "Cloudflare MCP names, aliases, titles, descriptions, and categories. Default "
                "results contain only agent-ready local navigation tools; set include_legacy=true "
                "only for advanced discovery of the mixed-risk API dispatcher."
            ),
            category="discovery",
            input_schema=_tool_input_schema(
                {
                    "query": {
                        "type": "string",
                        "minLength": 1,
                        "description": (
                            "Natural-language, category, alias, or tool-name search text."
                        ),
                    },
                    "categories": _optional_tool_input(
                        [{"type": "array", "items": {"type": "string"}}],
                        description="Optional exact Cloudflare tool category filters.",
                    ),
                    "include_legacy": {
                        "type": "boolean",
                        "default": False,
                        "description": "Include advanced legacy tools when true.",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 25,
                        "default": 8,
                        "description": "Maximum ranked matches to return, from 1 through 25.",
                    },
                },
                required=["query"],
            ),
            output_schema=_search_output_schema(),
            annotations=_annotations(
                read_only=True, destructive=False, open_world=False, idempotent=True
            ),
            confirmation=_confirmation(),
            documentation_url=CLOUDFLARE_DOCS_URL,
            navigation_role="tool_search",
            tier="agent_ready",
        ),
        _descriptor(
            native_tool_name="cloudflare_api_request",
            aliases=["api_request", "raw_api_request"],
            title="Execute Advanced Cloudflare API Request",
            description=(
                "Advanced compatibility tool spanning read, write, and destructive operations "
                "from the pinned Cloudflare schema with a request-scoped credential. "
                "It is visible in MCP protocol discovery but excluded from find_tools defaults. "
                "Ordinary mutations require an externally signed, expiring, one-use approval; "
                "high-risk credential, billing, commerce, and account-administration operations "
                "are permanently blocked from this dispatcher."
            ),
            category="advanced",
            input_schema=_tool_input_schema(
                {
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                        "description": "Cloudflare REST method to execute.",
                    },
                    "path": {
                        "type": "string",
                        "minLength": 1,
                        "description": (
                            "Cloudflare API path, for example /zones or "
                            "/zones/{zone_id}/dns_records with real IDs substituted. Full "
                            "https://api.cloudflare.com/client/v4 URLs are also accepted."
                        ),
                    },
                    "query": _optional_tool_input(
                        [{"type": "object", "additionalProperties": True}],
                        description="Optional query parameters to send to Cloudflare.",
                    ),
                    "body": _optional_tool_input(
                        [
                            {"type": "object", "additionalProperties": True},
                            {"type": "array", "items": {}},
                        ],
                        description="Optional JSON body for POST, PUT, or PATCH requests.",
                    ),
                    "content_type": _optional_tool_input(
                        [
                            {
                                "type": "string",
                                "enum": [
                                    "application/json",
                                    "application/merge-patch+json",
                                    "application/scim+json",
                                ],
                            }
                        ],
                        description=(
                            "Optional JSON media type. It must be advertised by the pinned "
                            "operation; application/json is selected automatically when available."
                        ),
                    ),
                    "timeout_seconds": {
                        "type": "number",
                        "minimum": 1,
                        "maximum": 120,
                        "default": 30.0,
                        "description": "Cloudflare request timeout in seconds.",
                    },
                    "max_response_bytes": {
                        "type": "integer",
                        "minimum": 4096,
                        "maximum": 245760,
                        "default": 100000,
                        "description": (
                            "Maximum redacted response payload bytes returned to the agent."
                        ),
                    },
                },
                required=["method", "path"],
            ),
            output_schema=_provider_output_schema(),
            annotations=_annotations(
                read_only=False, destructive=True, open_world=True, idempotent=False
            ),
            confirmation=_confirmation(
                required=True,
                parameter="x-mcp-approval-attestation",
                exact_phrase=None,
                when=(
                    "Ordinary mutations require an externally signed, principal-bound, expiring, "
                    "one-use approval in the x-mcp-approval-attestation HTTP header. High-risk "
                    "operations are not callable through this dispatcher."
                ),
            ),
            documentation_url=CLOUDFLARE_DOCS_URL,
            navigation_role=None,
            tier="legacy",
        ),
    ]
    return sorted(descriptors, key=lambda item: str(item["nativeToolName"]))


@lru_cache(maxsize=1)
def tool_descriptors() -> tuple[dict[str, Any], ...]:
    """Return stable descriptors in native-tool-name order."""

    return tuple(_build_descriptors())


def build_tool_manifest(build_sha: str | None = None) -> dict[str, Any]:
    """Build the lossless manifest; build identity does not affect descriptor hashes."""

    tools = [dict(item) for item in tool_descriptors()]
    counts = {
        "raw": len(tools),
        "agentReady": sum(item["tier"] == "agent_ready" for item in tools),
        "legacy": sum(item["tier"] == "legacy" for item in tools),
        "hidden": sum(item["tier"] == "hidden" for item in tools),
    }
    return {
        "schemaVersion": TOOL_MANIFEST_SCHEMA_VERSION,
        "serviceId": SERVICE_ID,
        "catalogVersion": TOOL_CATALOG_VERSION,
        "buildSha": (
            build_sha or os.getenv("MCP_BUILD_SHA") or os.getenv("BUILD_SHA") or "development"
        ).strip()
        or "development",
        "descriptorHash": _hash(tools),
        "counts": counts,
        "tools": tools,
    }


def tool_descriptor(identity: str) -> dict[str, Any]:
    """Resolve one native, canonical, or alias identity."""

    needle = identity.strip().casefold()
    for descriptor in tool_descriptors():
        identities = {
            str(descriptor["nativeToolName"]).casefold(),
            str(descriptor["canonicalName"]).casefold(),
            *(str(alias).casefold() for alias in descriptor["aliases"]),
        }
        if needle in identities:
            return dict(descriptor)
    raise KeyError(f"Unknown Cloudflare MCP tool: {identity}")


def _search_tokens(value: str) -> list[str]:
    return [token for token in re.sub(r"[^a-z0-9]+", " ", value.casefold()).split() if token]


def search_tools(
    query: str,
    *,
    categories: list[str] | None = None,
    include_legacy: bool = False,
    limit: int = 8,
) -> dict[str, Any]:
    """Rank descriptors with deterministic punctuation-normalized multi-token search."""

    tokens = _search_tokens(query)
    if not tokens:
        return {"query": query.strip(), "include_legacy": include_legacy, "count": 0, "results": []}

    category_filter = {value.strip().casefold() for value in categories or [] if value.strip()}
    ranked: list[tuple[int, str, dict[str, Any]]] = []
    for descriptor in tool_descriptors():
        if descriptor["tier"] != "agent_ready" and not include_legacy:
            continue
        if category_filter and str(descriptor["category"]).casefold() not in category_filter:
            continue

        native = str(descriptor["nativeToolName"]).casefold()
        canonical = str(descriptor["canonicalName"]).casefold()
        aliases = [str(value).casefold() for value in descriptor["aliases"]]
        title = str(descriptor["title"]).casefold()
        description = str(descriptor["description"]).casefold()
        category = str(descriptor["category"]).casefold()
        normalized_fields = {
            "native": " ".join(_search_tokens(native)),
            "canonical": " ".join(_search_tokens(canonical)),
            "aliases": [" ".join(_search_tokens(value)) for value in aliases],
            "title": " ".join(_search_tokens(title)),
            "description": " ".join(_search_tokens(description)),
            "category": " ".join(_search_tokens(category)),
        }
        if not all(
            any(
                token in field
                for field in [
                    normalized_fields["native"],
                    normalized_fields["canonical"],
                    *normalized_fields["aliases"],
                    normalized_fields["title"],
                    normalized_fields["description"],
                    normalized_fields["category"],
                ]
            )
            for token in tokens
        ):
            continue

        score = 0
        joined_query = " ".join(tokens)
        if joined_query == normalized_fields["native"]:
            score += 500
        if joined_query == normalized_fields["canonical"]:
            score += 450
        if joined_query in normalized_fields["aliases"]:
            score += 400
        for token in tokens:
            if token in normalized_fields["native"]:
                score += 80
            if token in normalized_fields["canonical"]:
                score += 70
            if any(token in alias for alias in normalized_fields["aliases"]):
                score += 65
            if token in normalized_fields["title"]:
                score += 45
            if token in normalized_fields["category"]:
                score += 30
            if token in normalized_fields["description"]:
                score += 10
        ranked.append((score, native, descriptor))

    results = []
    for score, _, descriptor in sorted(ranked, key=lambda row: (-row[0], row[1]))[
        : min(max(limit, 1), 25)
    ]:
        annotations = descriptor["annotations"]
        risk = (
            "destructive"
            if annotations["destructiveHint"]
            else "read"
            if annotations["readOnlyHint"]
            else "write"
        )
        results.append(
            {
                "toolName": descriptor["nativeToolName"],
                "canonicalName": descriptor["canonicalName"],
                "title": descriptor["title"],
                "description": descriptor["description"],
                "category": descriptor["category"],
                "tier": descriptor["tier"],
                "risk": risk,
                "score": score,
            }
        )
    return {
        "query": query.strip(),
        "include_legacy": include_legacy,
        "count": len(results),
        "results": results,
    }
