#!/usr/bin/env python3
"""Generate Cloudflare endpoint coverage artifacts from the official OpenAPI schema."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cloudflare_mcp.coverage import (
    ENDPOINT_POLICY_VERSION,
    REVIEWED_OPERATION_OVERRIDES,
    classify_operation,
    operation_risk_flags,
    reviewed_operation_override,
)

METHODS = {"get", "post", "put", "patch", "delete"}
SOURCE_COMMIT = "aefa753f1190c85866f65dcc7f348e18c7a1ca4a"
SOURCE_SHA256 = "6c141cf38b45a514fcba04d322d43916eaba179a4442c8d91afaf5e7a66c8f1f"
SOURCE_LICENSE = "BSD-3-Clause"
SOURCE_RETRIEVED_AT = "2026-06-14T05:04:13+00:00"
SOURCE_URL = (
    f"https://raw.githubusercontent.com/cloudflare/api-schemas/{SOURCE_COMMIT}/openapi.json"
)
SOURCE_REPO = "https://github.com/cloudflare/api-schemas"
JSON_MEDIA_TYPES = {
    "application/json",
    "application/merge-patch+json",
    "application/scim+json",
}
SIDE_EFFECTING_GET_PREFIXES = (
    "acquire ",
    "activate ",
    "close ",
    "connect ",
    "generate ",
    "open websocket ",
)
SCHEMA_SENSITIVITY_POLICY_ID = "schema.credentials.no_generic_projection"
SCHEMA_SENSITIVITY_SIGNALS = (
    "credential_semantics",
    "credential_like_read_only",
    "credential_like_write_only",
    "format_password",
    "x_sensitive",
)
_SCHEMA_WORD_RE = re.compile(r"[a-z0-9]+")
_SCHEMA_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_CREDENTIAL_WORDS = {
    "credential",
    "credentials",
    "passphrase",
    "passphrases",
    "password",
    "passwords",
    "secret",
    "secrets",
    "token",
    "tokens",
}
_SCHEMA_ARRAY_KEYS = ("allOf", "anyOf", "oneOf", "prefixItems")
_SCHEMA_MAP_KEYS = ("dependentSchemas", "patternProperties", "properties")
_SCHEMA_SINGLE_KEYS = (
    "additionalProperties",
    "contains",
    "else",
    "if",
    "items",
    "not",
    "propertyNames",
    "then",
    "unevaluatedProperties",
)
_SCHEMA_ANNOTATION_KEYS = {
    "default",
    "deprecated",
    "description",
    "example",
    "examples",
    "externalDocs",
    "nullable",
    "readOnly",
    "title",
    "writeOnly",
    "xml",
}


def load_pinned_schema(path: Path) -> dict[str, Any]:
    """Load the one reviewed schema snapshot and reject byte-level drift."""

    raw = path.read_bytes()
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != SOURCE_SHA256:
        raise ValueError(
            f"Cloudflare schema SHA256 mismatch: expected {SOURCE_SHA256}, got {actual_sha256}"
        )
    spec = json.loads(raw)
    if not isinstance(spec, dict):
        raise ValueError("Cloudflare schema root must be a JSON object")
    return spec


def resolve_local_pointer(spec: dict[str, Any], reference: Any) -> Any:
    """Resolve one local JSON Pointer and reject unsupported or stale refs."""

    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise ValueError(f"Unsupported non-local OpenAPI reference: {reference!r}")
    target: Any = spec
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or part not in target:
            raise ValueError(f"Unresolvable OpenAPI reference: {reference}")
        target = target[part]
    return target


def resolve_local_ref(spec: dict[str, Any], value: Any) -> Any:
    """Resolve a chain of local JSON Pointer references."""

    seen: set[str] = set()
    while isinstance(value, dict) and "$ref" in value:
        reference = value["$ref"]
        if not isinstance(reference, str):
            raise ValueError(f"Unsupported non-local OpenAPI reference: {reference!r}")
        if reference in seen:
            raise ValueError(f"Cyclic OpenAPI reference: {reference}")
        seen.add(reference)
        value = resolve_local_pointer(spec, reference)
    return value


def _location_key(value: Any) -> str:
    return f"[{json.dumps(str(value), ensure_ascii=True)}]"


def _schema_tokens(value: str) -> tuple[str, ...]:
    expanded = _SCHEMA_CAMEL_BOUNDARY_RE.sub(" ", value)
    return tuple(_SCHEMA_WORD_RE.findall(expanded.casefold()))


def _credential_like(value: str) -> bool:
    tokens = set(_schema_tokens(value))
    return (
        bool(tokens & _CREDENTIAL_WORDS)
        or ("key" in tokens and bool(tokens & {"access", "api", "private"}))
        or "privkey" in tokens
    )


def _semantic_credential_field(
    property_name: str | None,
    value: dict[str, Any],
    *,
    direction: str,
    description_context: str = "",
) -> bool:
    """Recognize strong credential value fields without trusting provider markers."""

    if property_name is None or str(value.get("type") or "").casefold() != "string":
        return False
    normalized_name = "_".join(_schema_tokens(property_name))
    description = " ".join(
        str(part).casefold()
        for part in (description_context, value.get("description") or "")
        if part
    )
    strong_names = {
        "access_key",
        "access_token",
        "api_key",
        "auth_token",
        "authorization",
        "build_token_secret",
        "card_number",
        "cep_jwt",
        "client_secret",
        "invoice_pdf",
        "license_key",
        "md5_key",
        "ownership_validation_token",
        "pairing_key",
        "payment_nonce",
        "private_key",
        "privkey",
        "r2_secret",
        "refresh_token",
        "secret_access_key",
        "signed_url",
        "stream_key",
        "validation_code",
    }
    if normalized_name in strong_names:
        return True
    if normalized_name in {"download_url", "upload_url"} or normalized_name.endswith(
        ("_download_url", "_upload_url")
    ):
        return True
    if direction == "success_response" and normalized_name in {
        "devtools_frontend_url",
        "web_socket_debugger_url",
        "ws_url",
    }:
        return True
    if normalized_name == "token":
        return True
    if normalized_name == "password":
        return not any(
            phrase in description
            for phrase in ("expression that selects", "ruleset expression", "matching the password")
        )
    if normalized_name == "secret":
        return not any(
            phrase in description
            for phrase in (
                "corresponding secret name",
                "name of the secret",
                "secret being referenced",
                "secret reference",
            )
        )
    if normalized_name == "private_credential":
        return direction == "request"
    if normalized_name == "token_id":
        return "token integration key" in description or "integration token" in description
    return False


def sensitive_schema_findings(
    spec: dict[str, Any],
    schema: Any,
    *,
    direction: str,
    location: str,
    property_name: str | None = None,
    description_context: str = "",
) -> list[dict[str, str]]:
    """Find credential-sensitive schema signals through local refs and composition."""

    findings: set[tuple[str, str, str]] = set()

    def visit(
        value: Any,
        current_location: str,
        current_property_name: str | None = property_name,
        inherited_description: str = description_context,
        ref_stack: frozenset[str] = frozenset(),
    ) -> None:
        if isinstance(value, list):
            for index, item in enumerate(value):
                visit(
                    item,
                    f"{current_location}[{index}]",
                    current_property_name,
                    inherited_description,
                    ref_stack,
                )
            return
        if not isinstance(value, dict):
            return

        if value.get("x-sensitive") is True:
            findings.add((direction, current_location, "x_sensitive"))
        if str(value.get("format") or "").casefold() == "password":
            findings.add((direction, current_location, "format_password"))
        credential_context = " ".join(
            part
            for part in (
                current_property_name or "",
                inherited_description,
                str(value.get("description") or ""),
            )
            if part
        )
        if value.get("writeOnly") is True and _credential_like(credential_context):
            findings.add((direction, current_location, "credential_like_write_only"))
        if _semantic_credential_field(
            current_property_name,
            value,
            direction=direction,
            description_context=inherited_description,
        ):
            findings.add((direction, current_location, "credential_semantics"))
        # Cloudflare's DNSSEC ZSK contract exposes `privkey` as read-only byte data without
        # x-sensitive. The exact credential-bearing property name is enough to fail closed;
        # descriptions or examples alone never activate this signal.
        if (
            value.get("readOnly") is True
            and current_property_name is not None
            and "".join(_schema_tokens(current_property_name)) == "privkey"
        ):
            findings.add((direction, current_location, "credential_like_read_only"))

        reference = value.get("$ref")
        if reference is not None:
            if not isinstance(reference, str):
                raise ValueError(f"Unsupported non-local OpenAPI reference: {reference!r}")
            target = resolve_local_pointer(spec, reference)
            if reference not in ref_stack:
                visit(
                    target,
                    f"{current_location}.$ref{_location_key(reference)}",
                    current_property_name,
                    inherited_description,
                    ref_stack | {reference},
                )

        for key in _SCHEMA_ARRAY_KEYS:
            nested = value.get(key)
            if isinstance(nested, list):
                for index, item in enumerate(nested):
                    visit(
                        item,
                        f"{current_location}.{key}[{index}]",
                        current_property_name,
                        inherited_description,
                        ref_stack,
                    )
        for key in _SCHEMA_MAP_KEYS:
            nested = value.get(key)
            if isinstance(nested, dict):
                for name, item in sorted(nested.items(), key=lambda pair: str(pair[0])):
                    nested_property = str(name) if key == "properties" else current_property_name
                    visit(
                        item,
                        f"{current_location}.{key}{_location_key(name)}",
                        nested_property,
                        "" if key == "properties" else inherited_description,
                        ref_stack,
                    )
        for key in _SCHEMA_SINGLE_KEYS:
            nested = value.get(key)
            if isinstance(nested, (dict, list)):
                visit(
                    nested,
                    f"{current_location}.{key}",
                    current_property_name,
                    inherited_description,
                    ref_stack,
                )

    visit(schema, location)
    return [
        {"direction": found_direction, "location": found_location, "signal": signal}
        for found_direction, found_location, signal in sorted(findings)
    ]


def _dereferenced_contract_objects(
    spec: dict[str, Any], value: Any, location: str
) -> list[tuple[dict[str, Any], str]]:
    """Return each object in a local-ref contract chain with auditable locations."""

    chain: list[tuple[dict[str, Any], str]] = []
    seen: set[str] = set()
    while isinstance(value, dict):
        chain.append((value, location))
        reference = value.get("$ref")
        if reference is None:
            break
        if not isinstance(reference, str):
            raise ValueError(f"Unsupported non-local OpenAPI reference: {reference!r}")
        if reference in seen:
            raise ValueError(f"Cyclic OpenAPI reference: {reference}")
        seen.add(reference)
        value = resolve_local_pointer(spec, reference)
        location = f"{location}.$ref{_location_key(reference)}"
    return chain


def _contract_object_findings(
    spec: dict[str, Any],
    value: Any,
    *,
    direction: str,
    location: str,
) -> list[dict[str, str]]:
    """Inspect a parameter/header/media wrapper and its declared schema."""

    findings: list[dict[str, str]] = []
    for resolved, resolved_location in _dereferenced_contract_objects(spec, value, location):
        if resolved.get("x-sensitive") is True:
            findings.append(
                {
                    "direction": direction,
                    "location": resolved_location,
                    "signal": "x_sensitive",
                }
            )
        if "schema" in resolved:
            wrapper_name = resolved.get("name")
            property_name = str(wrapper_name) if isinstance(wrapper_name, str) else None
            findings.extend(
                sensitive_schema_findings(
                    spec,
                    resolved["schema"],
                    direction=direction,
                    location=f"{resolved_location}.schema",
                    property_name=property_name,
                    description_context=str(resolved.get("description") or ""),
                )
            )
        content = resolved.get("content")
        if isinstance(content, dict):
            for media_type, media in sorted(content.items(), key=lambda pair: str(pair[0])):
                media_location = f"{resolved_location}.content{_location_key(media_type)}"
                findings.extend(
                    _contract_object_findings(
                        spec,
                        media,
                        direction=direction,
                        location=media_location,
                    )
                )
    return findings


def operation_sensitive_schema_findings(
    spec: dict[str, Any], path_item: dict[str, Any], operation: dict[str, Any]
) -> list[dict[str, str]]:
    """Inspect request and successful-response contracts for sensitive schemas."""

    findings: list[dict[str, str]] = []
    for scope, parameters in (
        ("path_parameters", path_item.get("parameters")),
        ("operation_parameters", operation.get("parameters")),
    ):
        if not isinstance(parameters, list):
            continue
        for index, parameter in enumerate(parameters):
            findings.extend(
                _contract_object_findings(
                    spec,
                    parameter,
                    direction="request",
                    location=f"request.{scope}[{index}]",
                )
            )

    if "requestBody" in operation:
        findings.extend(
            _contract_object_findings(
                spec,
                operation["requestBody"],
                direction="request",
                location="request.body",
            )
        )

    responses = operation.get("responses")
    if isinstance(responses, dict):
        for status, response in sorted(responses.items(), key=lambda pair: str(pair[0])):
            normalized_status = str(status).casefold()
            if not (normalized_status.startswith("2") or normalized_status == "default"):
                continue
            response_location = f"success_response{_location_key(status)}"
            for resolved, resolved_location in _dereferenced_contract_objects(
                spec, response, response_location
            ):
                if resolved.get("x-sensitive") is True:
                    findings.append(
                        {
                            "direction": "success_response",
                            "location": resolved_location,
                            "signal": "x_sensitive",
                        }
                    )
                content = resolved.get("content")
                if isinstance(content, dict):
                    for media_type, media in sorted(content.items(), key=lambda pair: str(pair[0])):
                        findings.extend(
                            _contract_object_findings(
                                spec,
                                media,
                                direction="success_response",
                                location=(
                                    f"{resolved_location}.content{_location_key(media_type)}"
                                ),
                            )
                        )
                headers = resolved.get("headers")
                if isinstance(headers, dict):
                    for header_name, header in sorted(
                        headers.items(), key=lambda pair: str(pair[0])
                    ):
                        findings.extend(
                            _contract_object_findings(
                                spec,
                                header,
                                direction="success_response",
                                location=(
                                    f"{resolved_location}.headers{_location_key(header_name)}"
                                ),
                            )
                        )

    unique = {
        (finding["direction"], finding["location"], finding["signal"]): finding
        for finding in findings
    }
    return [unique[key] for key in sorted(unique)]


def validate_sensitive_schema_policy(rows: list[dict[str, Any]]) -> None:
    """Fail generation if a sensitive operation is callable or metadata is inconsistent."""

    invalid: list[str] = []
    for row in rows:
        findings = row.get("sensitive_schema_findings")
        if not isinstance(findings, list):
            invalid.append(f"{row.get('method')} {row.get('path_template')} (missing findings)")
            continue
        request_sensitive = any(finding.get("direction") == "request" for finding in findings)
        response_sensitive = any(
            finding.get("direction") == "success_response" for finding in findings
        )
        metadata_matches = (
            row.get("sensitive_request_schema") is request_sensitive
            and row.get("sensitive_success_response_schema") is response_sensitive
        )
        if findings:
            policy_valid = (
                row.get("coverage_status") == "catalog_only"
                and row.get("transport_support") == "catalog_only"
                and row.get("mcp_tool") is None
                and row.get("high_risk") is True
                and "credentials" in row.get("risk_flags", [])
                and row.get("schema_policy_id") == SCHEMA_SENSITIVITY_POLICY_ID
                and bool(row.get("schema_policy_reason"))
            )
        else:
            policy_valid = (
                row.get("schema_policy_id") is None and row.get("schema_policy_reason") is None
            )
        if not metadata_matches or not policy_valid:
            invalid.append(f"{row.get('method')} {row.get('path_template')}")
    if invalid:
        raise ValueError("Sensitive schema policy invariant failed: " + ", ".join(invalid))


def request_content_types(spec: dict[str, Any], operation: dict[str, Any]) -> list[str]:
    """Return stable request media types after resolving requestBody refs."""

    request_body = operation.get("requestBody")
    if request_body is None:
        return []
    resolved = resolve_local_ref(spec, request_body)
    if not isinstance(resolved, dict) or not isinstance(resolved.get("content"), dict):
        return []
    return sorted(str(media_type).casefold() for media_type in resolved["content"])


def request_body_required(spec: dict[str, Any], operation: dict[str, Any]) -> bool:
    """Return the reviewed OpenAPI request-body presence requirement."""

    request_body = operation.get("requestBody")
    if request_body is None:
        return False
    resolved = resolve_local_ref(spec, request_body)
    return isinstance(resolved, dict) and resolved.get("required") is True


def schema_is_effectively_unconstrained(spec: dict[str, Any], schema: Any) -> bool:
    """Detect schemas that declare no reviewable value or object-field contract."""

    resolved = resolve_local_ref(spec, schema)
    if not isinstance(resolved, dict) or not resolved:
        return True

    contract = {key: value for key, value in resolved.items() if key not in _SCHEMA_ANNOTATION_KEYS}
    if not contract:
        return True
    if str(contract.get("type") or "").casefold() != "object":
        return False

    properties = contract.get("properties")
    pattern_properties = contract.get("patternProperties")
    composed = any(
        isinstance(contract.get(keyword), list) and bool(contract[keyword])
        for keyword in ("allOf", "anyOf", "oneOf")
    )
    fixed_values = bool(contract.get("enum")) or "const" in contract
    closed_empty_object = contract.get("additionalProperties") is False
    return not any(
        (
            isinstance(properties, dict) and bool(properties),
            isinstance(pattern_properties, dict) and bool(pattern_properties),
            composed,
            fixed_values,
            closed_empty_object,
        )
    )


def has_unconstrained_request_json_schema(spec: dict[str, Any], operation: dict[str, Any]) -> bool:
    """Detect request-body contracts that cannot support JSON field review."""

    if "requestBody" not in operation:
        return False
    resolved_body = resolve_local_ref(spec, operation["requestBody"])
    if not isinstance(resolved_body, dict):
        return True
    content = resolved_body.get("content")
    if not isinstance(content, dict) or not content:
        return True
    for media_type, media_contract in content.items():
        if str(media_type).casefold() not in JSON_MEDIA_TYPES:
            continue
        resolved_media = resolve_local_ref(spec, media_contract)
        if not isinstance(resolved_media, dict):
            return True
        schema = resolved_media.get("schema")
        if not isinstance(schema, dict):
            return True
        if schema_is_effectively_unconstrained(spec, schema):
            return True
    return False


def required_provider_headers(
    spec: dict[str, Any], path_item: dict[str, Any], operation: dict[str, Any]
) -> list[str]:
    """Return required request headers the fixed dispatcher cannot accept from callers."""

    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for owner in (path_item, operation):
        parameters = owner.get("parameters", [])
        if not isinstance(parameters, list):
            continue
        for parameter in parameters:
            resolved = resolve_local_ref(spec, parameter)
            if not isinstance(resolved, dict):
                continue
            location = str(resolved.get("in") or "").casefold()
            name = str(resolved.get("name") or "").strip()
            if not location or not name:
                continue
            merged[(location, name.casefold())] = resolved
    return sorted(
        str(parameter["name"])
        for (location, _), parameter in merged.items()
        if location == "header" and parameter.get("required") is True
    )


def token_auth_compatibility(spec: dict[str, Any], operation: dict[str, Any]) -> tuple[bool, str]:
    """Prove that the fixed Bearer-token client matches the pinned operation contract."""

    security = operation.get("security", spec.get("security", []))
    if isinstance(security, list):
        if not security:
            return True, "anonymous_allowed"
        if any(isinstance(requirement, dict) and not requirement for requirement in security):
            return True, "anonymous_allowed"
        if any(
            isinstance(requirement, dict) and bool({"api_token", "bearerAuth"} & set(requirement))
            for requirement in security
        ):
            return True, "declared_bearer_token"

    token_group = operation.get("x-api-token-group")
    if (isinstance(token_group, list) and bool(token_group)) or (
        isinstance(token_group, str) and bool(token_group.strip())
    ):
        return True, "provider_token_group"
    return False, "no_bearer_token_evidence"


def success_response_content_types(spec: dict[str, Any], operation: dict[str, Any]) -> list[str]:
    """Return media types declared by successful 2xx responses."""

    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return []

    media_types: set[str] = set()
    for status, response in responses.items():
        if not str(status).startswith("2"):
            continue
        resolved = resolve_local_ref(spec, response)
        if not isinstance(resolved, dict) or not isinstance(resolved.get("content"), dict):
            continue
        media_types.update(str(media_type).casefold() for media_type in resolved["content"])
    return sorted(media_types)


def has_declared_success_response(operation: dict[str, Any]) -> bool:
    """Return true only when the operation declares at least one explicit 2xx response."""

    responses = operation.get("responses")
    return isinstance(responses, dict) and any(str(status).startswith("2") for status in responses)


def has_ambiguous_bodyless_success_response(
    spec: dict[str, Any], operation: dict[str, Any]
) -> bool:
    """Reject non-204/205 success contracts that omit a response content contract."""

    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return False
    for status, response in responses.items():
        normalized_status = str(status)
        if not normalized_status.startswith("2") or normalized_status in {"204", "205"}:
            continue
        resolved_response = resolve_local_ref(spec, response)
        if not isinstance(resolved_response, dict):
            continue
        content = resolved_response.get("content")
        if content is None or content == {}:
            return True
    return False


def has_unconstrained_success_json_schema(spec: dict[str, Any], operation: dict[str, Any]) -> bool:
    """Detect supported successful JSON media whose schema is missing or empty."""

    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return False
    for status, response in responses.items():
        if not str(status).startswith("2"):
            continue
        resolved_response = resolve_local_ref(spec, response)
        if not isinstance(resolved_response, dict):
            return True
        if "content" not in resolved_response:
            continue
        content = resolved_response["content"]
        if not isinstance(content, dict):
            return True
        for media_type, media_contract in content.items():
            if str(media_type).casefold() not in JSON_MEDIA_TYPES:
                continue
            resolved_media = resolve_local_ref(spec, media_contract)
            if not isinstance(resolved_media, dict):
                return True
            schema = resolved_media.get("schema")
            if not isinstance(schema, dict):
                return True
            if schema_is_effectively_unconstrained(spec, schema):
                return True
    return False


def transport_metadata(
    request_types: list[str],
    response_types: list[str],
    *,
    required_headers: list[str],
    token_auth_compatible: bool,
    unconstrained_request_json_schema: bool,
    declared_success_response: bool,
    ambiguous_bodyless_success_response: bool,
    unconstrained_success_json_schema: bool,
) -> tuple[str, str, str]:
    """Describe whether the JSON-only dispatcher can represent an operation."""

    if required_headers:
        return (
            "catalog_only",
            "catalog_only",
            "Catalog only; the operation requires provider request headers the fixed dispatcher "
            f"does not accept: {', '.join(required_headers)}.",
        )
    if not token_auth_compatible:
        return (
            "catalog_only",
            "catalog_only",
            "Catalog only; the pinned operation has no Bearer API-token compatibility evidence.",
        )
    if unconstrained_request_json_schema:
        return (
            "catalog_only",
            "catalog_only",
            "Catalog only; the JSON request body has no reviewable schema contract.",
        )
    if not declared_success_response:
        return (
            "catalog_only",
            "catalog_only",
            "Catalog only; the pinned operation declares no explicit 2xx response contract.",
        )
    if ambiguous_bodyless_success_response:
        return (
            "catalog_only",
            "catalog_only",
            "Catalog only; a non-204/205 success response omits an explicit content contract.",
        )
    if unconstrained_success_json_schema:
        return (
            "catalog_only",
            "catalog_only",
            "Catalog only; a successful JSON response has no reviewable schema contract.",
        )

    unsupported_request = bool(request_types) and not any(
        media_type in JSON_MEDIA_TYPES for media_type in request_types
    )
    unsupported_response = any(media_type not in JSON_MEDIA_TYPES for media_type in response_types)
    if not unsupported_request and not unsupported_response:
        return (
            "json",
            "callable",
            "Callable through cloudflare_api_request with a declared JSON request media type "
            "or no request body; successful responses are JSON or bodyless.",
        )

    reasons: list[str] = []
    if unsupported_request:
        reasons.append(f"unsupported request media types: {', '.join(request_types)}")
    if unsupported_response:
        unsupported_types = [
            media_type for media_type in response_types if media_type not in JSON_MEDIA_TYPES
        ]
        reasons.append(
            f"unsupported successful-response media types: {', '.join(unsupported_types)}"
        )
    return (
        "catalog_only",
        "catalog_only",
        "Catalog only; the JSON dispatcher cannot safely carry " + "; ".join(reasons) + ".",
    )


def is_side_effecting_get_candidate(method: str, summary: str) -> bool:
    """Flag imperative GET summaries that require an explicit reviewed policy entry."""

    normalized_summary = " ".join(summary.casefold().split())
    return method.upper() == "GET" and normalized_summary.startswith(SIDE_EFFECTING_GET_PREFIXES)


def stable_operation_id(method: str, path_template: str, declared: object) -> str:
    """Return the upstream operationId or a deterministic bounded method/path identity."""

    upstream = str(declared or "").strip()
    if 1 <= len(upstream) <= 256:
        return upstream
    normalized_method = method.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", path_template.casefold()).strip("-") or "root"
    digest = hashlib.sha256(f"{normalized_method}\0{path_template}".encode()).hexdigest()[:16]
    suffix = f"-{digest}"
    prefix = f"generated-{normalized_method}-{slug}"
    return f"{prefix[: 256 - len(suffix)].rstrip('-')}{suffix}"


def validate_operation_identities(rows: list[dict[str, Any]]) -> None:
    """Require every generated row to carry an approval-safe operation identity."""

    invalid = [
        f"{row.get('method')} {row.get('path_template')}"
        for row in rows
        if not 1 <= len(str(row.get("operation_id") or "")) <= 256
    ]
    if invalid:
        raise ValueError("Operation identity invariant failed: " + ", ".join(invalid))


def validate_success_response_policy(rows: list[dict[str, Any]]) -> None:
    """Require unsupported request/auth/response contracts to remain catalog-only."""

    invalid = [
        f"{row.get('method')} {row.get('path_template')}"
        for row in rows
        if (
            bool(row.get("required_provider_headers"))
            or row.get("token_auth_compatible") is False
            or row.get("unconstrained_request_json_schema") is True
            or row.get("declared_success_response") is False
            or row.get("ambiguous_bodyless_success_response") is True
            or row.get("unconstrained_success_json_schema") is True
        )
        and (
            row.get("coverage_status") != "catalog_only"
            or row.get("transport_support") != "catalog_only"
            or row.get("mcp_tool") is not None
        )
    ]
    if invalid:
        raise ValueError("Explicit success-response policy invariant failed: " + ", ".join(invalid))


def operation_rows(
    spec: dict[str, Any], *, require_all_overrides: bool = True
) -> list[dict[str, Any]]:
    """Extract stable operation coverage rows from an OpenAPI document."""

    rows: list[dict[str, Any]] = []
    matched_overrides: set[tuple[str, str]] = set()
    unreviewed_side_effecting_gets: list[tuple[str, str]] = []
    for path_template, path_item in sorted(spec.get("paths", {}).items()):
        if not isinstance(path_item, dict):
            continue
        for method, operation in sorted(path_item.items()):
            if method not in METHODS or not isinstance(operation, dict):
                continue

            tags = [str(tag) for tag in operation.get("tags", [])]
            summary = str(operation.get("summary") or "")
            operation_id = stable_operation_id(method, path_template, operation.get("operationId"))
            feature_area = tags[0] if tags else "Uncategorized"
            classification = classify_operation(
                method.upper(),
                " ".join([summary, operation_id, path_template]),
            )
            risk_flags = operation_risk_flags(
                method,
                summary=summary,
                operation_id=operation_id,
                path_template=path_template,
            )
            request_types = request_content_types(spec, operation)
            body_required = request_body_required(spec, operation)
            required_headers = required_provider_headers(spec, path_item, operation)
            token_auth_compatible, auth_compatibility_evidence = token_auth_compatibility(
                spec, operation
            )
            unconstrained_request_json_schema = has_unconstrained_request_json_schema(
                spec, operation
            )
            response_types = success_response_content_types(spec, operation)
            declared_success_response = has_declared_success_response(operation)
            ambiguous_bodyless_success_response = has_ambiguous_bodyless_success_response(
                spec, operation
            )
            unconstrained_success_json_schema = has_unconstrained_success_json_schema(
                spec, operation
            )
            transport_support, coverage_status, notes = transport_metadata(
                request_types,
                response_types,
                required_headers=required_headers,
                token_auth_compatible=token_auth_compatible,
                unconstrained_request_json_schema=unconstrained_request_json_schema,
                declared_success_response=declared_success_response,
                ambiguous_bodyless_success_response=ambiguous_bodyless_success_response,
                unconstrained_success_json_schema=unconstrained_success_json_schema,
            )
            override = reviewed_operation_override(method, path_template)
            if is_side_effecting_get_candidate(method, summary) and override is None:
                unreviewed_side_effecting_gets.append((method.upper(), path_template))
            policy_override = None
            policy_reason = None
            if override is not None:
                matched_overrides.add((method.upper(), path_template))
                classification = override["classification"]
                risk_flags = list(override["risk_flags"])
                policy_override = override["policy_id"]
                policy_reason = override["reason"]
                if override["force_catalog_only"]:
                    transport_support = "catalog_only"
                    coverage_status = "catalog_only"
                    notes = f"Catalog only by reviewed policy {policy_override}: {policy_reason}"
                else:
                    notes = f"{notes} Reviewed policy {policy_override}: {policy_reason}"

            sensitive_findings = operation_sensitive_schema_findings(spec, path_item, operation)
            sensitive_request_schema = any(
                finding["direction"] == "request" for finding in sensitive_findings
            )
            sensitive_success_response_schema = any(
                finding["direction"] == "success_response" for finding in sensitive_findings
            )
            schema_policy_id = None
            schema_policy_reason = None
            if sensitive_findings:
                if "credentials" not in risk_flags:
                    risk_flags = ["credentials", *risk_flags]
                signals = sorted({finding["signal"] for finding in sensitive_findings})
                directions = []
                if sensitive_request_schema:
                    directions.append("request")
                if sensitive_success_response_schema:
                    directions.append("successful response")
                schema_policy_id = SCHEMA_SENSITIVITY_POLICY_ID
                schema_policy_reason = (
                    f"The {' and '.join(directions)} contract contains credential-sensitive "
                    f"schema signals ({', '.join(signals)}); the generic dispatcher has no "
                    "endpoint-specific safe projection."
                )
                transport_support = "catalog_only"
                coverage_status = "catalog_only"
                notes = (
                    f"{notes} Catalog only by schema policy {schema_policy_id}: "
                    f"{schema_policy_reason}"
                )

            rows.append(
                {
                    "method": method.upper(),
                    "path_template": path_template,
                    "feature_area": feature_area,
                    "tags": tags,
                    "operation_id": operation_id,
                    "summary": summary,
                    "classification": classification,
                    "risk_flags": risk_flags,
                    "high_risk": bool(risk_flags),
                    "request_content_types": request_types,
                    "request_body_required": body_required,
                    "required_provider_headers": required_headers,
                    "token_auth_compatible": token_auth_compatible,
                    "auth_compatibility_evidence": auth_compatibility_evidence,
                    "unconstrained_request_json_schema": unconstrained_request_json_schema,
                    "success_response_content_types": response_types,
                    "declared_success_response": declared_success_response,
                    "ambiguous_bodyless_success_response": (ambiguous_bodyless_success_response),
                    "unconstrained_success_json_schema": unconstrained_success_json_schema,
                    "transport_support": transport_support,
                    "auth_config_required": "Cloudflare API token",
                    "mcp_tool": (
                        "cloudflare_api_request" if coverage_status == "callable" else None
                    ),
                    "coverage_status": coverage_status,
                    "notes": notes,
                    "policy_override": policy_override,
                    "policy_reason": policy_reason,
                    "sensitive_request_schema": sensitive_request_schema,
                    "sensitive_success_response_schema": (sensitive_success_response_schema),
                    "sensitive_schema_findings": sensitive_findings,
                    "schema_policy_id": schema_policy_id,
                    "schema_policy_reason": schema_policy_reason,
                }
            )
    if unreviewed_side_effecting_gets:
        rendered = ", ".join(
            f"{method} {path}" for method, path in sorted(unreviewed_side_effecting_gets)
        )
        raise ValueError(f"Unreviewed side-effecting GET operations: {rendered}")
    if require_all_overrides:
        stale_overrides = sorted(set(REVIEWED_OPERATION_OVERRIDES) - matched_overrides)
        if stale_overrides:
            rendered = ", ".join(f"{method} {path}" for method, path in stale_overrides)
            raise ValueError(f"Reviewed operation overrides missing from pinned schema: {rendered}")
    validate_operation_identities(rows)
    validate_success_response_policy(rows)
    validate_sensitive_schema_policy(rows)
    return rows


def build_json(spec: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Build package data consumed by MCP navigation tools."""

    validate_operation_identities(rows)
    validate_success_response_policy(rows)
    validate_sensitive_schema_policy(rows)

    request_media_blocked = sum(
        bool(row["request_content_types"])
        and not any(media_type in JSON_MEDIA_TYPES for media_type in row["request_content_types"])
        for row in rows
    )
    response_media_blocked = sum(
        any(
            media_type not in JSON_MEDIA_TYPES
            for media_type in row["success_response_content_types"]
        )
        for row in rows
    )
    reviewed_policy_blocked = sum(
        row["policy_override"] is not None
        and REVIEWED_OPERATION_OVERRIDES[(row["method"], row["path_template"])][
            "force_catalog_only"
        ]
        for row in rows
    )
    sensitive_schema_blocked = sum(bool(row["sensitive_schema_findings"]) for row in rows)
    unconstrained_request_schema_blocked = sum(
        bool(row["unconstrained_request_json_schema"]) for row in rows
    )
    required_provider_headers_blocked = sum(bool(row["required_provider_headers"]) for row in rows)
    incompatible_token_auth_blocked = sum(not row["token_auth_compatible"] for row in rows)
    no_declared_success_blocked = sum(not row["declared_success_response"] for row in rows)
    ambiguous_bodyless_success_blocked = sum(
        bool(row["ambiguous_bodyless_success_response"]) for row in rows
    )
    unconstrained_success_schema_blocked = sum(
        bool(row["unconstrained_success_json_schema"]) for row in rows
    )
    sensitive_request_operations = sum(bool(row["sensitive_request_schema"]) for row in rows)
    sensitive_response_operations = sum(
        bool(row["sensitive_success_response_schema"]) for row in rows
    )
    signal_operation_counts = {
        signal: sum(
            any(finding["signal"] == signal for finding in row["sensitive_schema_findings"])
            for row in rows
        )
        for signal in SCHEMA_SENSITIVITY_SIGNALS
    }
    return {
        "generated_at": SOURCE_RETRIEVED_AT,
        "source": {
            "provider": "Cloudflare",
            "openapi": spec.get("openapi"),
            "title": spec.get("info", {}).get("title"),
            "version": spec.get("info", {}).get("version"),
            "schema_url": SOURCE_URL,
            "schema_repo": SOURCE_REPO,
            "commit": SOURCE_COMMIT,
            "sha256": SOURCE_SHA256,
            "license": SOURCE_LICENSE,
            "retrieved_at": SOURCE_RETRIEVED_AT,
        },
        "operation_count": len(rows),
        "policy_version": ENDPOINT_POLICY_VERSION,
        "reviewed_override_count": sum(row["policy_override"] is not None for row in rows),
        "sensitive_schema_operation_count": sensitive_schema_blocked,
        "sensitive_request_schema_operation_count": sensitive_request_operations,
        "sensitive_success_response_schema_operation_count": sensitive_response_operations,
        "sensitive_schema_signal_operation_counts": signal_operation_counts,
        "method_counts": dict(Counter(row["method"] for row in rows)),
        "classification_counts": dict(Counter(row["classification"] for row in rows)),
        "coverage_status_counts": dict(Counter(row["coverage_status"] for row in rows)),
        "transport_support_counts": dict(Counter(row["transport_support"] for row in rows)),
        "catalog_only_reason_counts": {
            "unsupported_request_media": request_media_blocked,
            "unsupported_success_response_media": response_media_blocked,
            "required_provider_headers": required_provider_headers_blocked,
            "incompatible_bearer_token_auth": incompatible_token_auth_blocked,
            "unconstrained_request_json_schema": unconstrained_request_schema_blocked,
            "no_declared_success_response": no_declared_success_blocked,
            "ambiguous_bodyless_success_response": ambiguous_bodyless_success_blocked,
            "unconstrained_success_json_schema": unconstrained_success_schema_blocked,
            "reviewed_policy_override": reviewed_policy_blocked,
            "sensitive_schema": sensitive_schema_blocked,
        },
        "high_risk_operation_count": sum(bool(row["high_risk"]) for row in rows),
        "risk_flag_counts": dict(Counter(flag for row in rows for flag in row["risk_flags"])),
        "feature_area_counts": dict(Counter(row["feature_area"] for row in rows)),
        "operations": rows,
    }


def markdown_table(rows: list[dict[str, Any]]) -> str:
    """Return a compact Markdown endpoint coverage table."""

    lines = [
        "| Method | Path | Feature area | Operation ID | Classification | Transport | "
        "High risk | Sensitive schema | Schema policy/reason | Policy override | MCP tool | "
        "Status |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            "| {method} | `{path}` | {area} | `{operation_id}` | {classification} | "
            "{transport} | {high_risk} | {sensitive} | {schema_policy} | `{policy}` | "
            "`{tool}` | {status} |".format(
                method=row["method"],
                path=row["path_template"].replace("|", "\\|"),
                area=row["feature_area"].replace("|", "\\|"),
                operation_id=(row["operation_id"] or "n/a").replace("|", "\\|"),
                classification=row["classification"],
                transport=row["transport_support"],
                high_risk="yes" if row["high_risk"] else "no",
                sensitive=(
                    ", ".join(
                        sorted({finding["signal"] for finding in row["sensitive_schema_findings"]})
                    )
                    or "no"
                ),
                schema_policy=(
                    f"`{row['schema_policy_id']}`: {row['schema_policy_reason']}"
                    if row["schema_policy_id"]
                    else "n/a"
                ).replace("|", "\\|"),
                policy=row["policy_override"] or "n/a",
                tool=row["mcp_tool"] or "n/a",
                status=row["coverage_status"],
            )
        )
    return "\n".join(lines)


def build_markdown(coverage: dict[str, Any]) -> str:
    """Build human-readable endpoint coverage docs."""

    source = coverage["source"]
    method_counts = ", ".join(
        f"{method}: {count}" for method, count in sorted(coverage["method_counts"].items())
    )
    classification_counts = ", ".join(
        f"{name}: {count}" for name, count in sorted(coverage["classification_counts"].items())
    )
    status_counts = coverage["coverage_status_counts"]
    reason_counts = coverage["catalog_only_reason_counts"]
    risk_counts = ", ".join(
        f"{name}: {count}" for name, count in sorted(coverage["risk_flag_counts"].items())
    )
    return "\n".join(
        [
            "# Cloudflare Endpoint Coverage",
            "",
            "Deterministic inventory generated from a pinned official Cloudflare OpenAPI schema.",
            "",
            f"- Provider docs source: {source['schema_repo']}",
            f"- Schema URL: {source['schema_url']}",
            f"- Schema commit: `{source['commit']}`",
            f"- Schema SHA256: `{source['sha256']}`",
            f"- Schema license: {source['license']}",
            f"- Retrieval date: {source['retrieved_at']}",
            f"- OpenAPI version: {source['openapi']}",
            f"- API title/version: {source['title']} {source['version']}",
            f"- Total inventoried operations: {coverage['operation_count']}",
            f"- Reviewed endpoint policy version: `{coverage['policy_version']}`",
            f"- Reviewed operation overrides: {coverage['reviewed_override_count']}",
            f"- JSON-callable operations: {status_counts['callable']}",
            f"- Catalog-only operations: {status_counts['catalog_only']}",
            "- Catalog-only due to unsupported request media: "
            f"{reason_counts['unsupported_request_media']}",
            "- Catalog-only due to unsupported successful-response media: "
            f"{reason_counts['unsupported_success_response_media']}",
            "- Catalog-only due to required provider request headers: "
            f"{reason_counts['required_provider_headers']}",
            "- Catalog-only due to no Bearer API-token compatibility evidence: "
            f"{reason_counts['incompatible_bearer_token_auth']}",
            "- Catalog-only due to no reviewable JSON request schema: "
            f"{reason_counts['unconstrained_request_json_schema']}",
            "- Catalog-only due to no explicit 2xx response contract: "
            f"{reason_counts['no_declared_success_response']}",
            "- Catalog-only due to an ambiguous non-204/205 bodyless success contract: "
            f"{reason_counts['ambiguous_bodyless_success_response']}",
            "- Catalog-only due to no reviewable successful JSON schema: "
            f"{reason_counts['unconstrained_success_json_schema']}",
            "- Catalog-only due to reviewed policy override: "
            f"{reason_counts['reviewed_policy_override']}",
            "- Catalog-only due to credential-sensitive request or success schema: "
            f"{reason_counts['sensitive_schema']}",
            "- Sensitive request-schema operations: "
            f"{coverage['sensitive_request_schema_operation_count']}",
            "- Sensitive successful-response-schema operations: "
            f"{coverage['sensitive_success_response_schema_operation_count']}",
            "- Sensitive schema signal operation counts: "
            + ", ".join(
                f"{signal}: {count}"
                for signal, count in sorted(
                    coverage["sensitive_schema_signal_operation_counts"].items()
                )
            ),
            f"- Method counts: {method_counts}",
            f"- Classification counts: {classification_counts}",
            f"- High-risk operations: {coverage['high_risk_operation_count']}",
            f"- Risk flag counts: {risk_counts}",
            "",
            "## Coverage Strategy",
            "",
            "This file inventories every operation; it does **not** claim every operation is "
            "callable. `cloudflare_api_request` is a JSON dispatcher. An operation is callable "
            "only when the pinned contract proves Bearer API-token compatibility, requires no "
            "caller-supplied provider headers, and its request is bodyless or supports one of "
            "`application/json`, "
            "`application/merge-patch+json`, or `application/scim+json`, and every declared "
            "successful response is JSON or explicitly bodyless with status 204/205. Operations "
            "without any "
            "declared 2xx response, plus multipart, form, binary, file, and stream transports, "
            "remain catalog-only. A declared successful JSON body must also carry a reviewable "
            "schema contract so response sensitivity can be reviewed. Likewise, a declared JSON "
            "request body must carry a reviewable schema contract before the dispatcher admits "
            "it. Bare object schemas and empty schemas are not reviewable contracts.",
            "",
            "The generator recursively dereferences request parameters and bodies plus every "
            "2xx or conservative `default` response body and header. It walks `allOf`, `oneOf`, "
            "`anyOf`, arrays, maps, `additionalProperties`, and nested local refs. Cloudflare "
            "`x-sensitive: true`, OpenAPI `format: password`, credential-like `writeOnly` fields, "
            "read-only `privkey` material, and strong credential value semantics such as "
            "`stream_key`, participant `token`, or raw secret inputs force catalog-only/high-risk "
            "credential handling. Descriptions and examples alone do not trigger the policy. "
            "Catalog-only reason counts may overlap because one operation can have multiple "
            "independent blockers.",
            "",
            "Exact method/path entries in the reviewed override registry supersede misleading "
            "HTTP method semantics. Side-effecting GET operations are mutation/high-risk gated. "
            "Credential-returning operations remain catalog-only unless an endpoint-specific "
            "safe output projection is implemented and reviewed.",
            "",
            "Use `get_endpoint_coverage` to inspect method, path, media types, classification, "
            "and risk flags before execution. Ordinary non-read operations require an external, "
            "expiring, one-use approval; high-risk operations are permanently blocked from the "
            "generic dispatcher.",
            "",
            "## Endpoint Matrix",
            "",
            markdown_table(coverage["operations"]),
            "",
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("schema", type=Path, help="Path to Cloudflare OpenAPI JSON schema")
    parser.add_argument(
        "--json-output",
        type=Path,
        default=Path("src/cloudflare_mcp/data/endpoint_coverage.json"),
    )
    parser.add_argument(
        "--markdown-output",
        type=Path,
        default=Path("docs/endpoint-coverage.md"),
    )
    args = parser.parse_args()

    try:
        spec = load_pinned_schema(args.schema)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    rows = operation_rows(spec)
    coverage = build_json(spec, rows)

    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps(coverage, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.markdown_output.write_text(build_markdown(coverage), encoding="utf-8")


if __name__ == "__main__":
    main()
