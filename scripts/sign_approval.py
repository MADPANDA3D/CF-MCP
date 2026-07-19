#!/usr/bin/env python3
"""Verify and sign one exact CF-MCP mutation in a trusted issuer context."""

from __future__ import annotations

import hmac
import json
import os
import sys
from typing import Any

from cloudflare_mcp.approval import decode_approval_payload, sign_approval_payload
from cloudflare_mcp.cloudflare import canonical_request_sha256, validate_operation_contract

MAX_REVIEW_DOCUMENT_BYTES = 1_048_576
_REVIEW_FIELDS = {
    "approval_payload",
    "body",
    "content_type",
    "method",
    "path",
    "query",
}


def sign_reviewed_request(review: dict[str, Any], signing_key: str) -> str:
    """Sign only after independently recomputing the exact request binding."""

    if set(review) != _REVIEW_FIELDS:
        raise ValueError("Review document fields are invalid.")
    approval_payload = review.get("approval_payload")
    method = review.get("method")
    path = review.get("path")
    query = review.get("query")
    body = review.get("body")
    content_type = review.get("content_type")
    if not isinstance(approval_payload, str):
        raise ValueError("approval_payload must be a string.")
    if not isinstance(method, str) or not isinstance(path, str):
        raise ValueError("method and path must be strings.")
    if query is not None and not isinstance(query, dict):
        raise ValueError("query must be an object or null.")
    if body is not None and not isinstance(body, (dict, list)):
        raise ValueError("body must be an object, array, or null.")
    if content_type is not None and not isinstance(content_type, str):
        raise ValueError("content_type must be a string or null.")

    operation, selected_content_type = validate_operation_contract(
        method=method,
        path=path,
        body=body,
        content_type=content_type,
    )
    if operation["classification"] == "read":
        raise ValueError("Read operations do not use mutation approval.")
    if operation["high_risk"]:
        raise ValueError("High-risk operations cannot be approved through the generic dispatcher.")

    decoded = decode_approval_payload(approval_payload)
    expected_digest = canonical_request_sha256(
        method=method,
        path=path,
        query=query,
        body=body,
        content_type=selected_content_type,
    )
    if not hmac.compare_digest(str(decoded["request_sha256"]), expected_digest):
        raise ValueError("The approval payload does not match the reviewed request.")
    if not hmac.compare_digest(str(decoded["operation_id"]), str(operation["operation_id"])):
        raise ValueError("The approval payload does not match the reviewed operation.")
    return sign_approval_payload(approval_payload, signing_key)


def main() -> None:
    signing_key = os.getenv("MCP_APPROVAL_SIGNING_KEY", "")
    if len(signing_key) < 32:
        raise SystemExit("MCP_APPROVAL_SIGNING_KEY must be set in the trusted issuer context.")
    raw = sys.stdin.buffer.read(MAX_REVIEW_DOCUMENT_BYTES + 1)
    if not raw:
        raise SystemExit("Provide one exact-request review JSON document on standard input.")
    if len(raw) > MAX_REVIEW_DOCUMENT_BYTES:
        raise SystemExit("Review document exceeds the 1 MiB limit.")
    try:
        review = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("Review document must be valid UTF-8 JSON.") from exc
    if not isinstance(review, dict):
        raise SystemExit("Review document must be one JSON object.")
    try:
        attestation = sign_reviewed_request(review, signing_key)
    except (KeyError, TypeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    sys.stdout.write(f"{attestation}\n")


if __name__ == "__main__":
    main()
