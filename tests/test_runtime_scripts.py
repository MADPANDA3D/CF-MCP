from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def _load_initializer() -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / "init_runtime_env.py"
    spec = importlib.util.spec_from_file_location("cf_mcp_init_runtime_env", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_approval_signer() -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / "sign_approval.py"
    spec = importlib.util.spec_from_file_location("cf_mcp_sign_approval", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _values(content: str) -> dict[str, str]:
    return {
        key: value
        for line in content.splitlines()
        if line and not line.startswith("#")
        for key, value in [line.split("=", 1)]
    }


def test_runtime_smoke_byok_probe_remains_callable_under_pinned_policy() -> None:
    from cloudflare_mcp.coverage import find_operation

    smoke_source = (Path(__file__).parents[1] / "scripts" / "runtime_smoke.py").read_text(
        encoding="utf-8"
    )
    operation = find_operation("GET", "/zones")

    assert 'PROVIDER_SMOKE_PATH = "/zones"' in smoke_source
    assert operation is not None
    assert operation["coverage_status"] == "callable"
    assert operation["classification"] == "read"
    assert operation["high_risk"] is False


def test_initializer_generates_mode_specific_service_and_separate_approval_secrets(
    tmp_path: Path,
) -> None:
    initializer = _load_initializer()
    standalone = _values(initializer.build_environment("standalone"))
    portal = _values(initializer.build_environment("portal"))

    assert len(standalone["MCP_ACCESS_TOKEN"]) >= 32
    assert standalone["MCP_PORTAL_GRANT_TOKEN"] == ""
    assert len(portal["MCP_PORTAL_GRANT_TOKEN"]) >= 32
    assert portal["MCP_ACCESS_TOKEN"] == ""
    assert len(standalone["MCP_APPROVAL_SIGNING_KEY"]) >= 32
    assert len(portal["MCP_APPROVAL_SIGNING_KEY"]) >= 32
    assert standalone["MCP_APPROVAL_SIGNING_KEY"] != standalone["MCP_ACCESS_TOKEN"]
    assert portal["MCP_APPROVAL_SIGNING_KEY"] != portal["MCP_PORTAL_GRANT_TOKEN"]
    assert "CLOUDFLARE" not in "\n".join(standalone)

    env_path = tmp_path / ".env"
    assert initializer.create_environment(env_path, "standalone") is True
    original = env_path.read_text(encoding="utf-8")
    assert env_path.stat().st_mode & 0o777 == 0o600
    assert initializer.create_environment(env_path, "portal") is False
    assert env_path.read_text(encoding="utf-8") == original


def test_approval_signer_recomputes_exact_request_before_signing() -> None:
    from cloudflare_mcp.approval import ApprovalLedger
    from cloudflare_mcp.cloudflare import canonical_request_sha256, validate_operation_contract

    signer = _load_approval_signer()
    signing_key = "approval-signing-key-000000000000000000000000"
    method = "POST"
    path = "/zones"
    body = {"name": "example.invalid", "account": {"id": "account-placeholder"}}
    operation, content_type = validate_operation_contract(
        method=method,
        path=path,
        body=body,
        content_type=None,
    )
    digest = canonical_request_sha256(
        method=method,
        path=path,
        query=None,
        body=body,
        content_type=content_type,
    )
    issued = ApprovalLedger().issue(
        request_sha256=digest,
        operation_id=operation["operation_id"],
        principal_fingerprint="a" * 64,
        provider_fingerprint="b" * 64,
    )
    review = {
        "approval_payload": issued["approval_payload"],
        "method": method,
        "path": path,
        "query": None,
        "body": body,
        "content_type": None,
    }

    attestation = signer.sign_reviewed_request(review, signing_key)
    assert attestation.startswith(f"{issued['approval_payload']}.")

    changed = {**review, "body": {**body, "name": "changed.invalid"}}
    try:
        signer.sign_reviewed_request(changed, signing_key)
    except ValueError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError("changed request was signed")
