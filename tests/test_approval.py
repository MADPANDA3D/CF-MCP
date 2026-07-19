from __future__ import annotations

import base64

import pytest

from cloudflare_mcp.approval import (
    ApprovalError,
    ApprovalLedger,
    decode_approval_payload,
    sign_approval_payload,
)

APPROVAL_KEY = "approval-signing-key-000000000000000000000000"
REQUEST_DIGEST = "a" * 64
OPERATION_ID = "zones-post"
PRINCIPAL = "b" * 64
PROVIDER = "c" * 64


def _issue(ledger: ApprovalLedger) -> dict[str, object]:
    return ledger.issue(
        request_sha256=REQUEST_DIGEST,
        operation_id=OPERATION_ID,
        principal_fingerprint=PRINCIPAL,
        provider_fingerprint=PROVIDER,
    )


def _consume(ledger: ApprovalLedger, attestation: str, **overrides: str) -> dict[str, object]:
    values = {
        "request_sha256": REQUEST_DIGEST,
        "operation_id": OPERATION_ID,
        "principal_fingerprint": PRINCIPAL,
        "provider_fingerprint": PROVIDER,
    }
    values.update(overrides)
    return ledger.consume(
        attestation=attestation,
        signing_key=APPROVAL_KEY,
        **values,
    )


def test_external_attestation_is_canonical_bound_and_one_use() -> None:
    ledger = ApprovalLedger()
    request = _issue(ledger)
    payload = str(request["approval_payload"])
    decoded = decode_approval_payload(payload)
    attestation = sign_approval_payload(payload, APPROVAL_KEY)

    assert decoded["request_sha256"] == REQUEST_DIGEST
    assert decoded["operation_id"] == OPERATION_ID
    with pytest.raises(ApprovalError, match="does not match") as mismatch:
        _consume(ledger, attestation, principal_fingerprint="d" * 64)
    assert mismatch.value.code == "approval_binding_mismatch"

    consumed = _consume(ledger, attestation)
    assert consumed["verified"] is True
    assert consumed["consumed"] is True
    with pytest.raises(ApprovalError, match="already used") as replay:
        _consume(ledger, attestation)
    assert replay.value.code == "approval_replayed"


def test_tampered_and_expired_attestations_fail_closed() -> None:
    now = 1_800_000_000.0
    ledger = ApprovalLedger(ttl_seconds=5, clock=lambda: now)
    request = _issue(ledger)
    attestation = sign_approval_payload(str(request["approval_payload"]), APPROVAL_KEY)

    encoded_payload, encoded_signature = attestation.split(".", 1)
    signature = base64.urlsafe_b64decode(encoded_signature + "=")
    tampered_signature = bytes([signature[0] ^ 1]) + signature[1:]
    encoded_tampered_signature = (
        base64.urlsafe_b64encode(tampered_signature).rstrip(b"=").decode("ascii")
    )
    with pytest.raises(ApprovalError, match="signature") as tampered:
        _consume(ledger, f"{encoded_payload}.{encoded_tampered_signature}")
    assert tampered.value.code == "approval_invalid"

    now += 6
    with pytest.raises(ApprovalError, match="unknown, expired") as expired:
        _consume(ledger, attestation)
    assert expired.value.code == "approval_not_issued"


def test_noncanonical_signature_alias_is_rejected() -> None:
    ledger = ApprovalLedger()
    request = _issue(ledger)
    attestation = sign_approval_payload(str(request["approval_payload"]), APPROVAL_KEY)
    encoded_payload, encoded_signature = attestation.split(".", 1)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    final_index = alphabet.index(encoded_signature[-1])

    # A SHA-256 signature has two unused bits in its final unpadded Base64URL sextet.
    # A non-canonical low-bit alias decodes to the same bytes and must still be rejected.
    assert final_index % 4 == 0
    alias = f"{encoded_signature[:-1]}{alphabet[final_index + 1]}"
    assert base64.urlsafe_b64decode(alias + "=") == base64.urlsafe_b64decode(
        encoded_signature + "="
    )

    with pytest.raises(ApprovalError, match="not canonical") as noncanonical:
        _consume(ledger, f"{encoded_payload}.{alias}")

    assert noncanonical.value.code == "approval_invalid"


def test_attestation_is_invalid_at_the_exact_expiry_second() -> None:
    current_time = [1_800_000_000.0]
    ledger = ApprovalLedger(ttl_seconds=5, clock=lambda: current_time[0])
    request = _issue(ledger)
    attestation = sign_approval_payload(str(request["approval_payload"]), APPROVAL_KEY)

    expires_at = request["expires_at"]
    assert isinstance(expires_at, int)
    current_time[0] = float(expires_at)
    with pytest.raises(ApprovalError, match="unknown, expired") as expired:
        _consume(ledger, attestation)

    assert expired.value.code == "approval_not_issued"


def test_per_principal_pending_limit_does_not_cross_evict_tenants() -> None:
    ledger = ApprovalLedger(max_pending=4, max_pending_per_principal=1)
    tenant_a = "d" * 64
    tenant_b = "e" * 64
    first = ledger.issue(
        request_sha256=REQUEST_DIGEST,
        operation_id=OPERATION_ID,
        principal_fingerprint=tenant_a,
        provider_fingerprint=PROVIDER,
    )
    second = ledger.issue(
        request_sha256=REQUEST_DIGEST,
        operation_id=OPERATION_ID,
        principal_fingerprint=tenant_b,
        provider_fingerprint=PROVIDER,
    )

    for issued, principal in ((first, tenant_a), (second, tenant_b)):
        attestation = sign_approval_payload(str(issued["approval_payload"]), APPROVAL_KEY)
        result = ledger.consume(
            attestation=attestation,
            signing_key=APPROVAL_KEY,
            request_sha256=REQUEST_DIGEST,
            operation_id=OPERATION_ID,
            principal_fingerprint=principal,
            provider_fingerprint=PROVIDER,
        )
        assert result["consumed"] is True
