"""One-use external approval attestations for Cloudflare mutations."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

APPROVAL_ATTESTATION_HEADER = "x-mcp-approval-attestation"
APPROVAL_REQUEST_TTL_SECONDS = 300
MAX_APPROVAL_ATTESTATION_LENGTH = 4096
_ATTESTATION_DOMAIN = b"cloudflare-mcp-approval-v1\x00"
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class ApprovalError(RuntimeError):
    """Raised when an approval attestation is missing, invalid, expired, or replayed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PendingApproval:
    """Secret-free binding retained until an approval is consumed or expires."""

    request_sha256: str
    operation_id: str
    principal_fingerprint: str
    provider_fingerprint: str
    expires_at: int
    issued_at: int


def fingerprint_secret(namespace: str, value: str) -> str:
    """Return a domain-separated fingerprint without retaining or exposing a secret."""

    return hashlib.sha256(f"{namespace}\0{value}".encode()).hexdigest()


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    if not value or not _BASE64URL_PATTERN.fullmatch(value):
        raise ApprovalError("approval_invalid", "Approval encoding is invalid.")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ApprovalError("approval_invalid", "Approval encoding is invalid.") from exc
    if not hmac.compare_digest(_base64url_encode(decoded), value):
        raise ApprovalError("approval_invalid", "Approval encoding is not canonical.")
    return decoded


def _canonical_payload(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def decode_approval_payload(encoded_payload: str) -> dict[str, object]:
    """Decode and strictly validate the public payload an operator is asked to sign."""

    try:
        decoded = json.loads(_base64url_decode(encoded_payload))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApprovalError("approval_invalid", "Approval payload is invalid.") from exc
    if not isinstance(decoded, dict) or set(decoded) != {
        "challenge",
        "exp",
        "operation_id",
        "request_sha256",
        "v",
    }:
        raise ApprovalError("approval_invalid", "Approval payload fields are invalid.")
    if decoded.get("v") != 1:
        raise ApprovalError("approval_invalid", "Approval payload version is unsupported.")
    challenge = decoded.get("challenge")
    operation_id = decoded.get("operation_id")
    request_sha256 = decoded.get("request_sha256")
    expires_at = decoded.get("exp")
    if not isinstance(challenge, str) or not 32 <= len(challenge) <= 128:
        raise ApprovalError("approval_invalid", "Approval challenge is invalid.")
    if not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 256:
        raise ApprovalError("approval_invalid", "Approval operation identity is invalid.")
    if not isinstance(request_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", request_sha256):
        raise ApprovalError("approval_invalid", "Approval request digest is invalid.")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise ApprovalError("approval_invalid", "Approval expiry is invalid.")
    if not hmac.compare_digest(_base64url_encode(_canonical_payload(decoded)), encoded_payload):
        raise ApprovalError("approval_invalid", "Approval payload is not canonical.")
    return decoded


def sign_approval_payload(encoded_payload: str, signing_key: str) -> str:
    """Sign an issued public payload in a trusted operator or broker context."""

    decode_approval_payload(encoded_payload)
    signature = hmac.new(
        signing_key.encode("utf-8"),
        _ATTESTATION_DOMAIN + encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{encoded_payload}.{_base64url_encode(signature)}"


class ApprovalLedger:
    """Bounded in-memory ledger for expiring, process-local, one-use approvals."""

    def __init__(
        self,
        *,
        ttl_seconds: int = APPROVAL_REQUEST_TTL_SECONDS,
        max_pending: int = 2048,
        max_pending_per_principal: int = 32,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._ttl_seconds = ttl_seconds
        self._max_pending = max_pending
        self._max_pending_per_principal = max_pending_per_principal
        self._clock = clock
        self._pending: dict[str, PendingApproval] = {}
        self._consumed: dict[str, int] = {}
        self._lock = threading.Lock()

    def _prune(self, now: int) -> None:
        self._pending = {
            key: pending for key, pending in self._pending.items() if pending.expires_at > now
        }
        self._consumed = {
            key: expires_at for key, expires_at in self._consumed.items() if expires_at > now
        }

    def _evict_oldest(self, keys: list[str]) -> None:
        if not keys:
            return
        oldest = min(keys, key=lambda key: self._pending[key].issued_at)
        del self._pending[oldest]

    def issue(
        self,
        *,
        request_sha256: str,
        operation_id: str,
        principal_fingerprint: str,
        provider_fingerprint: str,
    ) -> dict[str, object]:
        """Issue a secret-free approval request bound to the caller and BYOK credential."""

        now = int(self._clock())
        expires_at = now + self._ttl_seconds
        challenge = secrets.token_urlsafe(32)
        challenge_hash = hashlib.sha256(challenge.encode("ascii")).hexdigest()
        pending = PendingApproval(
            request_sha256=request_sha256,
            operation_id=operation_id,
            principal_fingerprint=principal_fingerprint,
            provider_fingerprint=provider_fingerprint,
            expires_at=expires_at,
            issued_at=now,
        )
        with self._lock:
            self._prune(now)
            same_principal = [
                key
                for key, value in self._pending.items()
                if value.principal_fingerprint == principal_fingerprint
            ]
            if len(same_principal) >= self._max_pending_per_principal:
                self._evict_oldest(same_principal)
            if len(self._pending) >= self._max_pending:
                self._evict_oldest(list(self._pending))
            self._pending[challenge_hash] = pending

        payload = {
            "challenge": challenge,
            "exp": expires_at,
            "operation_id": operation_id,
            "request_sha256": request_sha256,
            "v": 1,
        }
        return {
            "approval_payload": _base64url_encode(_canonical_payload(payload)),
            "expires_at": expires_at,
            "ttl_seconds": self._ttl_seconds,
            "approval_header": APPROVAL_ATTESTATION_HEADER,
            "mechanism": "externally_signed_one_time_attestation",
        }

    def consume(
        self,
        *,
        attestation: str,
        signing_key: str,
        request_sha256: str,
        operation_id: str,
        principal_fingerprint: str,
        provider_fingerprint: str,
    ) -> dict[str, object]:
        """Validate and atomically consume an exact approval before a provider attempt."""

        if not attestation or len(attestation) > MAX_APPROVAL_ATTESTATION_LENGTH:
            raise ApprovalError("approval_missing", "A valid approval attestation is required.")
        try:
            encoded_payload, encoded_signature = attestation.split(".", 1)
        except ValueError as exc:
            raise ApprovalError("approval_invalid", "Approval attestation is invalid.") from exc
        expected_signature = hmac.new(
            signing_key.encode("utf-8"),
            _ATTESTATION_DOMAIN + encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        supplied_signature = _base64url_decode(encoded_signature)
        if not hmac.compare_digest(expected_signature, supplied_signature):
            raise ApprovalError("approval_invalid", "Approval signature is invalid.")
        payload = decode_approval_payload(encoded_payload)
        challenge = str(payload["challenge"])
        payload_expires_at = payload["exp"]
        if not isinstance(payload_expires_at, int) or isinstance(payload_expires_at, bool):
            raise ApprovalError("approval_invalid", "Approval expiry is invalid.")
        challenge_hash = hashlib.sha256(challenge.encode("ascii")).hexdigest()
        now = int(self._clock())

        with self._lock:
            self._prune(now)
            if challenge_hash in self._consumed:
                raise ApprovalError("approval_replayed", "Approval attestation was already used.")
            pending = self._pending.get(challenge_hash)
            if pending is None:
                raise ApprovalError(
                    "approval_not_issued",
                    "Approval challenge is unknown, expired, or belongs to another process.",
                )
            if pending.expires_at <= now or payload_expires_at <= now:
                del self._pending[challenge_hash]
                raise ApprovalError("approval_expired", "Approval attestation has expired.")
            supplied_binding = (
                str(payload["request_sha256"]),
                str(payload["operation_id"]),
                request_sha256,
                operation_id,
                principal_fingerprint,
                provider_fingerprint,
                str(payload_expires_at),
            )
            expected_binding = (
                pending.request_sha256,
                pending.operation_id,
                pending.request_sha256,
                pending.operation_id,
                pending.principal_fingerprint,
                pending.provider_fingerprint,
                str(pending.expires_at),
            )
            if not all(
                hmac.compare_digest(supplied, expected)
                for supplied, expected in zip(supplied_binding, expected_binding, strict=True)
            ):
                raise ApprovalError(
                    "approval_binding_mismatch",
                    "Approval does not match this principal, credential, operation, or request.",
                )
            del self._pending[challenge_hash]
            self._consumed[challenge_hash] = pending.expires_at

        return {
            "required": True,
            "verified": True,
            "consumed": True,
            "operation_id": operation_id,
            "request_sha256": request_sha256,
            "expires_at": pending.expires_at,
            "mechanism": "externally_signed_one_time_attestation",
        }


approval_ledger = ApprovalLedger()
