"""traceseal-verify — standalone verification of Traceseal Execution Receipts.

Verify receipts without needing the full Traceseal installation.
One dependency (cryptography). One function (verify_receipt).

A receipt is a self-contained JSON document proving that a specific
signed skill ran inside a specific sandbox and produced a specific
result. See RECEIPT-SPEC.md for the full specification.
"""

from __future__ import annotations

__version__ = "1.0.1"

import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RECEIPT_VERSION = "1.0"


def canonical_dumps(obj: dict) -> bytes:
    """Encode a dict as canonical JSON bytes.

    Rules (from RECEIPT-SPEC.md §3):
    - Keys sorted lexicographically at every nesting level
    - Compact encoding (no whitespace)
    - No trailing newline
    - UTF-8 encoded
    - No JSON booleans or nulls — use string equivalents
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


@dataclass
class VerifyResult:
    """Result of verifying an execution receipt."""
    ok: bool
    message: str
    skill_name: str = ""
    skill_version: str = ""
    operator_fingerprint: str = ""
    publisher_fingerprint: str = ""


def verify_receipt(receipt: dict | str | bytes) -> VerifyResult:
    """Verify a Traceseal Execution Receipt.

    Accepts a dict (already parsed), a JSON string, or JSON bytes.

    Checks (per RECEIPT-SPEC.md §4):
      1. Structure — receipt_version, three required sections
      2. Manifest hash consistency between execution and provenance
      3. Operator public key is loadable
      4. Signature is valid over canonical JSON of execution + provenance

    Returns a VerifyResult with ok=True if the receipt is valid.
    """
    if isinstance(receipt, (str, bytes)):
        try:
            receipt = json.loads(receipt)
        except (json.JSONDecodeError, ValueError) as e:
            return VerifyResult(ok=False, message=f"invalid JSON: {e}")

    if not isinstance(receipt, dict):
        return VerifyResult(ok=False, message="receipt is not a JSON object")

    version = receipt.get("receipt_version")
    if version != RECEIPT_VERSION:
        return VerifyResult(
            ok=False,
            message=f"unsupported receipt version {version!r} (expected {RECEIPT_VERSION!r})",
        )

    execution = receipt.get("execution")
    provenance = receipt.get("provenance")
    attestation = receipt.get("attestation")

    if execution is None or not isinstance(execution, dict):
        return VerifyResult(ok=False, message="missing or invalid 'execution' section")
    if provenance is None or not isinstance(provenance, dict):
        return VerifyResult(ok=False, message="missing or invalid 'provenance' section")
    if attestation is None or not isinstance(attestation, dict):
        return VerifyResult(ok=False, message="missing or invalid 'attestation' section")

    exec_manifest = execution.get("skill_manifest_hash", "")
    prov_manifest = provenance.get("manifest_hash", "")
    if exec_manifest and prov_manifest and exec_manifest != prov_manifest:
        return VerifyResult(
            ok=False,
            message=f"manifest hash mismatch: execution has {exec_manifest}, provenance has {prov_manifest}",
        )

    operator_pubkey_hex = attestation.get("operator_public_key", "")
    if not operator_pubkey_hex:
        return VerifyResult(ok=False, message="attestation missing operator_public_key")

    try:
        pk_bytes = bytes.fromhex(operator_pubkey_hex)
        if len(pk_bytes) != 32:
            return VerifyResult(ok=False, message=f"operator public key is {len(pk_bytes)} bytes, expected 32")
        operator_pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
    except (ValueError, Exception) as e:
        return VerifyResult(ok=False, message=f"invalid operator public key: {e}")

    payload = canonical_dumps({"execution": execution, "provenance": provenance})

    signature_hex = attestation.get("signature", "")
    if not signature_hex:
        return VerifyResult(ok=False, message="attestation missing signature")

    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as e:
        return VerifyResult(ok=False, message=f"invalid signature hex: {e}")

    try:
        operator_pk.verify(signature, payload)
    except InvalidSignature:
        return VerifyResult(
            ok=False,
            message="attestation signature verification FAILED — receipt may have been tampered with",
        )
    except Exception as e:
        return VerifyResult(ok=False, message=f"signature check error: {e}")

    return VerifyResult(
        ok=True,
        message="receipt verified",
        skill_name=execution.get("skill_name", ""),
        skill_version=execution.get("skill_version", ""),
        operator_fingerprint=attestation.get("operator_fingerprint", ""),
        publisher_fingerprint=provenance.get("publisher_fingerprint", ""),
    )


def verify_receipt_file(path: str) -> VerifyResult:
    """Convenience: verify a receipt from a file path."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return VerifyResult(ok=False, message=f"cannot read receipt file: {e}")
    return verify_receipt(data)
