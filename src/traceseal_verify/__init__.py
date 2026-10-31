"""traceseal-verify — standalone verification of Traceseal Execution Receipts.

Verify receipts without needing the full Traceseal installation.
One dependency (cryptography). One function (verify_receipt).

A receipt is a self-contained JSON document proving that a specific
signed skill ran inside a specific sandbox and produced a specific
result. See RECEIPT-SPEC.md for the full specification.
"""

from __future__ import annotations

__version__ = "1.0.2"

import hashlib
import json
from dataclasses import dataclass, field
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
    receipt_type: str = ""
    summary: dict = field(default_factory=dict)
    """Type-specific, display-only facts read from the verified receipt."""
    receipt_hash: str = ""
    """SHA-256 of the canonical receipt (how other receipts refer to it)."""


def fingerprint_matches(public_key_bytes: bytes, fingerprint: Any) -> bool:
    """RECEIPT-SPEC.md §4 Step 3: the fingerprint must be derived from the key.

    Accepts the v1 operator form (first 128 bits of SHA-256, 32 hex) and the
    full form (64 hex) used by newer profiles.
    """
    if not isinstance(fingerprint, str) or not fingerprint.startswith("ed25519:"):
        return False
    digest = hashlib.sha256(public_key_bytes).hexdigest()
    value = fingerprint[len("ed25519:"):]
    return value in (digest[:32], digest)


def receipt_hash(receipt: dict) -> str:
    """sha256:<hex> of the canonical JSON of the whole receipt."""
    return "sha256:" + hashlib.sha256(canonical_dumps(receipt)).hexdigest()


def _summary(execution: dict) -> dict:
    """A few human-readable facts per receipt type, for display only."""
    keys = {
        "skill": ("skill_name", "skill_version"),
        "model": ("provider", "model", "served_model", "response_mode", "stream_complete"),
        "tool": ("tool_name", "transport"),
        "data_flow": ("method", "destination_host", "status_code", "destination_declared"),
        "orchestration": ("workflow_name", "step_count"),
        "outcome": ("outcome_status",),
        "oversight": ("decision", "review_seconds"),
        "policy_decision": ("policy_id", "decision", "stage"),
        "incident": ("category", "severity", "status"),
        "erasure": ("reason", "object_count"),
        "evidence_pack": ("file_count", "verification_ok"),
        "chain_key_rotation": ("rotation_reason",),
    }.get(execution.get("receipt_type", "skill"), ())
    out = {k: execution[k] for k in keys if k in execution}
    if "chain_id" in execution:
        out["chain"] = f"{execution.get('chain_id')}#{execution.get('chain_seq')}"
    ctx = execution.get("context")
    if isinstance(ctx, dict) and isinstance(ctx.get("agent"), dict) and ctx["agent"].get("id"):
        out["agent"] = ctx["agent"]["id"]
    if "reviewer_signature" in execution:
        out["reviewer_signed"] = "true"
    return out


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

    # Skill receipts attest that a specific signed code artifact ran, so the
    # manifest hash is mandatory and must agree across both sections. Other
    # receipt types (model/tool/orchestration/...) legitimately carry no
    # manifest. Treating "skill" as the default keeps receipts that omit the
    # discriminator on the strict path — omission must never skip the check.
    exec_manifest = execution.get("skill_manifest_hash", "")
    prov_manifest = provenance.get("manifest_hash", "")
    receipt_type = execution.get("receipt_type", "skill")

    if receipt_type == "skill":
        if not exec_manifest:
            return VerifyResult(ok=False, message="skill receipt missing execution.skill_manifest_hash")
        if not prov_manifest:
            return VerifyResult(ok=False, message="skill receipt missing provenance.manifest_hash")

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

    # §4 Step 3: the fingerprint is outside the signed payload, so it must be
    # derived from the key, never trusted as given. Otherwise a valid receipt
    # could be relabelled to display someone else's identity.
    if not fingerprint_matches(pk_bytes, attestation.get("operator_fingerprint")):
        return VerifyResult(
            ok=False,
            message="operator_fingerprint is missing or not derived from operator_public_key",
        )

    payload = canonical_dumps({"execution": execution, "provenance": provenance})

    signature_hex = attestation.get("signature", "")
    if not signature_hex:
        return VerifyResult(ok=False, message="attestation missing signature")

    # An Ed25519 signature is exactly 64 bytes (128 hex chars). Bound the
    # length before decoding so a hostile receipt can't force an unbounded
    # bytes.fromhex() allocation (the crypto layer would reject it anyway).
    if len(signature_hex) != 128:
        return VerifyResult(
            ok=False,
            message=f"signature is {len(signature_hex)} hex chars, expected 128",
        )

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
        receipt_type=receipt_type,
        summary=_summary(execution),
        receipt_hash=receipt_hash(receipt),
    )


def verify_receipt_file(path: str) -> VerifyResult:
    """Convenience: verify a receipt from a file path."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return VerifyResult(ok=False, message=f"cannot read receipt file: {e}")
    return verify_receipt(data)


# ---------------------------------------------------------------------------
# Chain links (RECEIPT-CHAINS.md §1.2, §1.4 steps 2-4, §1.6)
# ---------------------------------------------------------------------------

_CHAIN_VERSION = "1.0"
_ROTATION = "chain_key_rotation"
_ACCEPTANCE_PURPOSE = "traceseal-chain-key-acceptance/1"


def _rotation_next_key(execution: dict, signer_hex: str) -> str | None:
    """The incoming key of a valid rotation receipt, else None."""
    nxt = execution.get("next_public_key")
    if execution.get("previous_public_key") != signer_hex or not isinstance(nxt, str) or len(nxt) != 64:
        return None
    message = canonical_dumps({
        "chain_id": execution.get("chain_id"),
        "chain_prev_hash": execution.get("chain_prev_hash"),
        "chain_seq": execution.get("chain_seq"),
        "next_public_key": nxt,
        "previous_public_key": signer_hex,
        "purpose": _ACCEPTANCE_PURPOSE,
    })
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(nxt)).verify(
            bytes.fromhex(execution.get("next_key_acceptance", "")), message)
    except (ValueError, InvalidSignature):
        return None
    return nxt


def check_chains(receipts: list[dict]) -> dict[str, dict]:
    """Check hash links across already signature-verified receipts.

    Groups chained receipts by chain_id and reports, per chain: the seq
    range, gaps (missing receipts), forks (two different receipts at one
    position), broken links, and signing-key changes that did not go
    through a valid chain_key_rotation. This is the offline subset of
    traceseal-chain verify; checkpoints, proofs and trusted time need
    traceseal-observe.
    """
    chains: dict[str, dict[int, dict]] = {}
    report: dict[str, dict] = {}
    for r in receipts:
        ex = r.get("execution", {})
        if ex.get("chain_version") != _CHAIN_VERSION:
            continue
        cid, seq = ex.get("chain_id"), ex.get("chain_seq")
        if not isinstance(cid, str) or not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            continue
        entry = report.setdefault(cid, {"errors": [], "gaps": [], "forks": []})
        h = receipt_hash(r)
        slot = chains.setdefault(cid, {})
        if seq in slot and receipt_hash(slot[seq]) != h:
            entry["forks"].append(seq)
            entry["errors"].append(f"seq {seq}: two different receipts claim this position (fork)")
            continue
        slot[seq] = r
    for cid, slot in chains.items():
        entry = report[cid]
        seqs = sorted(slot)
        entry.update(first_seq=seqs[0], last_seq=seqs[-1], count=len(seqs),
                     starts_at_genesis=seqs[0] == 1)
        first = slot[seqs[0]]["execution"]
        if (seqs[0] == 1) != (first.get("chain_prev_hash") == "genesis"):
            entry["errors"].append(f"seq {seqs[0]}: genesis link is wrong")
        expected = None
        for i, seq in enumerate(seqs):
            r = slot[seq]
            ex = r["execution"]
            signer = r["attestation"]["operator_public_key"]
            if i:
                before = seqs[i - 1]
                if seq != before + 1:
                    entry["gaps"].append([before + 1, seq - 1])
                else:
                    if ex.get("chain_prev_hash") != receipt_hash(slot[before]):
                        entry["errors"].append(f"seq {seq}: chain_prev_hash does not match seq {before}")
                    if signer != expected:
                        entry["errors"].append(f"seq {seq}: signing key changed without a valid rotation")
            expected = signer
            if ex.get("receipt_type") == _ROTATION:
                nxt = _rotation_next_key(ex, signer)
                if nxt is None:
                    entry["errors"].append(f"seq {seq}: invalid key rotation")
                else:
                    expected = nxt
        entry["ok"] = not entry["errors"] and not entry["gaps"]
    return report
