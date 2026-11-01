"""traceseal-verify — standalone verification of Traceseal Execution Receipts.

Verify receipts without needing the full Traceseal installation.
One dependency (cryptography). One function (verify_receipt).

A receipt is a self-contained JSON document proving that a specific
signed skill ran inside a specific sandbox and produced a specific
result. See RECEIPT-SPEC.md for the full specification.
"""

from __future__ import annotations

__version__ = "1.2.0"

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RECEIPT_VERSION = "1.0"

_KEY_HEX_RE = re.compile(r"[0-9a-f]{64}")
_SIG_HEX_RE = re.compile(r"[0-9a-f]{128}")


def _reject_duplicate_keys(pairs: list) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _reject_constant(name: str):
    raise ValueError(f"non-standard JSON constant {name}")


def loads_json(data: str | bytes) -> Any:
    """Parse receipt JSON strictly.

    Duplicate object keys are an error (otherwise this parser and another
    one could read different values from the same signed file), as are
    NaN / Infinity. Raises ValueError.
    """
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8")
    return json.loads(
        data, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant
    )


# Edwards25519 (RFC 8032 §5.1), only to decode a public key strictly and
# test its order. OpenSSL loads any 32 bytes as a key, including the
# identity 01 00..00, under which (R = B, S = 1) verifies for EVERY message.
_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _decode_point(encoded: bytes):
    if len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    sign, y = value >> 255, value & ((1 << 255) - 1)
    if y >= _P:  # non-canonical
        return None
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    vxx = v * x * x % _P
    if vxx == (-u) % _P:
        x = x * _SQRT_M1 % _P
    elif vxx != u:
        return None  # not on the curve
    if x == 0 and sign:  # non-canonical "-0"
        return None
    if x & 1 != sign:
        x = _P - x
    return x, y


def _double(point):
    x, y = point
    t = _D * x * x * y * y % _P
    return (
        2 * x * y * pow(1 + t, _P - 2, _P) % _P,
        (y * y + x * x) * pow(1 - t, _P - 2, _P) % _P,
    )


def is_weak_ed25519_public_key(key: bytes | str) -> bool:
    """True for malformed, non-canonical (y >= p, or x = 0 with the sign
    bit set), off-curve and small-order (8·A = identity) Ed25519 keys.
    Signatures under such keys can be made without a private key."""
    try:
        raw = bytes.fromhex(key) if isinstance(key, str) else bytes(key)
    except (ValueError, TypeError):
        return True
    point = _decode_point(raw)
    if point is None:
        return True
    for _ in range(3):
        point = _double(point)
    return point == (0, 1)


def _forbidden_value(value: Any) -> str | None:
    """Path of the first JSON boolean or null (RECEIPT-SPEC §3), else None."""
    stack = [(value, "")]
    while stack:
        item, where = stack.pop()
        if item is None or isinstance(item, bool):
            return where or "/"
        if isinstance(item, dict):
            stack.extend((v, f"{where}.{k}") for k, v in item.items())
        elif isinstance(item, list):
            stack.extend((v, f"{where}[{i}]") for i, v in enumerate(item))
    return None


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
            receipt = loads_json(receipt)
        except (ValueError, RecursionError) as e:
            return VerifyResult(ok=False, message=f"invalid JSON: {e}")
    try:
        return _verify_receipt(receipt)
    except Exception as e:  # hostile shapes fail verification, never crash
        return VerifyResult(ok=False, message=f"malformed receipt ({type(e).__name__})")


def _verify_receipt(receipt: Any) -> VerifyResult:

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
    # One encoding only: lower-case hex (as signers emit it). Accepting other
    # spellings would let anyone mint byte-different copies of a receipt.
    if not isinstance(operator_pubkey_hex, str) or _KEY_HEX_RE.fullmatch(operator_pubkey_hex) is None:
        length = len(operator_pubkey_hex) if isinstance(operator_pubkey_hex, str) else "non-string"
        return VerifyResult(
            ok=False,
            message=f"operator public key must be 64 lower-case hex chars (got {length})",
        )
    pk_bytes = bytes.fromhex(operator_pubkey_hex)
    if is_weak_ed25519_public_key(pk_bytes):
        return VerifyResult(ok=False, message="operator public key is a small-order or non-canonical Ed25519 key")
    try:
        operator_pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
    except Exception as e:
        return VerifyResult(ok=False, message=f"invalid operator public key: {e}")

    # §4 Step 3: the fingerprint is outside the signed payload, so it must be
    # derived from the key, never trusted as given. Otherwise a valid receipt
    # could be relabelled to display someone else's identity.
    if not fingerprint_matches(pk_bytes, attestation.get("operator_fingerprint")):
        return VerifyResult(
            ok=False,
            message="operator_fingerprint is missing or not derived from operator_public_key",
        )

    forbidden = _forbidden_value({"execution": execution, "provenance": provenance})
    if forbidden is not None:
        return VerifyResult(
            ok=False,
            message=f"signed payload contains a JSON boolean or null at {forbidden} (RECEIPT-SPEC §3)",
        )
    try:
        payload = canonical_dumps({"execution": execution, "provenance": provenance})
        digest = receipt_hash(receipt)
    except (ValueError, TypeError) as e:  # e.g. lone surrogates, non-string keys
        return VerifyResult(
            ok=False, message=f"receipt is not encodable as canonical JSON ({type(e).__name__})")

    signature_hex = attestation.get("signature", "")
    if not signature_hex:
        return VerifyResult(ok=False, message="attestation missing signature")
    if not isinstance(signature_hex, str):
        return VerifyResult(ok=False, message="signature must be a hex string")

    # An Ed25519 signature is exactly 64 bytes (128 hex chars). Bound the
    # length before decoding so a hostile receipt can't force an unbounded
    # bytes.fromhex() allocation (the crypto layer would reject it anyway).
    if len(signature_hex) != 128:
        return VerifyResult(
            ok=False,
            message=f"signature is {len(signature_hex)} hex chars, expected 128",
        )

    if _SIG_HEX_RE.fullmatch(signature_hex) is None:
        return VerifyResult(ok=False, message="signature must be 128 lower-case hex chars")
    signature = bytes.fromhex(signature_hex)

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
        receipt_hash=digest,
    )


def verify_receipt_file(path: str) -> VerifyResult:
    """Convenience: verify a receipt from a file path."""
    try:
        with open(path, "rb") as f:
            data = loads_json(f.read())
    except (OSError, ValueError, RecursionError) as e:
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
    previous = execution.get("previous_public_key")
    acceptance = execution.get("next_key_acceptance")
    # Fields are operator-signed but otherwise untrusted: validate types
    # before decoding so a malformed rotation is an error, not a crash.
    if (
        not isinstance(previous, str) or previous != signer_hex
        or not isinstance(nxt, str) or _KEY_HEX_RE.fullmatch(nxt) is None
        or nxt == previous
        or not isinstance(acceptance, str) or _SIG_HEX_RE.fullmatch(acceptance) is None
    ):
        return None
    if is_weak_ed25519_public_key(nxt):
        return None
    reason = execution.get("rotation_reason")
    compromised = execution.get("previous_key_compromised_after_seq")
    if compromised is not None and (
        reason != "compromise"
        or isinstance(compromised, bool)
        or not isinstance(compromised, int)
        or not 0 <= compromised < execution.get("chain_seq")
    ):
        return None
    message = canonical_dumps({
        "chain_id": execution.get("chain_id"),
        "chain_prev_hash": execution.get("chain_prev_hash"),
        "chain_seq": execution.get("chain_seq"),
        "next_public_key": nxt,
        "previous_public_key": previous,
        "purpose": _ACCEPTANCE_PURPOSE,
    })
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(nxt)).verify(
            bytes.fromhex(acceptance), message)
    except (ValueError, TypeError, InvalidSignature):
        return None
    return nxt


def _body_id(receipt: dict) -> str:
    """Hash of the SIGNED bytes. receipt_hash also covers the unsigned
    attestation (attested_at, fingerprint form), so byte-different copies of
    one signed receipt are trivial to make and must not count as a fork."""
    return hashlib.sha256(canonical_dumps({
        "execution": receipt["execution"], "provenance": receipt["provenance"],
    })).hexdigest()


def check_chains(receipts: list[dict], *, allow_compromised: bool = False) -> dict[str, dict]:
    """Check hash links across already signature-verified receipts.

    Groups chained receipts by chain_id and reports, per chain: the seq
    range, gaps (missing receipts), forks (two receipts with different
    SIGNED content at one position), broken links, signing-key changes
    that did not go through a valid chain_key_rotation (including any key
    change across a gap, which is an error, not a gap), and
    compromised_seqs: ranges a rotation declared signed by a compromised
    key (previous_key_compromised_after_seq). Supplied receipts inside a
    compromised range are errors unless allow_compromised=True.

    This is the offline subset of traceseal-chain verify; checkpoints,
    proofs and trusted time need traceseal-observe.
    """
    chains: dict[str, dict[int, dict]] = {}
    bodies: dict[str, dict[int, str]] = {}
    copies: dict[str, dict[int, list[dict]]] = {}
    report: dict[str, dict] = {}
    for r in receipts:
        try:
            ex = r.get("execution", {}) if isinstance(r, dict) else None
            if not isinstance(ex, dict) or ex.get("chain_version") != _CHAIN_VERSION:
                continue
            cid, seq = ex.get("chain_id"), ex.get("chain_seq")
            if not isinstance(cid, str) or not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
                continue
            body, h = _body_id(r), receipt_hash(r)
            str(r["attestation"]["operator_public_key"])
        except Exception:
            # Not a verified receipt shape; verify_receipt rejects these.
            continue
        entry = report.setdefault(cid, {"errors": [], "gaps": [], "forks": [],
                                        "compromised_seqs": [], "warnings": []})
        slot = chains.setdefault(cid, {})
        if seq in slot:
            if bodies[cid][seq] != body:
                entry["forks"].append(seq)
                entry["errors"].append(f"seq {seq}: two different signed receipts claim this position (fork)")
            elif all(receipt_hash(c) != h for c in copies[cid][seq]):
                copies[cid][seq].append(r)
                entry["warnings"].append(
                    f"seq {seq}: duplicate copy differs only outside the signed payload")
            continue
        slot[seq] = r
        bodies.setdefault(cid, {})[seq] = body
        copies.setdefault(cid, {})[seq] = [r]
    for cid, slot in chains.items():
        entry = report[cid]
        seqs = sorted(slot)
        # The signed chain_prev_hash of seq s+1 names the chained copy of s.
        for seq in seqs:
            if len(copies[cid][seq]) > 1 and seq + 1 in slot:
                link = slot[seq + 1]["execution"].get("chain_prev_hash")
                for c in copies[cid][seq]:
                    if receipt_hash(c) == link:
                        slot[seq] = c
                        break
        entry.update(first_seq=seqs[0], last_seq=seqs[-1], count=len(seqs),
                     starts_at_genesis=seqs[0] == 1)
        first = slot[seqs[0]]["execution"]
        if (seqs[0] == 1) != (first.get("chain_prev_hash") == "genesis"):
            entry["errors"].append(f"seq {seqs[0]}: genesis link is wrong")
        expected = str(slot[seqs[0]]["attestation"]["operator_public_key"])
        for i, seq in enumerate(seqs):
            if len(copies[cid][seq]) > 1 and str(slot[seq]["attestation"]["operator_public_key"]) != expected:
                for c in copies[cid][seq]:
                    if str(c["attestation"]["operator_public_key"]) == expected:
                        slot[seq] = c
                        break
            r = slot[seq]
            ex = r["execution"]
            signer = str(r["attestation"]["operator_public_key"])
            key_ok = signer == expected
            if i:
                before = seqs[i - 1]
                if seq != before + 1:
                    entry["gaps"].append([before + 1, seq - 1])
                    if not key_ok:
                        entry["errors"].append(
                            f"seq {seq}: signing key changed across the gap before it; "
                            "the rotation cannot be verified")
                else:
                    if ex.get("chain_prev_hash") != receipt_hash(slot[before]):
                        entry["errors"].append(f"seq {seq}: chain_prev_hash does not match seq {before}")
                    if not key_ok:
                        entry["errors"].append(f"seq {seq}: signing key changed without a valid rotation")
            # Never adopt a key that did not arrive through a verified rotation.
            if ex.get("receipt_type") == _ROTATION:
                nxt = _rotation_next_key(ex, signer) if key_ok else None
                if nxt is None:
                    entry["errors"].append(f"seq {seq}: invalid key rotation")
                    continue
                expected = nxt
                after = ex.get("previous_key_compromised_after_seq")
                if after is not None and after + 1 <= seq - 1:
                    lo, hi = after + 1, seq - 1
                    entry["compromised_seqs"].append([lo, hi])
                    present = [s for s in seqs if lo <= s <= hi]
                    if present and not allow_compromised:
                        entry["errors"].append(
                            f"seq {lo}..{hi}: {len(present)} supplied receipt(s) signed by a "
                            "key the operator declared compromised")
                    else:
                        entry["warnings"].append(
                            f"seq {lo}..{hi}: signed by a key the operator declared compromised")
        entry["ok"] = not entry["errors"] and not entry["gaps"]
    return report
