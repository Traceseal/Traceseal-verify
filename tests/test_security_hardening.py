"""Security-hardening tests for the 2026-06-07 audit HIGH findings.

Covers (traceseal-verify):
  H1 — manifest-hash check must not be skippable by omission on skill receipts
  H2 — signature and public-key hex must be length-bounded before parsing
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from traceseal_verify import canonical_dumps, verify_receipt

MANIFEST = "sha256:" + "ab" * 32


def make_receipt(execution: dict, provenance: dict) -> dict:
    """Build a correctly-signed receipt around the given sections."""
    sk = Ed25519PrivateKey.generate()
    pk_hex = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    payload = canonical_dumps({"execution": execution, "provenance": provenance})
    sig_hex = sk.sign(payload).hex()
    return {
        "receipt_version": "1.0",
        "execution": execution,
        "provenance": provenance,
        "attestation": {"operator_public_key": pk_hex, "signature": sig_hex},
    }


def skill_execution(**overrides) -> dict:
    exec_section = {
        "skill_name": "demo",
        "skill_version": "1.0.0",
        "skill_manifest_hash": MANIFEST,
        "ok": "true",
    }
    exec_section.update(overrides)
    return exec_section


class TestManifestOmission:
    def test_valid_skill_receipt_verifies(self):
        r = make_receipt(skill_execution(), {"manifest_hash": MANIFEST})
        result = verify_receipt(r)
        assert result.ok, result.message

    def test_skill_receipt_missing_provenance_manifest_fails(self):
        """H1: omitting provenance.manifest_hash must not skip the check."""
        r = make_receipt(skill_execution(), {})
        result = verify_receipt(r)
        assert not result.ok
        assert "manifest" in result.message.lower()

    def test_skill_receipt_missing_execution_manifest_fails(self):
        """H1: omitting execution.skill_manifest_hash must not skip the check."""
        execution = skill_execution()
        del execution["skill_manifest_hash"]
        r = make_receipt(execution, {"manifest_hash": MANIFEST})
        result = verify_receipt(r)
        assert not result.ok
        assert "manifest" in result.message.lower()

    def test_explicit_receipt_type_skill_requires_manifest(self):
        r = make_receipt(skill_execution(receipt_type="skill", skill_manifest_hash=""), {})
        result = verify_receipt(r)
        assert not result.ok

    def test_model_receipt_without_manifests_still_verifies(self):
        """Non-skill receipt types (model/tool/...) legitimately omit manifests."""
        execution = {
            "receipt_type": "model",
            "provider": "anthropic",
            "model": "claude-sonnet-4",
            "ok": "true",
        }
        r = make_receipt(execution, {})
        result = verify_receipt(r)
        assert result.ok, result.message

    def test_manifest_mismatch_still_fails(self):
        r = make_receipt(skill_execution(), {"manifest_hash": "sha256:" + "cd" * 32})
        result = verify_receipt(r)
        assert not result.ok
        assert "mismatch" in result.message.lower()


class TestBoundedHexParsing:
    def test_oversized_signature_rejected(self):
        """H2: signature hex must be rejected by length, not parsed unbounded."""
        r = make_receipt(skill_execution(), {"manifest_hash": MANIFEST})
        r["attestation"]["signature"] = "ab" * 100_000
        result = verify_receipt(r)
        assert not result.ok
        assert "signature" in result.message.lower()

    def test_wrong_length_signature_rejected(self):
        r = make_receipt(skill_execution(), {"manifest_hash": MANIFEST})
        r["attestation"]["signature"] = "ab" * 65  # 65 bytes, not 64
        result = verify_receipt(r)
        assert not result.ok

    def test_oversized_public_key_rejected(self):
        r = make_receipt(skill_execution(), {"manifest_hash": MANIFEST})
        r["attestation"]["operator_public_key"] = "ab" * 100_000
        result = verify_receipt(r)
        assert not result.ok
        assert "key" in result.message.lower()
