"""Fingerprint derivation (spec §4 Step 3), chain-link checks, and
conformance vectors produced by traceseal-observe."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from traceseal_verify import canonical_dumps, check_chains, receipt_hash, verify_receipt

VECTORS = Path(__file__).parent / "vectors"
CHAIN = sorted((VECTORS / "chain").glob("*.json"))


def _key():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign(sk, pk, execution, *, full_fingerprint=False):
    digest = hashlib.sha256(pk).hexdigest()
    return {
        "receipt_version": "1.0",
        "execution": execution,
        "provenance": {},
        "attestation": {
            "operator_public_key": pk.hex(),
            "operator_fingerprint": "ed25519:" + (digest if full_fingerprint else digest[:32]),
            "attested_at": "2026-10-01T00:00:00Z",
            "signature": sk.sign(canonical_dumps({"execution": execution, "provenance": {}})).hex(),
        },
    }


def _chain(n, chain_id="c"):
    sk, pk = _key()
    out, prev = [], "genesis"
    for seq in range(1, n + 1):
        r = _sign(sk, pk, {"receipt_type": "tool", "tool_name": f"t{seq}", "chain_version": "1.0",
                           "chain_id": chain_id, "chain_seq": seq, "chain_prev_hash": prev,
                           "chained_at": "2026-10-01T00:00:00Z"})
        prev = receipt_hash(r)
        out.append(r)
    return sk, pk, out


class TestFingerprint:
    def test_both_fingerprint_forms_verify(self):
        sk, pk = _key()
        for full in (False, True):
            assert verify_receipt(_sign(sk, pk, {"receipt_type": "tool"}, full_fingerprint=full)).ok

    def test_relabelled_fingerprint_rejected(self):
        sk, pk = _key()
        r = _sign(sk, pk, {"receipt_type": "tool"})
        r["attestation"]["operator_fingerprint"] = "ed25519:" + "0" * 32
        result = verify_receipt(r)
        assert not result.ok and "fingerprint" in result.message
        del r["attestation"]["operator_fingerprint"]
        assert not verify_receipt(r).ok

    def test_vector_relabelled_fingerprint(self):
        result = verify_receipt(json.loads((VECTORS / "relabelled-fingerprint.json").read_text()))
        assert not result.ok and "fingerprint" in result.message


class TestChains:
    def test_complete_chain(self):
        _, _, rs = _chain(4)
        c = check_chains(rs)["c"]
        assert c["ok"] and c["starts_at_genesis"] and (c["first_seq"], c["last_seq"]) == (1, 4)

    def test_gap(self):
        _, _, rs = _chain(5)
        c = check_chains(rs[:2] + rs[3:])["c"]
        assert not c["ok"] and c["gaps"] == [[3, 3]]

    def test_fork_and_broken_link(self):
        _, _, a = _chain(3)
        _, _, b = _chain(3)
        c = check_chains(a + [b[1]])["c"]
        assert c["forks"] == [2]
        c = check_chains([a[0], b[1], a[2]])["c"]
        assert any("does not match" in e for e in c["errors"])

    def test_key_change_needs_rotation(self):
        sk, pk, rs = _chain(1)
        sk2, pk2 = _key()
        r2 = _sign(sk2, pk2, {"receipt_type": "tool", "chain_version": "1.0", "chain_id": "c",
                              "chain_seq": 2, "chain_prev_hash": receipt_hash(rs[0]),
                              "chained_at": "2026-10-01T00:00:00Z"})
        assert any("without a valid rotation" in e for e in check_chains(rs + [r2])["c"]["errors"])

    def test_unchained_receipts_ignored(self):
        sk, pk = _key()
        assert check_chains([_sign(sk, pk, {"receipt_type": "tool"})]) == {}


class TestProducerVectors:
    def test_every_vector_verifies_with_its_type(self):
        types = set()
        for path in CHAIN:
            result = verify_receipt(json.loads(path.read_text()))
            assert result.ok, (path.name, result.message)
            types.add(result.receipt_type)
            assert result.summary["chain"].startswith("vector-chain#")
        assert {"model", "oversight", "tool", "policy_decision", "chain_key_rotation",
                "incident", "erasure"} <= types

    def test_vector_chain_with_rotation_is_complete(self):
        receipts = [json.loads(p.read_text()) for p in CHAIN]
        c = check_chains(receipts)["vector-chain"]
        assert c["ok"], c
        assert c["count"] == 8

    def test_forged_rotation_rejected(self):
        receipts = [json.loads(p.read_text()) for p in CHAIN]
        rotation = next(r for r in receipts if r["execution"]["receipt_type"] == "chain_key_rotation")
        forged = copy.deepcopy(rotation)
        forged["execution"]["next_key_acceptance"] = "00" * 64
        # Unsigned change: fails the receipt signature itself.
        assert not verify_receipt(forged).ok
        # Even if accepted into the set, the chain check rejects the handover.
        c = check_chains([r if r is not rotation else forged for r in receipts])["vector-chain"]
        assert not c["ok"]

    def test_cli(self):
        cmd = [sys.executable, "-m", "traceseal_verify.cli", *map(str, CHAIN)]
        done = subprocess.run(cmd, capture_output=True, text=True)
        assert done.returncode == 0, done.stdout + done.stderr
        assert "type:      oversight (decision=approved, review_seconds=30" in done.stdout
        assert "[OK] chain vector-chain: seq 1..8, 8 receipt(s), from genesis: True" in done.stdout
        gap = [str(p) for p in CHAIN if not p.name.startswith("03-")]
        done = subprocess.run([sys.executable, "-m", "traceseal_verify.cli", *gap],
                              capture_output=True, text=True)
        assert done.returncode == 1 and "GAP: seq 3..3 missing" in done.stdout
        done = subprocess.run([sys.executable, "-m", "traceseal_verify.cli", "--allow-gaps", *gap],
                              capture_output=True, text=True)
        assert done.returncode == 0
        done = subprocess.run([sys.executable, "-m", "traceseal_verify.cli", "--json", *map(str, CHAIN)],
                              capture_output=True, text=True)
        assert json.loads(done.stdout)["chains"]["vector-chain"]["ok"]
