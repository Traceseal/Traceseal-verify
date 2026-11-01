"""Regression tests for the 2026-11 cryptographic red-team findings
(traceseal-verify 1.2.0)."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import random
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from traceseal_verify import (
    canonical_dumps,
    check_chains,
    is_weak_ed25519_public_key,
    loads_json,
    receipt_hash,
    verify_receipt,
)

SRC = str(Path(__file__).resolve().parents[1] / "src")
P = 2**255 - 19
IDENTITY = "01" + "00" * 31
UNIVERSAL_SIG = "58" + "66" * 31 + "01" + "00" * 31  # (R = B, S = 1)
SMALL_ORDER = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
]


def _key():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _fp(pk: bytes, full=False) -> str:
    d = hashlib.sha256(pk).hexdigest()
    return "ed25519:" + (d if full else d[:32])


def _sign(sk, pk, execution, provenance=None):
    provenance = provenance or {}
    return {
        "receipt_version": "1.0",
        "execution": execution,
        "provenance": provenance,
        "attestation": {
            "operator_public_key": pk.hex(),
            "operator_fingerprint": _fp(pk),
            "attested_at": "2026-10-01T00:00:00Z",
            "signature": sk.sign(canonical_dumps({"execution": execution, "provenance": provenance})).hex(),
        },
    }


def _link(seq, prev, cid="c", **extra):
    return {"receipt_type": "tool", "tool_name": f"t{seq}", "chain_version": "1.0",
            "chain_id": cid, "chain_seq": seq, "chain_prev_hash": prev,
            "chained_at": "2026-10-01T00:00:00Z", **extra}


def _chain(n, sk=None, pk=None, start=1, prev="genesis"):
    if sk is None:
        sk, pk = _key()
    out = []
    for seq in range(start, start + n):
        r = _sign(sk, pk, _link(seq, prev))
        prev = receipt_hash(r)
        out.append(r)
    return sk, pk, out


def _rotation(sk, pk, seq, prev, nsk, npk, **extra):
    ex = {"receipt_type": "chain_key_rotation", "rotation_version": "1.0",
          "rotation_reason": extra.pop("reason", "scheduled"),
          "previous_public_key": pk.hex(), "next_public_key": npk.hex(),
          "chain_version": "1.0", "chain_id": "c", "chain_seq": seq,
          "chain_prev_hash": prev, "chained_at": "2026-10-01T00:00:00Z", **extra}
    msg = canonical_dumps({k: ex[k] for k in ("chain_id", "chain_prev_hash", "chain_seq",
                                               "next_public_key", "previous_public_key")}
                          | {"purpose": "traceseal-chain-key-acceptance/1"})
    ex["next_key_acceptance"] = nsk.sign(msg).hex()
    return _sign(sk, pk, ex)


def _cli(*args, stdin=None):
    env = dict(os.environ, PYTHONPATH=SRC)
    return subprocess.run([sys.executable, "-m", "traceseal_verify.cli", *args],
                          capture_output=True, text=True, env=env, input=stdin)


def _files(tmp_path, receipts):
    out = []
    for i, r in enumerate(receipts):
        p = tmp_path / f"{i:02d}.json"
        p.write_text(json.dumps(r))
        out.append(str(p))
    return out


class TestWeakKeys:
    def test_small_order_and_non_canonical(self):
        for h in SMALL_ORDER:
            assert is_weak_ed25519_public_key(h) and is_weak_ed25519_public_key(bytes.fromhex(h))
        for y in range(P, 2**255):
            for sign in (0, 1):
                assert is_weak_ed25519_public_key((y | sign << 255).to_bytes(32, "little"))
        assert is_weak_ed25519_public_key((1 | 1 << 255).to_bytes(32, "little"))
        assert is_weak_ed25519_public_key((2).to_bytes(32, "little"))  # off curve
        for _ in range(20):
            assert not is_weak_ed25519_public_key(_key()[1])

    def test_universal_forgery_rejected(self):
        for h in SMALL_ORDER:
            pk = bytes.fromhex(h)
            r = {"receipt_version": "1.0",
                 "execution": {"receipt_type": "tool", "tool_name": "refund", "amount": "999999"},
                 "provenance": {},
                 "attestation": {"operator_public_key": h, "operator_fingerprint": _fp(pk),
                                 "signature": UNIVERSAL_SIG}}
            result = verify_receipt(r)
            assert not result.ok and "small-order" in result.message

    def test_rotation_to_weak_key_rejected(self):
        sk, pk, rs = _chain(1)
        ex = {"receipt_type": "chain_key_rotation", "rotation_version": "1.0",
              "rotation_reason": "scheduled", "previous_public_key": pk.hex(),
              "next_public_key": IDENTITY, "next_key_acceptance": UNIVERSAL_SIG,
              "chain_version": "1.0", "chain_id": "c", "chain_seq": 2,
              "chain_prev_hash": receipt_hash(rs[0]), "chained_at": "2026-10-01T00:00:00Z"}
        rot = _sign(sk, pk, ex)
        assert verify_receipt(rot).ok
        c = check_chains(rs + [rot])["c"]
        assert any("invalid key rotation" in e for e in c["errors"])


class TestGapKeySwitch:
    def test_key_change_across_gap_is_an_error(self, tmp_path):
        sk, pk, honest = _chain(3)
        ask, apk, forged = _chain(2, start=5, prev="sha256:" + "ab" * 32)
        c = check_chains(honest + forged)["c"]
        assert not c["ok"]
        assert any("across the gap" in e for e in c["errors"])
        assert any("seq 6" in e for e in c["errors"])  # attacker key never adopted
        done = _cli("--allow-gaps", *_files(tmp_path, honest + forged))
        assert done.returncode == 1, done.stdout
        assert "across the gap" in done.stdout

    def test_same_key_across_gap_passes_with_allow_gaps(self, tmp_path):
        sk, pk, rs = _chain(4)
        files = _files(tmp_path, [rs[0], rs[3]])
        assert _cli(*files).returncode == 1
        assert _cli("--allow-gaps", *files).returncode == 0


class TestForkFraming:
    def test_attestation_only_copy_is_a_duplicate(self, tmp_path):
        sk, pk, rs = _chain(3)
        for mutate in (
            lambda a: a.__setitem__("attested_at", "1999-01-01T00:00:00Z"),
            lambda a: a.__setitem__("operator_fingerprint", _fp(pk, full=True)),
        ):
            twin = copy.deepcopy(rs[1])
            mutate(twin["attestation"])
            assert verify_receipt(twin).ok  # still a valid receipt
            for order in (rs + [twin], [twin] + rs):
                c = check_chains(order)["c"]
                assert c["ok"] and c["forks"] == [], c
            assert _cli(*_files(tmp_path, [twin] + rs)).returncode == 0

    def test_resigned_copy_is_not_a_fork(self):
        sk, pk, rs = _chain(3)
        osk, opk = _key()
        resigned = _sign(osk, opk, rs[1]["execution"])
        c = check_chains([resigned] + rs)["c"]
        assert c["ok"] and c["forks"] == [], c

    def test_signed_difference_is_a_fork(self):
        sk, pk, rs = _chain(3)
        alt = _sign(sk, pk, _link(2, receipt_hash(rs[0]), tool_name="other"))
        c = check_chains(rs + [alt])["c"]
        assert c["forks"] == [2] and not c["ok"]


class TestCompromise:
    def _compromised_chain(self):
        sk, pk, rs = _chain(3)
        nsk, npk = _key()
        rot = _rotation(sk, pk, 4, receipt_hash(rs[-1]), nsk, npk,
                        reason="compromise", previous_key_compromised_after_seq=1)
        after = _sign(nsk, npk, _link(5, receipt_hash(rot)))
        return rs + [rot, after]

    def test_reported_and_failing_by_default(self, tmp_path):
        receipts = self._compromised_chain()
        c = check_chains(receipts)["c"]
        assert c["compromised_seqs"] == [[2, 3]] and not c["ok"]
        assert check_chains(receipts, allow_compromised=True)["c"]["ok"]
        assert check_chains(receipts[3:])["c"]["ok"]  # range not supplied
        files = _files(tmp_path, receipts)
        done = _cli(*files)
        assert done.returncode == 1 and "COMPROMISED: seq 2..3" in done.stdout
        assert _cli("--allow-compromised", *files).returncode == 0
        j = json.loads(_cli("--json", *files).stdout)
        assert j["chains"]["c"]["compromised_seqs"] == [[2, 3]]

    def test_invalid_declaration_is_an_invalid_rotation(self):
        sk, pk, rs = _chain(1)
        nsk, npk = _key()
        for extra in ({"previous_key_compromised_after_seq": 1},  # reason is scheduled
                      {"reason": "compromise", "previous_key_compromised_after_seq": 9},
                      {"reason": "compromise", "previous_key_compromised_after_seq": "0"}):
            rot = _rotation(sk, pk, 2, receipt_hash(rs[0]), nsk, npk, **dict(extra))
            c = check_chains(rs + [rot])["c"]
            assert any("invalid key rotation" in e for e in c["errors"]), extra


class TestStrictJson:
    def test_duplicate_keys_rejected(self, tmp_path):
        sk, pk = _key()
        r = _sign(sk, pk, {"receipt_type": "tool", "tool_name": "lookup_balance"})
        raw = json.dumps(r).replace('"tool_name": "lookup_balance"',
                                    '"tool_name": "wire_transfer_1M", "tool_name": "lookup_balance"')
        p = tmp_path / "dup.json"
        p.write_text(raw)
        done = _cli(str(p))
        assert done.returncode == 1 and "duplicate JSON key" in done.stderr
        assert _cli("-", stdin=raw).returncode == 1
        assert not verify_receipt(raw).ok
        assert verify_receipt(json.dumps(r)).ok

    def test_bool_null_rejected_floats_allowed(self):
        sk, pk = _key()
        for value in (True, False, None):
            result = verify_receipt(_sign(sk, pk, {"receipt_type": "tool", "x": value}))
            assert not result.ok and "RECEIPT-SPEC" in result.message
        assert verify_receipt(_sign(sk, pk, {"receipt_type": "tool", "x": 1.5})).ok
        try:
            loads_json('{"a": NaN}')
            raise AssertionError("NaN accepted")
        except ValueError:
            pass


class TestNoCrash:
    def test_lone_surrogate_cli(self, tmp_path):
        sk, pk = _key()
        r = _sign(sk, pk, {"receipt_type": "tool", "tool_name": "t"})
        r["execution"]["tool_name"] = "\ud800"
        p = tmp_path / "s.json"
        p.write_text(json.dumps(r))
        done = _cli(str(p))
        assert done.returncode == 1 and "Traceback" not in done.stderr
        r2 = _sign(sk, pk, {"receipt_type": "tool"})
        r2["attestation"]["attested_at"] = "\udfff"
        assert not verify_receipt(r2).ok

    def test_hostile_shapes(self):
        sk, pk, rs = _chain(2)
        good = rs[0]
        shapes = []
        for path, value in [
            (("attestation", "operator_public_key"), 7),
            (("attestation", "operator_public_key"), ["a"]),
            (("attestation", "signature"), 5),
            (("attestation", "signature"), {"x": 1}),
            (("attestation",), []),
            (("execution",), "x"),
            (("execution", "chain_seq"), 10**40),
            (("provenance",), [1]),
        ]:
            r = copy.deepcopy(good)
            node = r
            for k in path[:-1]:
                node = node[k]
            node[path[-1]] = value
            shapes.append(r)
        shapes += [None, 1, "x", [], {"receipt_version": "1.0"}, {"execution": {1: 2}}]
        for s in shapes:
            assert not verify_receipt(s).ok if isinstance(s, (dict, type(None), int, list)) else True
            check_chains([s, good])
            check_chains([good, s] + rs)
        weird = copy.deepcopy(good)
        weird["execution"] = {1: "x", "chain_version": "1.0"}
        check_chains([weird])

    def test_random_mutations_never_raise(self):
        sk, pk, rs = _chain(2)
        text = json.dumps(rs[0])
        rng = random.Random(11)
        for _ in range(300):
            i = rng.randrange(len(text))
            mutated = text[:i] + rng.choice('0aZ"{}[],:\\') + text[i + 1:]
            result = verify_receipt(mutated)
            assert isinstance(result.ok, bool)
            try:
                check_chains([loads_json(mutated), rs[1]])
            except ValueError:
                pass


def test_circular_dict_input_fails_instead_of_hanging():
    sk, pk = _key()
    r = _sign(sk, pk, {"receipt_type": "tool", "tool_name": "x"})
    r["execution"]["loop"] = r["execution"]
    result = verify_receipt(r)
    assert not result.ok and "circular" in result.message
    deep = cur = {}
    for _ in range(200):
        cur["d"] = {}
        cur = cur["d"]
    r2 = _sign(sk, pk, {"receipt_type": "tool", "tool_name": "x"})
    r2["execution"]["deep"] = deep
    assert not verify_receipt(r2).ok
