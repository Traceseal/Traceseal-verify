"""CLI for traceseal-verify."""
from __future__ import annotations

import json
import sys

USAGE = """Usage: traceseal-verify [OPTIONS] RECEIPT_FILE [RECEIPT_FILE ...]

Verify one or more Traceseal Execution Receipts: structure, operator
signature, and that the displayed fingerprint is derived from the key.
Chained receipts given together are also checked for gaps, forks, broken
hash links and key changes outside a valid rotation.

Options:
  -              Read receipt JSON from stdin
  --json         Output results as JSON
  --allow-gaps   Report missing chain positions without failing
  --no-chain     Skip chain checks
  -h, --help     Show this message

Checkpoints, inclusion proofs, timestamps, causality and oversight checks:
  pip install traceseal-observe   (traceseal-chain, traceseal-trace)

Spec: https://traceseal.io/spec"""


def _describe(r) -> str:
    if r.receipt_type in ("", "skill"):
        return f"skill:     {r.skill_name} v{r.skill_version}"
    facts = ", ".join(f"{k}={v}" for k, v in r.summary.items())
    return f"type:      {r.receipt_type}" + (f" ({facts})" if facts else "")


def main() -> None:
    args = sys.argv[1:]

    if not args or args == ["--help"] or args == ["-h"]:
        print(USAGE)
        sys.exit(0 if args else 2)

    flags = {"--json", "--allow-gaps", "--no-chain"}
    json_output = "--json" in args
    allow_gaps = "--allow-gaps" in args
    no_chain = "--no-chain" in args
    files = [a for a in args if a not in flags]

    if not files:
        print("error: no receipt files specified", file=sys.stderr)
        sys.exit(2)

    from traceseal_verify import check_chains, verify_receipt

    all_ok = True
    results = []
    verified: list[dict] = []

    for path in files:
        try:
            if path == "-":
                data = json.load(sys.stdin)
            else:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
        except (OSError, json.JSONDecodeError, ValueError) as e:
            label = "stdin" if path == "-" else path
            results.append({"file": label, "ok": False, "message": f"cannot read receipt: {e}"})
            all_ok = False
            if not json_output:
                print(f"[FAIL] {label}: cannot read receipt: {e}", file=sys.stderr)
            continue

        r = verify_receipt(data)
        results.append({
            "file": path, "ok": r.ok, "message": r.message,
            "receipt_type": r.receipt_type, "summary": r.summary,
            "receipt_hash": r.receipt_hash,
            "skill_name": r.skill_name, "skill_version": r.skill_version,
            "operator_fingerprint": r.operator_fingerprint,
            "publisher_fingerprint": r.publisher_fingerprint,
        })
        if r.ok:
            verified.append(data)
        else:
            all_ok = False
        if not json_output:
            if r.ok:
                print(f"[OK] {path}")
                print(f"  {_describe(r)}")
                print(f"  operator:  {r.operator_fingerprint}")
                if r.publisher_fingerprint:
                    print(f"  publisher: {r.publisher_fingerprint}")
            else:
                print(f"[FAIL] {path}: {r.message}", file=sys.stderr)

    chains = {} if no_chain else check_chains(verified)
    for cid, c in chains.items():
        failed = bool(c["errors"]) or (bool(c["gaps"]) and not allow_gaps)
        if failed:
            all_ok = False
        if not json_output:
            status = "FAIL" if failed else "OK"
            print(f"\n[{status}] chain {cid}: seq {c['first_seq']}..{c['last_seq']}, "
                  f"{c['count']} receipt(s), from genesis: {c['starts_at_genesis']}")
            for lo, hi in c["gaps"]:
                print(f"  GAP: seq {lo}..{hi} missing")
            for e in c["errors"]:
                print(f"  ERROR: {e}")

    if json_output:
        # Without chains, keep the original list output for compatibility.
        print(json.dumps({"receipts": results, "chains": chains}, indent=2)
              if chains else json.dumps(results, indent=2))
    elif all_ok and len(files) > 1:
        print(f"\nAll {len(files)} receipts verified.")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
