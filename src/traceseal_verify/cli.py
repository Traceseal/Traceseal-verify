"""CLI for traceseal-verify."""
from __future__ import annotations
import json
import sys


def main() -> None:
    args = sys.argv[1:]

    if not args or args == ["--help"] or args == ["-h"]:
        print("Usage: traceseal-verify [OPTIONS] RECEIPT_FILE [RECEIPT_FILE ...]")
        print()
        print("Verify one or more Traceseal Execution Receipts.")
        print()
        print("A receipt is a self-contained JSON proof that a specific signed")
        print("AI agent skill ran inside a specific sandbox and produced a")
        print("specific result. Verification requires only the receipt file.")
        print()
        print("Options:")
        print("  -            Read receipt JSON from stdin")
        print("  --json       Output results as JSON")
        print("  -h, --help   Show this message")
        print()
        print("Spec: https://traceseal.io/spec")
        sys.exit(0 if args else 2)

    json_output = "--json" in args
    files = [a for a in args if a != "--json"]

    if not files:
        print("error: no receipt files specified", file=sys.stderr)
        sys.exit(2)

    from traceseal_verify import verify_receipt, verify_receipt_file

    all_ok = True
    results = []

    for path in files:
        if path == "-":
            try:
                data = json.load(sys.stdin)
            except (json.JSONDecodeError, ValueError) as e:
                results.append({"file": "stdin", "ok": False, "message": f"invalid JSON: {e}"})
                all_ok = False
                if not json_output:
                    print(f"[FAIL] stdin: invalid JSON: {e}", file=sys.stderr)
                continue
            from traceseal_verify import verify_receipt as _vr
            r = _vr(data)
        else:
            r = verify_receipt_file(path)

        result_dict = {
            "file": path, "ok": r.ok, "message": r.message,
            "skill_name": r.skill_name, "skill_version": r.skill_version,
            "operator_fingerprint": r.operator_fingerprint,
            "publisher_fingerprint": r.publisher_fingerprint,
        }
        results.append(result_dict)
        if not r.ok:
            all_ok = False
        if not json_output:
            if r.ok:
                print(f"[OK] {path}")
                print(f"  skill:     {r.skill_name} v{r.skill_version}")
                print(f"  operator:  {r.operator_fingerprint}")
                if r.publisher_fingerprint:
                    print(f"  publisher: {r.publisher_fingerprint}")
            else:
                print(f"[FAIL] {path}: {r.message}", file=sys.stderr)

    if json_output:
        print(json.dumps(results, indent=2))
    if not json_output and all_ok and len(files) > 1:
        print(f"\nAll {len(files)} receipts verified.")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
