# traceseal-verify

**Status:** active (shipped — v1.0.1 on PyPI)
**Owner intent:** The public TraceSeal verification package. Released 2026-05-31; maintained, not in active feature development.
**Last reviewed:** 2026-06-05

## Run
```bash
pip install -e .          # setuptools project (src/ layout)
python -m pytest tests/
```

## Depends on
- Receipt spec in `RECEIPT-SPEC.md` (and the v2 draft in `~/projects/traceseal/traceseal-plan` for future work).

## Depended on by
- PyPI users; sibling packages traceseal-observe / traceseal-langchain pair with it.

## Gotchas
- Repo clean, remote Traceseal/Traceseal-verify. Release process documented in `RELEASE.md` — follow it, don't push ad-hoc tags.
- Spec changes are breaking for verifiers in the wild; v2 belongs in the PoC until the spec freezes.
