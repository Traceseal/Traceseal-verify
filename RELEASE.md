# Release Checklist — traceseal-verify

This document describes the publish process for `traceseal-verify` to PyPI. Treat publishing as **irreversible** — PyPI does not allow deletes, only yanks, and a yanked release still occupies the version number forever.

A new release MUST NOT happen without:

- ✅ Tim's explicit "ship it" go-ahead (one-line confirmation in chat or email)
- ✅ Foundation key has signed the matching spec version (if this release corresponds to a spec change)
- ✅ All conformance test vectors pass against the to-be-published wheel
- ✅ `CHANGELOG.md` updated with the user-facing summary of changes

---

## Pre-publish (always)

```bash
cd /home/tim/traceseal-verify

# 1. Confirm version is consistent
grep -E '^version|^__version__' pyproject.toml src/traceseal_verify/__init__.py

# 2. Wipe stale build artefacts
rm -rf dist/ build/ src/*.egg-info

# 3. Build the wheel + sdist
python3 -m build

# 4. Validate metadata
twine check dist/*

# 5. Run conformance vectors against the freshly-built wheel
python3 -m pip install --user dist/*.whl --force-reinstall
python3 /home/tim/traceseal-plan/v1.0-freeze/build_vectors.py
# Expected: all 10 PASS

# 6. Sanity-check CLI
traceseal-verify /home/tim/traceseal-plan/v1.0-freeze/test-vectors/01-valid-skill.json
# Expected: [OK] ...
```

If anything in steps 1-6 fails, **STOP**. Do not publish.

---

## Publish

Only after Tim's explicit go-ahead:

```bash
cd /home/tim/traceseal-verify

# Upload to PyPI (uses ~/.pypirc credentials)
twine upload dist/traceseal_verify-X.Y.Z-py3-none-any.whl \
            dist/traceseal_verify-X.Y.Z.tar.gz

# Tag the release in git
git tag -a v1.0.1 -m "Release v1.0.1: empty-provenance fix"
git push origin v1.0.1

# Create GitHub Release with the CHANGELOG.md entry as the body
gh release create v1.0.1 dist/* --notes-file CHANGELOG.md
```

Wait ~2 minutes for PyPI to propagate, then verify:

```bash
# Fresh-install in a clean venv to confirm PyPI sees it
python3 -m venv /tmp/verify-test
/tmp/verify-test/bin/pip install traceseal-verify==X.Y.Z
/tmp/verify-test/bin/traceseal-verify --help
rm -rf /tmp/verify-test
```

---

## Post-publish

1. **Log to PLAN.md §9** with the date, version, and key behaviour change.
2. **Update `traceseal.io`** to advertise the new version (if user-facing).
3. **If this release corresponds to a spec change**: update the canonical metadata at `traceseal.io/spec/vX.Y/` to reference the new verifier version.
4. **Notify stewards** via the Foundation mailing list when the release is significant.

---

## Yank procedure (if a release is broken)

```bash
# Mark version as yanked on PyPI (does not delete; users with the version pinned still get it)
twine yank traceseal-verify --version X.Y.Z --reason "explanation"
```

A yank is a public admission. Use only for security issues or hard correctness failures. Always ship a fixed version (`X.Y.Z+1`) the same day as the yank.

---

## Notes on publish credentials

Credentials live in `~/.pypirc` under `[pypi]` with a token-based username (`__token__`). The token has upload-only scope on the `traceseal-verify` project. Never commit the token to a repo. Rotate on YubiKey-protected workstation only.
