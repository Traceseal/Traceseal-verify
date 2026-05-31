# Changelog

All notable changes to `traceseal-verify` are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.1] — 2026-05-03

### Fixed
- `verify_receipt()` now correctly accepts an empty `provenance: {}` dictionary, conforming to RECEIPT-SPEC.md §2.3 which states all provenance fields are OPTIONAL. Previously, the `not provenance` check rejected empty-dict provenance, causing valid model-call and tool-call receipts (which legitimately have sparse provenance) to fail verification. Caught by conformance test vector `02-valid-model-call`.

### Notes
- This fix is conservative: any receipt that verified under v1.0.0 will still verify under v1.0.1. The change only allows previously-rejected-but-actually-valid receipts to pass, never the reverse.
- No spec changes. No API changes. Drop-in upgrade.

## [1.0.0] — 2026-04-XX

### Added
- Initial public release of the standalone Receipt Verifier.
- Implements RECEIPT-SPEC.md v1.0 §3 (canonical JSON) and §4 (verification algorithm).
- One-command CLI: `traceseal-verify receipt.json`.
- One dependency: `cryptography>=41.0`.
