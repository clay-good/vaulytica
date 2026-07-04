# Tasks

- [ ] 1. Bundle member classes: extend `planBundle`/`classifyExtension` with `data_members` (`.csv`, one per bundle in v1); unrecognized/multiple csv → rejected-with-reason; regression test pins csv-free bundles byte-identical.
- [ ] 2. `src/ingest/privilege-log.ts`: deterministic CSV parse (RFC 4180), conservative header synonym map per design.md, typed `PrivilegeLog`, total (never throws), warnings for unmapped columns; property tests.
- [ ] 3. Bates extraction from member filenames (prefix/number/padding), bundle-level distribution model; PROD-001 gaps, PROD-002 duplicates/overlaps, PROD-003 prefix inconsistency, PROD-004 padding inconsistency — Sedona protocol citations; findings quote the exact filenames.
- [ ] 4. Reconciliation rules: PROD-010 log-range overlaps produced range, PROD-011 produced-sequence gap not covered by any log entry, PROD-012 overlapping/duplicate log rows, PROD-013 rows missing FRCP 26(b)(5)(A) minimum fields (privilege assertion + description); each finding cites the rule text and, for timing/method context, the 2025-12-01 amendments to FRCP 26(f)(3)(D) and 16(b)(3)(B)(iv).
- [ ] 5. Pre-production sweep: run the existing delivery scan (HANDOFF-001..005, unchanged) per member; bundle roll-up section with per-check counts and per-document drill-down; sweep result inside the new `production_qa_hash`.
- [ ] 6. Production-QA report: tab section + DOCX/JSON export + reconciliation CSV (via the guarded `csvField`); namespaced `production_qa_hash`; scope-of-review block per proposal (no page-stamp reading, no redaction-integrity check, no privilege-merits assessment).
- [ ] 7. CLI: `vaulytica analyze production.zip --production-qa` (log auto-detected as the csv member); exit-code gate `--fail-on-production-gap` for CI use before a production goes out.
- [ ] 8. Fixtures: a synthetic production set (gap, duplicate, prefix drift, log overlap, unlogged gap, clean); determinism goldens; full gate green.
