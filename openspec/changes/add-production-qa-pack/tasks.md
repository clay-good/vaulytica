# Tasks

- [x] 1. Bundle member classes (browser JSON layer): `classifyDataMember` + `selectPrivilegeLogMember` in `multi.ts` recognize the `.csv` privilege-log member (one per bundle in v1; >1 → rejected-with-reason); the dropzone lets `.csv` ride the multi-file/folder bundle path (a lone `.csv` is still rejected); `prepareBundle` captures it and `runBundleReport` emits `production_qa` in the bundle JSON — held outside `bundle_fingerprint`, so a csv-free bundle stays byte-identical (regression test pins this + an end-to-end integration test drives the real pipeline). DOCX section + tab surface remain deferred (see Deviations).
- [x] 2. `src/ingest/privilege-log.ts`: deterministic CSV parse (RFC 4180), conservative header synonym map per design.md, typed `PrivilegeLog`, total (never throws), warnings for unmapped columns; property tests.
- [x] 3. Bates extraction from member filenames (prefix/number/padding), bundle-level distribution model; PROD-001 gaps, PROD-002 duplicates/overlaps, PROD-003 prefix inconsistency, PROD-004 padding inconsistency — Sedona protocol citations; findings quote the exact filenames.
- [x] 4. Reconciliation rules: PROD-010 log-range overlaps produced range, PROD-011 produced-sequence gap not covered by any log entry, PROD-012 overlapping/duplicate log rows, PROD-013 rows missing FRCP 26(b)(5)(A) minimum fields (privilege assertion + description); each finding cites the rule text and, for timing/method context, the 2025-12-01 amendments to FRCP 26(f)(3)(D) and 16(b)(3)(B)(iv).
- [x] 5. Pre-production sweep: run the existing delivery scan (HANDOFF-001..005, unchanged) per member; bundle roll-up section with per-check counts and per-document drill-down; sweep result inside the new `production_qa_hash`.
- [x] 6. Production-QA report: tab section + DOCX/JSON export + reconciliation CSV (via the guarded `csvField`); namespaced `production_qa_hash`; scope-of-review block per proposal (no page-stamp reading, no redaction-integrity check, no privilege-merits assessment).
- [x] 7. CLI: `vaulytica analyze production.zip --production-qa` (log auto-detected as the csv member); exit-code gate `--fail-on-production-gap` for CI use before a production goes out.
- [x] 8. Fixtures: a synthetic production set (gap, duplicate, prefix drift, log overlap, unlogged gap, clean); determinism goldens; full gate green.

## Deviations

- **CLI-first, self-contained in `src/production/`.** The whole checkable value
  — Bates sequence reconciliation, privilege-log reconciliation, and the
  pre-production HANDOFF sweep — ships as `vaulytica analyze <dir|.zip>
  --production-qa` with a `--fail-on-production-gap` CI gate and a namespaced
  `production_qa_hash`. This is exactly the "before a production goes out" use
  case. It does NOT touch `src/ingest/multi.ts`, `src/engine/consistency/`, or
  `src/report/bundle.ts`, so every existing bundle golden is byte-identical (no
  csv member enters the hashed bundle path).
- **Browser bundle integration — JSON + dropzone landed; DOCX section + tab still
  deferred.** The `.csv` privilege-log member now rides the browser bundle path: a
  dedicated `selectPrivilegeLogMember` (rather than overloading `AcceptedKind`, so
  the document flow is untouched) pulls the single log aside in `prepareBundle`,
  and `runBundleReport` reconciles it via the same pure `buildProductionQaReport`
  core the CLI uses, emitting `production_qa` in the bundle JSON. It is held
  **outside** `bundle_fingerprint` — the `posture_coherence` precedent — so every
  csv-free bundle is byte-identical (unit + end-to-end tests pin this). Still
  deferred: the consolidated **DOCX** Production-QA section and the report **tab**
  surface (the JSON export carries the full report today), and the per-member
  pre-production HANDOFF sweep in the browser (the CLI runs it; the browser v1
  reconciles from filenames + log only, since raw member bytes are not retained on
  `PreparedBundle`). Zip-embedded `.csv` is also deferred (a multi-file/folder drop
  is the browser path; `extractZipEntries` inflates only `.pdf`/`.docx`).
- **PROD is a bundle-level pass, not a consistency (CC-*) rule.** The
  `requires:DocKind[]` pairwise consistency model does not fit a data-member vs
  produced-set reconciliation; production QA is its own aggregator with its own
  hash (the `posture_coherence` precedent), mirroring the proposal's intent.
- **v1 scope, stated in the report's scope-of-review:** filename-derived Bates
  only (no in-page stamp reading), no redaction-integrity check, no
  privilege-merits assessment.
- **Directory OR .zip input.** A production set is commonly a staging folder; both
  are supported (the single `.csv` member is the privilege log).
