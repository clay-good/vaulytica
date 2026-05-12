# dkb/fixtures/v3 — v3 Fixture Corpus

This directory holds vendored regulator-published materials and curated real-world
documents that serve as the ground truth for v3 rules, tests, and golden outputs.

Per spec-v3.md §15, the full corpus will include:

## Regulator-published materials (~80 documents)

- `hhs-sample-baa.html` + `hhs-sample-baa.parsed.json` — HHS model BAA provisions
  (fetched from hhs.gov, public domain US government work).
- `eu-scc-2021-914-module-2.docx` + `eu-scc-2021-914-module-3.docx` — EU SCC official
  template (Commission Implementing Decision 2021/914), clause-indexed.
- `uk-idta-template.docx` + `uk-addendum-template.docx` — ICO-published templates.
- `swiss-addendum-template.pdf` — FDPIC Swiss Addendum.
- `iapp-dpa-reference.docx` (if license clearable; otherwise EDPB-published DPA example).
- `ocr-resolutions/` — HHS OCR resolution-agreement summaries (~30 JSON files).
- `snapshots/` — HTTP snapshot fixtures for the v3 fetchers (used in offline CI).
- `uk-idta/` — ICO UK Addendum and IDTA published-template documents.
- ACORD 25 blank form (for layout recognition).

## Curated real-world corpus (public sources)

- 25 real-world BAAs (SEC EDGAR 8-K Item 1.01 exhibits).
- 25 real-world DPAs.
- 15 real-world MSAs.
- 15 real-world NDAs (CUAD + open-source project legal docs).
- 10 EULAs.
- 10 ToS.
- 10 privacy policies.
- 5 COIs.

Each document carries provenance metadata and a baseline expected-findings JSON.
New v3 builds re-run the corpus and diff against baselines; any change in findings
without a corresponding rule change is a test failure.

## When does this directory get populated?

Fetchers are implemented in Steps 21 (HIPAA, US state) and 22 (GDPR, SCC, UK, international).
Curated real-world documents are vendored in Step 34 (golden tests).
This README is created in Step 18 (scaffolding).
