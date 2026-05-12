# dkb/build/v3 — v3 DKB Build Pipeline

This directory holds the v3 DKB fetchers and build utilities.

Per spec-v3.md §§21–22, each fetcher:
1. Implements HTTP fetch with conditional GET (If-Modified-Since / ETag) and
   exponential-backoff retry.
2. Implements a parser that produces structured DKB nodes per source.
3. Records content hashes for the source-pinning protocol (spec-v3.md §14).
4. Supports an offline mode that replays snapshot fixtures from
   `dkb/fixtures/v3/snapshots/` so CI does not hit the network.

## Planned fetchers (Steps 21–22)

### Step 21 — HIPAA and US state-privacy (spec-v3.md §§5, 7, 8)

- `hipaa-ecfr.ts` — eCFR Title 45 Part 164 (XML via eCFR versioner API).
- `hhs-sample-baa.ts` — HHS model BAA HTML.
- `hhs-ocr-resolutions.ts` — HHS OCR resolution-agreement index.
- `ccpa.ts` — Cal. Civ. Code §§ 1798.100–1798.199.100 + 11 CCR §§ 7000–7304.
- `state-privacy-us.ts` — Virginia (VCDPA), Colorado (CPA), Connecticut (CTDPA),
  Utah (UCPA), Texas (TDPSA), Oregon (OCPA), Delaware (DPDPA).

### Step 22 — GDPR, SCC, UK IDTA, international (spec-v3.md §§6, 9)

- `gdpr-eurlex.ts` — EUR-Lex GDPR XML (Regulation (EU) 2016/679).
- `eu-scc-eurlex.ts` — EUR-Lex EU SCC Implementing Decision 2021/914.
- `uk-gdpr.ts` — UK GDPR retained-law text (legislation.gov.uk).
- `uk-idta.ts` — ICO UK Addendum and IDTA templates (vendored).
- `swiss-fadp.ts` — Swiss revFADP (fedlex.admin.ch) + FDPIC Swiss Addendum.
- `edpb.ts` — EDPB guidelines index (PDF downloads vendored).
- `international.ts` — PIPEDA, LGPD, APPI, PIPL.

## When does this directory get populated?

Fetchers are implemented in Steps 21 and 22.
This README is created in Step 18 (scaffolding).
