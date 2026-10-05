# Data sources

Vaulytica's Deterministic Knowledge Base (DKB) is rebuilt from the public sources listed below. Every artifact in `dkb/dist/<version>/` carries a `SourceCitation` pointing back to the originating record, and the weekly rebuild workflow ([dkb-rebuild.yml](../.github/workflows/dkb-rebuild.yml)) is the only way a new version reaches production. Source declarations live in [dkb/build/sources.yaml](../dkb/build/sources.yaml); fetchers live in [dkb/build/fetchers/](../dkb/build/fetchers/).

| Source                                   | License                              | What we extract                            | Parser                                                          |
| ---------------------------------------- | ------------------------------------ | ------------------------------------------ | --------------------------------------------------------------- |
| **SEC EDGAR**                            | Public domain (US government work)   | EX-10 exhibit corpus (stratified by SIC)   | [`fetchers/edgar.ts`](../dkb/build/fetchers/edgar.ts)           |
| **Office of Law Revision Counsel** (US Code) | Public domain (US government work) | USLM XML by title (9, 11, 15, 17, 18, 26, 35) | [`fetchers/uscode.ts`](../dkb/build/fetchers/uscode.ts)     |
| **eCFR** (Electronic CFR)                | Public domain (US government work)   | Title 16, 17, 29, 49 sections via Versioner API | [`fetchers/ecfr.ts`](../dkb/build/fetchers/ecfr.ts)         |
| **govinfo.gov bulk data**                | Public domain (US government work)   | Public Laws XML (current congress)         | [`fetchers/govinfo.ts`](../dkb/build/fetchers/govinfo.ts)       |
| **Common Paper**                         | CC BY 4.0                            | Mutual NDA, One-Way NDA, Cloud Service Agreement, Professional Services Agreement | [`fetchers/commonpaper.ts`](../dkb/build/fetchers/commonpaper.ts) |
| **CUAD (Atticus Project)**               | CC BY 4.0                            | 41-category clause-annotated corpus        | [`fetchers/cuad.ts`](../dkb/build/fetchers/cuad.ts)             |
| **LEDGAR (lex_glue)**                    | CC BY-NC 4.0                         | 100-category clause-labeled corpus         | [`fetchers/ledgar.ts`](../dkb/build/fetchers/ledgar.ts)         |
| **Uniform Law Commission**               | Permissive (per ULC publication)     | UETA, UCC Article 2, UCITA                 | [`fetchers/ulc.ts`](../dkb/build/fetchers/ulc.ts)               |

## What each source contributes today

Measured on the weekly rebuild logs and every `dkb/dist/` manifest through 2026-10-05. **Only LEDGAR feeds real data into the build.** The statutes and model clauses that rules cite (33 statutes, 30 clauses) come from the hand-curated baseline in [`dkb/dist/v0.0.1-starter/`](../dkb/dist/v0.0.1-starter/), which every build merges in first; no fetched statute or clause has ever reached a published version.

| Source       | Contributes                                   | Why not more                                                                                                   |
| ------------ | --------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| LEDGAR       | 100 classifier categories (5,000 provisions)  | —                                                                                                              |
| SEC EDGAR    | 3 classifier categories                       | The search endpoint returns filing metadata, so the "examples" are filer names and dates, not exhibit text.   |
| US Code      | Nothing                                       | Downloads from uscode.house.gov were cut off mid-transfer or served a maintenance page on every recent build. |
| eCFR         | Nothing                                       | The fetcher asks for today's date; eCFR publishes a few days behind, so every title 404s.                      |
| govinfo      | Nothing                                       | The single `PLAW-118publ.xml` file it requests does not exist; public laws are one file each under `public/`. |
| Common Paper | Nothing                                       | Repos were renamed (`CSA`, `PSA`), One-Way NDA was removed, and each README now holds an FAQ, not the terms.   |
| CUAD         | Nothing                                       | HuggingFace's rows API no longer serves `cuad-qa` (it is a script-based dataset).                              |
| ULC          | Nothing                                       | The download URLs use placeholder keys; the real ones are GUIDs.                                               |

Two things limit how much fixing these would change today. The analysis pipeline does not use the trained vocabulary ([`src/ui/pipeline.ts`](../src/ui/pipeline.ts) passes an empty one; patterns do the classifying), and fetched statutes carry ids like `cfr-16-310.3` while rules cite curated ids like `stat-16-cfr-425`, so a fetched section is never looked up. Importing whole CFR titles would add thousands of unreferenced entries to a file the browser downloads.

## Etiquette

- Every fetcher carries the descriptive User-Agent `Vaulytica DKB Builder (vaulytica.com)`. EDGAR rejects unidentified clients; the others do not require it but get it anyway.
- Per-source rate limits are declared in [sources.yaml](../dkb/build/sources.yaml) and enforced by `RateLimitedHttp`. EDGAR is capped at 10 RPS per SEC's published policy.
- Everything is cached at `dkb/build/cache/{source}/{sha256(url)}`. A re-run after a successful first fetch is network-free.

## License obligations

| Source        | What you must do                                                                                                  |
| ------------- | ----------------------------------------------------------------------------------------------------------------- |
| EDGAR / U.S. Code / eCFR / govinfo | Nothing — these are public domain.                                                          |
| Common Paper  | Preserve attribution. We embed the `attribution` string on every emitted `ClauseLibraryEntry`.                    |
| CUAD          | Preserve attribution. Use is unrestricted under CC BY 4.0.                                                        |
| LEDGAR        | **Non-commercial** (CC BY-NC 4.0). Vaulytica is MIT-licensed but the LEDGAR-derived classifier vocabulary inherits the dataset's commercial-use restriction. Operators redistributing modified DKB builds must respect this. |
| ULC           | Permissive per ULC's publication terms; preserve attribution.                                                     |

## Per-source notes

### SEC EDGAR

EDGAR's full-text search (`efts.sec.gov/LATEST/search-index`) returns paged hits with `_source` metadata; we pull EX-10 exhibits stratified by SIC code as the classifier training corpus. The launch sample is capped at 200 hits so the GitHub Action stays within its 30-minute budget; raise the cap in [edgar.ts](../dkb/build/fetchers/edgar.ts) when the corpus quality demands it.

### US Code

We pull seven contract-relevant titles as USLM XML. The parser ([`parseUslmXml`](../dkb/build/fetchers/uscode.ts)) extracts each `<section>` into a `StatuteRecord` with `usc-<title>-<section>` ids and Bluebook-style citations (`9 U.S.C. § 2`).

### eCFR

Titles 16 (FTC, including UDAP / dark patterns), 17 (Commodity Futures, Securities), 29 (Labor — backs the employment playbook), and 49 (Transportation — for DOT services contracts). The Versioner API requires a date key; the build uses the deterministic `nowIso` slice so re-runs are reproducible.

### govinfo

Public Laws XML by congress. We currently pull congress 118; bump the constant in [govinfo.ts](../dkb/build/fetchers/govinfo.ts) when a new congress begins.

### Common Paper

We pull each template repo's `README.md` from the raw GitHub URL and split on `## ` to extract one `ClauseLibraryEntry` per H2. If a template moves the content outside the README, the parser misses it — switch to the GitHub Contents API and re-test.

### CUAD / LEDGAR

Both pulled via HuggingFace's `datasets-server` rows API so no auth or `datasets` Python library is needed. CUAD gives us 41 supervised categories; LEDGAR gives us 100. The build pipeline reconciles both into the unified taxonomy in [`classifier_taxonomy.json`](../dkb/build/classifier_taxonomy.json).

### ULC

UETA, UCC Article 2, and UCITA as PDFs. The fetcher stages a `StatuteRecord` stub per act; the Step-11 build helper uses `pdfjs-dist` to extract `excerpt` text from the cached bytes.

## Adding a source

1. Add a new entry to [`dkb/build/sources.yaml`](../dkb/build/sources.yaml).
2. Add a parser id to the `ParserId` union in [`dkb/build/types.ts`](../dkb/build/types.ts).
3. Implement a new fetcher under [`dkb/build/fetchers/`](../dkb/build/fetchers/) following the contract `(ctx: FetchContext) => Promise<FetcherResult>`. Split a pure `parse*` function from the network orchestrator so the parser is testable from a fixture string.
4. Register the fetcher in [`fetchers/index.ts`](../dkb/build/fetchers/index.ts).
5. Add a parser test in [`fetchers/parsers.test.ts`](../dkb/build/fetchers/parsers.test.ts) with a representative fixture.
6. Verify `npm test` and `npm run dkb:fetch -- <source-id>` against a live network when possible.
