# add-contract-abstract-inventory

## Why

The first deliverable in a diligence, a migration into a contract system, or a portfolio review is not a findings report. It is the abstract: one row per agreement with the facts a person would otherwise type by hand: type, parties and roles, effective date, term and expiry, renewal and notice window, governing law and forum, caps, assignment and change-of-control treatment. Every contract-lifecycle vendor sells extraction of this table, and a vendor field list (parties, initial term, end dates, notice period, governing law, venue, assignment, renewal term, change of control) is the de facto standard. Vaulytica already extracts almost every one of those facts, for every document, deterministically, and renders them only as an appendix inside the Word report or as inputs to rules. The portfolio matrix answers "which of these lack a cap"; nothing answers "what are these".

A folder dropped in the browser or named on the CLI should yield the inventory as a CSV and JSON, with each cell traceable to the section it was read from, and with blanks where the extractor found nothing, never a guess. For a data room of 400 documents this is the table the deal team builds in the first week.

## What Changes

- **An abstract per document**, a pure projection of `ExtractedData` and the run's classification: `document_type` (family id and label; "unmatched" where no family matched), `secondary_families` (detected, not confirmed), `title`, `parties[]` with role and formation state where read, `effective_date`, `term` (as stated: duration and anchor), `expiry` (computed only when the critical-dates register resolved it), `renewal` (none / automatic / optional, with the notice window), `governing_law`, `forum`, `liability_cap` (amount or multiple, as the metric extractor reads it), `indemnity_cap`, `assignment` (silent / consent required / freely assignable / with change-of-control exception, from a bounded clause classifier over the located assignment clause), `change_of_control` (silent / present), `notice_addresses` count, `signatories` count, `page_count` / `word_count`, `result_hash`. Every non-empty cell carries `section_label` provenance.
- **Exports:** `abstract-json` and `abstract-csv` for one document; for a folder or bundle, `inventory-csv` and `inventory-json` with one row per document plus a `not_analyzed` row per unreadable file, sorted by title. Formula-injection guarded like every CSV the tool writes. An `inventory_hash` over the canonical rows, namespaced apart from every `result_hash`.
- **Reach:** the tab's single-document exports and the bundle view; CLI `--format abstract-csv,inventory-csv`; the Action's `format`; MCP `export_report` formats and a read-only `abstract_document` tool returning the JSON for one path.
- **Honesty:** a blank is a blank. The CSV header row's second line (or the JSON's `coverage`) states for each column how many rows have a value, so a column the extractor rarely fills is visible as such. The abstract states that it is extracted text, not a legal summary, in the file's first line.

## Impact

- Affected specs: `report-exports`
- Affected code: new `src/report/abstract.ts`; a bounded assignment-clause classifier in `src/extract/` (measure-first, fixture-gated like the v10 metrics); `tools/cli/artifacts.ts` formats; bundle UI; MCP tool; `export-reach.test.ts`
- Risk: none to hashes; render-side. The assignment classifier is the one new extractor and ships only with a fixture proving its reach on the corpus.
