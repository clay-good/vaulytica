# add-defined-terms-report

## Why

Deterministic defined-term checking is the most-loved capability in the category (Definely's Definitions Report, Litera Contract Companion; case studies claim 85% reduction in definition errors and ~an hour saved per lawyer per day). Vaulytica already extracts definitions and flags used-but-undefined terms inside rule findings, but there is no dedicated surface an attorney can open, sort, and work through. The data is computed; the deliverable is missing.

## What Changes

- New export and tab view: "Definitions report" — every defined term with its definition location; every *used-but-undefined* term with use locations; every *defined-but-unused* term; terms defined more than once (with both locations); and definition-order notes (term used before defined). In bundle mode it extends across documents (a term defined in the MSA, redefined in the SOW — reusing the existing CROSS-DEFTERM machinery).
- Rendered risk-ordered (undefined-but-used first), exportable as DOCX section, standalone CSV, and JSON with a namespaced `definitions_hash`.
- CLI: `--definitions` flag adds the block to the JSON report and a `definitions` section to the markdown summary.

## Impact

- Affected specs: `report-exports`
- Affected code: new `src/report/definitions.ts` projecting from the existing extraction (`extracted.definitions`, term-usage index) — no engine change; wiring in tab + CLI; tests
- Risk: none — a projection over already-extracted facts, additive everywhere.
