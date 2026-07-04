# Tasks

- [ ] 1. Implement `src/report/definitions.ts`: pure projection from `extracted.definitions` + term-usage locations → the five buckets (undefined-but-used, defined, unused, duplicate, used-before-defined), risk-ordered, with `definitions_hash` over the canonical model.
- [ ] 2. Bundle mode: merge per-document projections and mark cross-document redefinitions (reuse CROSS-DEFTERM's comparison, unchanged).
- [ ] 3. Renderers: DOCX section, CSV, JSON block; determinism tests.
- [ ] 4. Tab view: sortable table with locations; jump-to-excerpt.
- [ ] 5. CLI `--definitions`; stream contract respected.
- [ ] 6. Tests over fixtures with known term inventories; property test — every term in exactly one primary bucket per document.
- [ ] 7. README/site: "Definitions report" feature blurb.
- [ ] 8. Full gate green.
