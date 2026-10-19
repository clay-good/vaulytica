# Tasks

- [ ] 1. Field census: for each proposed column, measure over the 363 specimens how often the extractor fills it today and read a sample; drop or defer a column under 20% reach unless its blanks are honest silence (assignment, change of control).
- [ ] 2. Assignment / change-of-control classifier: locate the clause with the existing clause locator; classify by bounded markers (consent, unreasonably withheld, freely, affiliate, merger / sale of substantially all assets); fixture reach test; no finding, projection only.
- [ ] 3. `src/report/abstract.ts`: projection with provenance, coverage line, `inventory_hash`; CSV writer through the shared formula-guarded writer; first-line disclaimer from `disclaimers.ts`.
- [ ] 4. Formats `abstract-json`, `abstract-csv`, `inventory-csv`, `inventory-json` in `artifacts.ts`; `--help` lists them; `export-reach.test.ts` extended.
- [ ] 5. Browser: single-document export buttons; bundle view "Download inventory"; byte parity with the CLI.
- [ ] 6. MCP: `export_report` formats; `abstract_document` tool with the same caps and `excerpts` semantics as `analyze_document`.
- [ ] 7. Determinism: report-reproducibility test renders the inventory twice; two-"today" metamorphic test confirms nothing relative to the clock enters it.
- [ ] 8. Docs: `reference.md` exports table, README exports sentence, `ci-integration.md` inventory example.
- [ ] 9. Full gate green.
