# Tasks

- [x] 1. Field census: for each proposed column, measure over the 363 specimens how often the extractor fills it today and read a sample; drop or defer a column under 20% reach unless its blanks are honest silence (assignment, change of control).
- [x] 2. Assignment / change-of-control classifier: locate the clause with the existing clause locator; classify by bounded markers (consent, unreasonably withheld, freely, affiliate, merger / sale of substantially all assets); fixture reach test; no finding, projection only.
- [x] 3. `src/report/abstract.ts`: projection with provenance, coverage line, `inventory_hash`; CSV writer through the shared formula-guarded writer; first-line disclaimer from `disclaimers.ts`.
- [x] 4. Formats `abstract-json`, `abstract-csv`, `inventory-csv`, `inventory-json` in `artifacts.ts`; `--help` lists them; `export-reach.test.ts` extended.
- [ ] 5. Browser: single-document export buttons; bundle view "Download inventory"; byte parity with the CLI.
- [ ] 6. MCP: `export_report` formats; `abstract_document` tool with the same caps and `excerpts` semantics as `analyze_document`.
- [x] 7. Determinism: report-reproducibility test renders the inventory twice; two-"today" metamorphic test confirms nothing relative to the clock enters it.
- [x] 8. Docs: `reference.md` exports table, README exports sentence, `ci-integration.md` inventory example.
- [ ] 9. Full gate green.

## Progress — 9.956.0 (slice A)

Built: `src/report/abstract.ts` (projection, coverage, `inventory_hash` over rows with folder-relative paths); `abstract-json`, `abstract-csv`, `inventory-csv`, `inventory-json` in the CLI and the Action; docs; an integration test for projection, provenance, the formula guard, input order and the clock.

Census over the 363 specimens (task 1): parties 342, governing law 222, effective date 202, forum 159, liability cap 103, renewal 23 (honest silence: only auto-renewing documents). Measured and dropped: `term_end`, 4 of 363 resolved by the critical-dates register.

Decided against the proposal, with reasons:
- The statement is in the CSV's SECOND line, the first cell of the coverage row. The CLI's stream contract requires a machine CSV's first line to be its header (`cli-stream-contract.test.ts`), and a spreadsheet reads it that way. The JSON carries it as `statement`.
- Provenance falls back to the paragraph's own clause number (`§ 12.1`) where the document has no section headings, which is every pasted document; the renewal cell has none on such a document, because a finding carries no paragraph id.

Not yet built: the `indemnity_cap`, `notice_addresses`, `signatories` and `page_count` columns, task 5 (browser), task 6 (MCP).

## Progress — 9.957.0

Task 2, built differently from the proposal: the `assignment` cell QUOTES the sentence that restricts assigning the instrument (else the one that mentions it) instead of labelling it. A prototype classifier was measured first and misread exactly the cases a diligence table must get right: "Neither party may assign … without the other's prior written consent, except to a successor" as freely assignable, and a one-sided "Buyer may assign to an affiliate" as the rule. A wrong label is a confident wrong fact; the sentence is the fact. `change_of_control` is `mentioned` when that sentence names one. Reach over the 363 specimens: assignment 63 (57 the restricting rule), change of control 8.

