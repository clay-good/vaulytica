# Tasks

- [ ] 1. `src/ui/results-page.ts`: a pure `buildResultsModel(run, abstract, delivery, criticalDates)` that returns the headline, to-do rows, key terms, observations and covered lines. Unit-test that the to-do rows are exactly the `isActionable` findings plus the critical and warning delivery items, in report order.
- [ ] 2. Render the model in the `complete` state. Rows are `<button aria-expanded>` that open in place and work from the keyboard; several may be open at once. Replace the counts line and the stacked panels, and keep the three trust notices at the top.
- [ ] 3. Quote handling: show the quote only when `hasQuotedExcerpt` (from `src/report/clause-evidence.ts`, exported for reuse) is true; otherwise show the placeholder under "Not in the document." Test with the legend NDA, whose absence findings carry placeholder text at offsets 0–0.
- [ ] 4. Copy suggested change (Clipboard API, with a selectable-text fallback) and `reportLinkForFinding` on each row.
- [ ] 5. Key terms from `buildDocumentAbstract`. Known defect to fix first: the abstract lists signature-block names as parties (the legend NDA's parties include both signatories). Show entries with a role or formation as Parties, and name-only signature-block entries as "Signed by." Measure the split on the corpus before shipping.
- [ ] 6. Folds for Dates to verify, Also noted, and What this review covered (with Adjust this review). A test lists every current panel role and asserts that each still renders somewhere.
- [ ] 7. Print stylesheet: all rows open, controls hidden.
- [ ] 8. Landing page: three cards. `tools/site/sample-report.ts` renders `/sample-report` with the same model and markup.
- [ ] 9. e2e: paste the legend NDA → the headline reads 6, each row's quote matches the finding's evidence, no download fires without a click, there are zero cross-origin requests, and the layout holds at 360 px with no horizontal scroll. Before the change, the same paste shows 36 visible buttons; record the new number.
- [ ] 10. Full gate green.
