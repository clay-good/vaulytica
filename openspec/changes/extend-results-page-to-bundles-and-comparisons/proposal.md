# extend-results-page-to-bundles-and-comparisons

## Why

`add-results-page` covers one document. The other three results (several related documents, two versions of one document, and two rounds of a deal) still show counts, panels and a primary "Download … (Word)" button. A user who drops a folder or a revised draft should get the same answer the same way: what to raise, why, then a download if they want one.

## What Changes

All three use the page's parts: headline, to-do rows that open to their evidence, folds, and the Download section from `simplify-result-downloads`.

| Result                   | Headline                                        | To-do list                                                                                                                                                                                                                                         | Below                                                                              |
| ------------------------ | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Several documents**    | "N things to raise across M documents"          | Conflicts between documents first (each row names both documents and quotes both clauses), then one row per document showing its own count; opening a document's row shows that document's page                                                    | Skipped files, cross-document toggle, posture coherence, production QA, all folded |
| **Two versions**         | "The revision added N, resolved M, left K open" | Rows grouped **Added by this revision**, **Still open**, **Resolved**; each added row names the revision's author once the browser carries that attribution (today only `compare --redline` in the CLI does, per `add-redline-two-sided-analysis`) | The clause-level redline summary and the knowledge-base mismatch notice, folded    |
| **Two rounds of a deal** | "Positions moved on N fronts"                   | One row per front that moved, opening to the before and after                                                                                                                                                                                      | Trajectory detail, folded                                                          |

- The "N things" count uses the same `isActionable` definition everywhere, so a document's count is the same on its own page, in a bundle row and in a comparison.
- "Analyze another" stays as a plain link at the bottom of each page.
- Downloads keep at most three named files up front (the consolidated report, a .zip of everything for a bundle, and the comparison report), with the rest under Other formats.

## Impact

- Affected specs: `results-page`
- Affected code: the `bundle-complete`, `comparison-complete`, `bundle-comparison-complete` and `coherence-trend-complete` templates in `src/ui/states.ts`, reusing the row and fold components from `add-results-page`
- Hashes: none; render-side only
- Order: after `add-results-page` and `simplify-result-downloads`
