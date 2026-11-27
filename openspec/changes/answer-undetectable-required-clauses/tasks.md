# Tasks

- [x] 1. Measure the proposed CLI classifier divergence before changing anything — closed as
      no-defect; the CLI routes through `runIngested`, which passes the classifier.
- [x] 2. Measure what wiring the DKB vocab would move (363 specimens: 645 → 6,258 labeled
      paragraphs, 14 → 109 categories, 0 routes, 0 findings).
- [x] 3. Add `detectableCategories(data)`, derived from the classifier's own two inputs.
- [x] 4. Route an undetectable `required_clauses` category to `unevaluable` with a reason that
      names the detectable categories.
- [x] 5. Make `detectable` a required argument and supply it from the DKB at every caller.
- [x] 6. Prove the guard by failing: with the branch disabled, the clean document is accused of
      missing both clauses and the hash test collapses — 2 of 7 red, 5 still green.
