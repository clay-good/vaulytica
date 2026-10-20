# Tasks

- [ ] 1. Bundle page: cross-document conflict rows quoting both clauses, then per-document rows that open the single-document page; existing bundle panels folded.
- [ ] 2. Comparison page: Added / Still open / Resolved groups from the existing `introduced` / `unchanged` / `resolved` buckets, filtered by `isActionable` (today's counts include observations); the author on added rows only once the browser comparison carries attribution (the CLI's `compare --redline` does today; the browser does not).
- [ ] 3. Round-trend page: one row per moved front, before and after.
- [ ] 4. Download sections per `simplify-result-downloads`; every current export stays reachable (one export-reach test per page).
- [ ] 5. Test that a document's count is identical on its own page, its bundle row and a comparison against itself.
- [ ] 6. e2e for each page at 360 px; no automatic downloads; zero cross-origin requests.
- [ ] 7. Full gate green.
