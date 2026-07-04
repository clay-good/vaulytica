# Tasks

- [ ] 1. Ledger entry schema (zod): rule id, reviewer name + bar jurisdiction/number, review date, tier (`established` | `prevailing-practice` | `opinion`), notes, source pins reviewed. CI validation test: entries reference real rule ids; no duplicates.
- [ ] 2. `tools/legal-basis/queue.ts`: generate `docs/legal-basis/review-queue.md` — top-100 rules by severity × scoreboard firing frequency, with each rule's citations to check.
- [ ] 3. Report rendering: tier badge on signed-rule findings in DOCX/HTML/JSON; report-level "N of M findings cite attorney-reviewed rules" count; absence renders as no badge, never as a fabricated tier.
- [ ] 4. Scope-of-review block appended to every report near the disclaimer (fixed text, versioned).
- [ ] 5. Site trust section: live signed-rule count read from the ledger at build time (guard test pins site count == ledger length).
- [ ] 6. `docs/legal-basis/README.md`: the signing workflow for reviewers (how to review a rule, what signing attests, how tiers are assigned).
- [ ] 7. Full gate green.
