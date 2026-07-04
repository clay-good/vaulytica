# add-attorney-review-ledger

## Why

The trust architecture exists but is empty: `docs/legal-basis/ledger.json` is `[]`, so zero of the 1,065 rules carry an attorney sign-off and no review-tier badge reaches any report. For a tool whose pitch is "the second pair of eyes you can cite," an all-author-asserted rule base is the credibility ceiling — and the repo's own frontier notes have long identified the human-gated attorney review as the next real work. This change turns the ledger into a running, visible program instead of an empty file.

## What Changes

- Define the ledger workflow end-to-end: a signing schema (rule id, reviewer bar number/jurisdiction, date, tier: `established` / `prevailing-practice` / `opinion`, notes), a CLI helper to draft entries, and validation in CI (ledger entries must reference real rule ids; tiers from the fixed vocabulary).
- Reports render the tier badge on findings whose rule has a signed entry, and render "unreviewed" *honestly* (absence of a badge, plus a report-level count: "N of M findings cite attorney-reviewed rules").
- A scope-of-review block in every report: "reviewed for: clause completeness and the listed red flags; NOT reviewed for: commercial adequacy, tax, local counsel matters" — matching how attorneys frame limited-scope engagements.
- Prioritized first tranche defined as data, not code: the top-100 rules by severity × firing frequency (from the accuracy scoreboard) listed in `docs/legal-basis/review-queue.md` for a licensed reviewer to work.
- The site's trust section reports the live signed count truthfully (wired to the ledger, so it can never drift).

## Impact

- Affected specs: `legal-authority`
- Affected code: ledger schema/validation test, `src/report/*` badge + scope-block rendering, review-queue generator in `tools/`, site counter; no engine changes
- Risk: the human signing work itself is out of band (requires a licensed attorney); the change ships the rails and the honest zero-state, not fabricated review.
