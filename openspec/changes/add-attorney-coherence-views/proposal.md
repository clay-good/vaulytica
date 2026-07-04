# add-attorney-coherence-views

## Why

The posture-coherence family is 29 CLI commands with engineer vocabulary — volatility, relapse, tenure, settling, recovery-chain — that a deal lawyer will never map to a question they actually ask. The underlying data answers exactly three attorney questions: "did our position slip between drafts?", "which front is weakest right now, and where has it been each round?", and "are our documents consistent with each other?". The family is feature-complete on shape (per the v44 spec); what's missing is a legible front door. No computation changes — this is naming, grouping, and one umbrella command.

## What Changes

- One umbrella CLI command, `vaulytica posture-review <r1.coherence.json> … <rN.coherence.json>`, that runs the three attorney views over a round archive and prints them in deal language: **Position drift** (from trend/movement: which fronts slipped, held, improved since the first and previous rounds), **Exposure map** (the v44 matrix heatmap with its blackout verdict, relabeled "rounds where every stated position was below your floor"), and **Weakest front** (from weak-front/exposure: which dimension binds and in which documents). Each section names the underlying command for drill-down; `--format json` nests the three reports under one `posture_review` document.
- All 29 existing commands unchanged (drill-down surface); the tab's posture card adopts the same three headings.
- `docs/posture-for-attorneys.md`: a one-page guide mapping each attorney question to the view and to the underlying commands, replacing engineer vocabulary in all user-facing copy (site + README feature blurbs) while spec docs keep their internal names.

## Impact

- Affected specs: `attorney-ux` (new capability spec)
- Affected code: new `tools/cli/posture-review.ts` composing three existing pure report modules (unchanged), dispatcher + USAGE, tab copy, one new doc; tests for composition and JSON nesting
- Risk: none to existing outputs — additive command and copy changes only.
