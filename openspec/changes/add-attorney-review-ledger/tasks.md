# Tasks

- [x] 1. (ALREADY SHIPPED — spec-v5 Step 75) Ledger entry schema (zod): `LegalBasisEntrySchema` in `tools/accuracy/legal-basis.ts` (rule id, reviewer credential, date, tier, verdict, notes, DKB-pinned legal_basis). CI validation in `tests/integration/legal-basis-ledger.test.ts` (real rule ids; no duplicates; DKB-node pins exist; inline `Rule.tier` backed by a signed entry).
- [x] 2. `tools/legal-basis/queue.ts` + `npm run queue:legal`: generates `docs/legal-basis/review-queue.md` — top-100 UNREVIEWED rules by severity × scoreboard firing frequency, each with its DKB-node citations to check. Deterministic (no wall clock); a golden guard (`queue.test.ts`) pins the committed artifact to the generator.
- [x] 3. Report rendering: report-level "N of M findings cite attorney-reviewed rules" count in JSON (`review_coverage`), HTML, and DOCX — a render-side projection of `run.findings.tier`, outside `result_hash`, always emitted and honest ("0 of N" until a rule is signed). Per-finding tier badge on HTML; per-finding `tier` already carried in JSON `run.findings[]`. Absence renders as no badge, never a fabricated tier (verified end-to-end through the real CLI + unit tests with a synthetic signed tier). (DOCX per-finding badge deferred — dormant until a rule is signed.)
- [x] 4. Universal scope-of-review block (`src/report/engagement-scope.ts`, versioned `ENGAGEMENT_SCOPE_VERSION`) rendered near the disclaimer on every HTML and DOCX report — limited-scope-engagement framing (reviewed for / not reviewed for), distinct from the per-pack "Scope of Review — <pack>" block. Fixed text, outside `run`/`result_hash` (verified: CLI hash unchanged).
- [ ] 5. Site trust section: live signed-rule count read from the ledger at build time (guard test pins site count == ledger length).
- [ ] 6. `docs/legal-basis/README.md`: the signing workflow for reviewers (how to review a rule, what signing attests, how tiers are assigned).
- [ ] 7. Full gate green.

## Deviations

- **Task 1 was already shipped** as spec-v5 Step 75 (the ledger schema, machine
  mirror, `tierForRule`/`ledgerCoverage`, and `Rule.tier`/`Finding.tier`
  plumbing all predate this change), so this change need not re-do it — noted
  here for the audit trail. The remaining rails (queue → report badge → scope
  block → site count → workflow doc) build on that foundation.
- **Task 2 ranks the UNREVIEWED catalog** (signed rules are excluded, so the
  queue shrinks as attorneys sign) and scores `severity × (1 + firing)`. The
  `1 +` keeps severity the primary key while the ground-truth corpus is empty
  (firing is uniformly 0 today) — the queue is severity-then-id ordered and the
  header says so honestly; firing refines the order automatically once real
  annotated documents land, with no code change. Build-and-CI-only, never
  imported by `src/`.
