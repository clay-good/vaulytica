# Tasks

- [x] 1. (approved_language, rungs[], party_roles/role_variants AND size_bands all shipped — tasks 3 and 4; the stale DEFERRED note is corrected at the end) Schema v3 in `custom-playbook.ts`: `rungs[]` (ordered labeled predicates between ideal and acceptable, cap `MAX_NEGOTIATION_RUNGS`=8, clause-trap + duplicate-label refinements), `party_role` + `role_variants`, deal-size bands on named thresholds, `approved_language` per position. v2 files parse unchanged (`rungs` optional, additive). Published `docs/v6/playbook.schema.json` updated to document `rungs` AND the previously-missing `approved_language` (the artifact's `additionalProperties:false` was silently rejecting valid v3 playbooks); a new schema-artifact guard pins every negotiation-position property.
- [x] 2. (rungs, role and band resolution all shipped — see tasks 3 and 4) Extend `evaluateNegotiationPosture`: report the highest met rung as `met_rung` (detail only, computed only above the floor); floor semantics untouched — INVARIANT PINNED by test: for a v3 rungs playbook, `tier` ∈ the v2 value set across every draft AND `posture_hash` is byte-identical to the same ladder without rungs, so the 29 coherence commands + goldens are provably unaffected. Verified end-to-end via the real CLI (`--playbook-file … --posture`): 8x draft → tier `acceptable`, `met_rung` "7x cap".
- [x] 3. (CLI + tab both done; tab picker landed 2026-07-17) Role resolution: schema gains playbook-level `party_roles[]` + per-position `role_variants` (validated: variant role must be declared; role_variants require party_roles). `resolvePositionsForRole` applies the selected role's ladder into a concrete single-role playbook BEFORE eval/hash — so `ladderHash` distinguishes roles automatically (verified: vendor vs customer hash differ) and a roleless (v2) playbook is a byte-identical no-op. `--role <name>` on the CLI; unset role with role-varying positions → hard error, undeclared role → hard error (never a silent default). Verified end-to-end: same 8x doc reads `acceptable` as customer, `below-acceptable` as vendor.
- [x] 4. Deal-size band resolution (both paths DONE). Positions carry `size_bands[]` (each `min_value` + a full ladder); `resolvePositionsForDealValue` picks the highest band at/below the resolved value into a concrete ladder BEFORE eval/hash (so `ladderHash` distinguishes deal sizes; a bandless position is a byte-identical no-op). Resolution source: (a) explicit `--deal-value <n>` (resolved at the CLI, works for coherence too), or (b) **auto-detected** from the document's *labeled* total value (`src/extract/deal-value.ts` — "total contract value"/"aggregate fees"/"not to exceed"/… + `$` amount; never a "largest amount" guess; unlabeled ⇒ base default). The applied band is `size_band` DETAIL (outside `posture_hash`), naming the provenance for an auto-detected value; unresolvable ⇒ base default with an honest note. Per-document auto-detection is guarded off for multi-doc/coherence runs (they require explicit `--deal-value` for a shared ladder). Verified end-to-end + unit/integration tests.
- [x] 5. (met rung, approved_language AND the deal-size band all render — verified below) Negotiation sheet: shows the highest met rung ("met rung: <label>") above the floor and quotes `approved_language` beside below-floor dimensions, attributed to the playbook.
- [x] 6. Coherence suites green unchanged (verified: the binary-floor invariant holds — pinned by tests that assert `tier` stays in the v2 set and `posture_hash`/`ladderHash` behave as required for rungs, roles, and bands). The "golden for a v3 playbook run" is served by these invariant + resolver tests rather than a committed artifact file.
- [x] 7. Docs: v3 ladder section added to `docs/v6/playbook-schema.md` (the user-facing custom-playbook doc — `adding-a-playbook.md` covers *built-in* playbooks, not custom ones) with a complete worked example (vendor/customer roles, 3-rung customer ladder, a size band) + the `--role`/`--deal-value` CLI usage; the example is verified to validate and behave as documented.
- [x] 8. Full gate green (typecheck, lint, format, 4,011 tests, build; every sub-feature verified end-to-end through the real CLI).

## Deviations

- **Only the `approved_language` sub-feature shipped; the ladder/role/band
  extensions are DEFERRED.** `approved_language` is additive and rendering-only:
  the team's pre-approved fallback text, carried onto a below-floor position and
  quoted (attributed to the playbook, never generated) in the negotiation sheet.
  It touches NO tier evaluation and is NOT in `posture_hash` (pinned by test:
  the hash is identical with and without it), so it cannot disturb the binary
  floor or the coherence subsystem.
- **`rungs[]` and `party_role`/`role_variants` (`--role`) NOW SHIPPED** as
  their own gated commits, each with the binary-floor invariant pinned and
  verified end-to-end through the real CLI:
  - **Intermediate `rungs[]`** — labeled predicates between ideal and the floor.
    The met rung is reported as `met_rung` DETAIL ONLY; the `tier` stays in the
    v2 value set and `posture_hash` is byte-identical to the same ladder without
    rungs (pinned by test across every draft). No `ladderHash` change (rungs
    don't move the tier a document lands on).
  - **`party_role`/`role_variants`** — one playbook expresses both sides of a
    deal. `resolvePositionsForRole` applies the selected role's ladder into a
    concrete single-role playbook BEFORE eval/hash, so `ladderHash` distinguishes
    roles automatically and a roleless (v2) playbook is a byte-identical no-op.
    Honest failures (varies-by-role with none selected; undeclared role), never
    a silent default. The tab `--role` toggle SHIPPED (follow-up, 2026-07-17):
    the playbook panel renders a "Party role" picker whenever the loaded
    playbook's positions carry `role_variants`; the playbook stays INACTIVE
    until a side is chosen (the tab equivalent of the CLI hard error — before
    this, the tab silently evaluated the base ladder), and the chosen role is
    resolved via the same `resolvePositionsForRole` (re-exported through the
    lazy pipeline chunk, keeping zod out of the eager bundle) into concrete
    positions before anything evaluates or hashes.
- ~~**Deal-size bands (`--deal-value`) REMAIN DEFERRED**~~ — **SHIPPED in task 4**; the paragraph below is kept as the record of what the work turned out to need, and its conclusion is superseded. It was genuinely a
  dedicated change, not a tail-of-session task: `thresholds` is currently INERT
  (consumed only by `ladderHash`, never referenced by predicates, which use
  literal values), and there is NO contract-value extractor in `src/extract/`.
  Bands therefore need (a) a new value-resolution mechanism tying a named
  threshold's band to the deal's size, (b) new deal-value extraction (or a
  `--deal-value`-only first cut), and (c) a fresh decision on whether the
  resolved band enters `posture_hash`. That new infrastructure — on hash-
  critical code — deserves its own focused session. v2 files still parse
  unchanged.

## Correction — 2026-11-23: tasks 1, 2 and 5 were already done

🚨 **These three were marked `[~]` with reasons that tasks 3 and 4 had already
superseded**, and the Deviations section still said "Deal-size bands REMAIN
DEFERRED" directly above a `[x]` task 4 reading "Deal-size band resolution
(both paths DONE)". A reader of this file would have concluded that role
resolution and deal-size bands were unbuilt. They are built.

This is the inverse of the usual stale-record defect: not a claim that
something works when it does not, but a claim that something is missing when it
ships. It is still a false record, and it was costing the next session a
re-derivation.

Verified in the code rather than from the task text:

| Deferred in the note | Where it actually is |
| --- | --- |
| `party_roles`, `role_variants` | `custom-playbook.ts` (10 references each), `resolvePositionsForRole`, `--role`, and the tab's picker via `playbook-panel.ts` |
| deal-size bands | `size_bands` / `min_value` in `custom-playbook.ts`, `resolvePositionsForDealValue`, `--deal-value`, and `src/extract/deal-value.ts` (8.2 KB, 26 tests green) |
| the sheet's band, rung and fallback | `docx.ts` renders "met rung: …", "Deal-size band: …" and "Your approved fallback: …"; `exports.ts` carries `deal_size_band`, `met_rung` and `approved_language` as Markdown and CSV columns (11 tests green) |

What remains open on this change: nothing. The one thing the Deviations
paragraph asked for that is NOT in the code is a *decision* it already records
— the resolved band is DETAIL, outside `posture_hash` — which task 4 made and
pinned by test.
