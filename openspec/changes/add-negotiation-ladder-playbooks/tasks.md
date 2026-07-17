# Tasks

- [~] 1. (PARTIAL — approved_language + rungs[] done; party_role/role_variants/deal-size-bands DEFERRED, see Deviations) Schema v3 in `custom-playbook.ts`: `rungs[]` (ordered labeled predicates between ideal and acceptable, cap `MAX_NEGOTIATION_RUNGS`=8, clause-trap + duplicate-label refinements), `party_role` + `role_variants`, deal-size bands on named thresholds, `approved_language` per position. v2 files parse unchanged (`rungs` optional, additive). Published `docs/v6/playbook.schema.json` updated to document `rungs` AND the previously-missing `approved_language` (the artifact's `additionalProperties:false` was silently rejecting valid v3 playbooks); a new schema-artifact guard pins every negotiation-position property.
- [~] 2. (rungs done; role/band DEFERRED) Extend `evaluateNegotiationPosture`: report the highest met rung as `met_rung` (detail only, computed only above the floor); floor semantics untouched — INVARIANT PINNED by test: for a v3 rungs playbook, `tier` ∈ the v2 value set across every draft AND `posture_hash` is byte-identical to the same ladder without rungs, so the 29 coherence commands + goldens are provably unaffected. Verified end-to-end via the real CLI (`--playbook-file … --posture`): 8x draft → tier `acceptable`, `met_rung` "7x cap".
- [~] 3. (CLI done; tab toggle DEFERRED as UI follow-up) Role resolution: schema gains playbook-level `party_roles[]` + per-position `role_variants` (validated: variant role must be declared; role_variants require party_roles). `resolvePositionsForRole` applies the selected role's ladder into a concrete single-role playbook BEFORE eval/hash — so `ladderHash` distinguishes roles automatically (verified: vendor vs customer hash differ) and a roleless (v2) playbook is a byte-identical no-op. `--role <name>` on the CLI; unset role with role-varying positions → hard error, undeclared role → hard error (never a silent default). Verified end-to-end: same 8x doc reads `acceptable` as customer, `below-acceptable` as vendor.
- [ ] 4. Deal-size band resolution: from extracted contract value or `--deal-value`; the resolved band and its source are stamped into the posture block; unresolvable value → the position evaluates under its `default` band and the report says so.
- [~] 5. (met-rung + approved_language done; full deal-size-band ladder DEFERRED with bands) Negotiation sheet: shows the highest met rung ("met rung: <label>") above the floor and quotes `approved_language` beside below-floor dimensions, attributed to the playbook.
- [ ] 6. Coherence suites green unchanged; new golden for a v3 playbook run.
- [ ] 7. Docs: `docs/adding-a-playbook.md` v3 section with a complete example (vendor/customer roles, 3 rungs, 2 size bands).
- [ ] 8. Full gate green.

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
    a silent default. The tab `--role` toggle is deferred as a UI follow-up.
- **Deal-size bands (`--deal-value`) REMAIN DEFERRED** — and are genuinely a
  dedicated change, not a tail-of-session task: `thresholds` is currently INERT
  (consumed only by `ladderHash`, never referenced by predicates, which use
  literal values), and there is NO contract-value extractor in `src/extract/`.
  Bands therefore need (a) a new value-resolution mechanism tying a named
  threshold's band to the deal's size, (b) new deal-value extraction (or a
  `--deal-value`-only first cut), and (c) a fresh decision on whether the
  resolved band enters `posture_hash`. That new infrastructure — on hash-
  critical code — deserves its own focused session. v2 files still parse
  unchanged.
