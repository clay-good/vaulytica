# Tasks

- [x] 1. **ANSWERED at 9.917.0, by a different design than the one planned — and fractions measured and declined.** (Original plan, and why it was deferred: share arithmetic done in-rule to avoid the hashed amounts path. **2026-10-12: the deferral's COST is now measured.** Because no extractor owns the percentage, 42 rule files read one in 139 places, each with its own notion of what one looks like, and two of them disagreed: FIN-009 required the literal sign, so "a late fee of 5 percent per month" was invisible and the 18%/year usury threshold silently did not run; GOV-121 listed `5%` and `five percent` but not `5 percent`, so a proxy stating its 5%-holder table that way was told the table was missing. Both are fixed in 9.911.0 and `tests/integration/percent-word-form.test.ts` now holds the whole class at zero over every specimen that writes a bare percentage — so the other 40 readers and any rule added later are covered without this task being built. That makes the deferral safe to keep, which it was not before.

  **2026-10-12, second look: the task's LITERAL DESIGN IS UNSOUND, and the deferral now rests on the type system and a measurement rather than on a judgment.** "Percentage … as additive fields" means adding non-money entries to `extracted.amounts`, which is `MoneyReference[]` — and `MoneyReference.currency` is a REQUIRED string. Two consumers read that array as money:

  1. [`src/report/docx.ts`](../../../src/report/docx.ts) renders an **Amounts** table with a **Currency** column, so a percentage would print a blank or invented currency in a table an attorney reads; and
  2. **FIN-003** fires `warning` — "Multiple currencies referenced" — whenever `new Set(amounts.map(a => a.currency))` has two or more members.

  Measured over the 363 specimens: **145 contain a bare percentage and have exactly one currency today, and 0 are already multi-currency.** So the naive build would put a confident false multi-currency accusation on **145 documents — 40% of the corpus** — which is the precise harm class this repo has narrowed rules twice to avoid.

  A correct build is therefore a SEPARATE `percentages: PercentageReference[]` field, not an extension of `amounts`. That is a different task from the one written here, and it needs a consumer to be worth adding (see the dead-optional-field sweep: 29 of 201 optional fields were read by nobody). Migrating the 42 in-rule readers to consume it is the work that would make it pay, and none of that is needed for the defect this task was protecting against, which `percent-word-form.test.ts` now holds at zero.

  **The field design was changed, and then it was built.** 9.917.0 adds
  `src/extract/percentages.ts` and `ExtractedData.percentages`, a field of its
  own rather than an extension of `amounts`, with the §58-style appendix table
  in `report/docx.ts` as its consumer — so it is not a dead optional field.
  **455 percentages across 147 of the 363 specimens**, in the three spellings a
  drafted instrument uses: `20%`, `20 percent` / `20 per cent`, and `twenty
  percent`. The spelled-plus-numeral convention `twenty percent (20%)` reads as
  ONE figure, not two.

  🥇 **The task's regression requirement is met literally, and for every
  document rather than only those containing none.** `extractAmounts` is not
  touched, and all **1,114 golden tests pass UNREGENERATED** — `result_hash`
  does not fold in the extracted shape, so no golden moved at all.

  ⚠️ **Word-fractions are measured and DECLINED**, which is the other half of
  what this task asked for. A pass reading `N/M` as a share returned roughly
  one wrong answer per right one: `AND 00/100 DOLLARS` (the cents convention
  every promissory note writes), `5/2` and `14/1` (dates in slash form),
  `90/20` (a ratio that is not a share), against genuine `2/3` votes and `1/48`
  vesting fractions. Telling them apart needs the surrounding words, not the
  punctuation. The spelled share is covered anyway: "one-half percent" is
  number words and reads correctly. The reasoning sits in the module docstring
  so it is not rediscovered.) Extend `src/extract/amounts.ts` with percentage (`50%`, `fifty percent (50%)`) and word-fraction (`one-half (1/2)`, `a third`) forms as additive fields; regression test pins every existing amounts golden byte-identical for documents containing none.
- [x] 2. `codicil` playbook; verify `last-will-and-testament` and `revocable-living-trust` playbooks classify fixture instruments above threshold.
- [x] 3. (shipped 2026-07-17 as `src/dkb/estate-formalities.ts` — primary-source-verified seed) DKB state-formalities overlay nodes (per state: attestation expectation, notarization-alternative flag, holographic flag, e-will-regime flag, citations, `retrieved_at`) — seeded with verified data: PA 20 Pa. C.S. § 2502 (no witnesses for ordinary signed will); LA arts. 1576–1577 (notarial testament: 2 witnesses + notary, per-page signatures; olographic per art. 1575); CO C.R.S. § 15-11-502(1)(c)(II) and ND N.D.C.C. § 30.1-08-02 (notarization in lieu of witnesses, "reasonable time" phrasing); VT 14 V.S.A. § 5. Vermont 3→2 session-law citation RESOLVED against the official annotated statute: **2005, No. 106 (Adj. Sess.), § 1**. The ~27-holographic-state sweep and per-state e-will flags remain unseeded — the schema carries them as OPTIONAL fields omitted when unverified (honest N/A, never a guessed `false`), so future verified states are additive. **(2026-07-17 later session: the sweep COMPLETED — all 50 states + DC now carry primary-source-verified nodes with per-state holographic postures, added across twelve web-verified waves; e_will_regime is verified-true for MD/IN/NV/UT/DC and honestly omitted everywhere else, including two refuted enactment claims: the speculated Alabama e-wills act and Wyoming's ULC-tracked UEWA, both negative-checked against session laws.)**
- [x] 4. New `--state` and `--estate-checks` CLI flags + browser toggles (no `--state` flag exists today); EST-1xx recital rules gated to will/codicil playbooks AND dormant until asserted — pin an unasserted-run `result_hash` regression on a shipped will golden. Rules: attestation clause presence + recited witness count; witness signature blocks vs. recital count; self-proving affidavit (UPC § 2-504 pattern); notary block; testator signature block. Jurisdiction-neutral when asserted without a state; overlay-aware wording when `--state` is asserted (e.g., under PA, absence of witness blocks is an info note citing § 2502, not a warning).
- [x] 5. EST-2xx share arithmetic: residuary-clause detection, per-beneficiary share table, sum ≠ 100% warning citing UPC § 2-604(b) / § 2-101(a); handles mixed percent + fraction forms; never fires when shares are non-numeric ("equal shares").
- [x] 6. EST-3xx presence checks: executor/trustee named; successor fiduciary; guardian nomination when minors referenced; survivorship/simultaneous-death provision; no-alternate-beneficiary note.
- [x] 7. Scope-of-review statement per proposal, rendered on every report where the pack runs.
- [x] 8. Fixtures: attested will (clean), will with mismatched witness recital, PA signed will, LA notarial testament, 105%-residue will, minor-children-no-guardian will; determinism goldens; full gate green.

## Deviations

- **Jurisdiction-neutral core shipped first; per-state overlay landed
  2026-07-17.** The assertion-gated recital, share-arithmetic, and
  fiduciary/survivorship rules (EST-101..105, EST-201, EST-301..304) ship and
  run under `--estate-checks`. The `--state <xx>` flag (implies the pack) and
  the verified formalities overlay (`src/dkb/estate-formalities.ts`: PA
  zero-witness, LA notarial testament, CO/ND notarization alternative, VT with
  the resolved 2005, No. 106 (Adj. Sess.) citation) landed after each seed
  statute was verified against its primary source. Overlay-aware wording swaps
  EST-101/103/105 only under `--state` with a seeded state; `--estate-checks`
  without a state appends the exact neutral rule constants, so pre-overlay
  asserted runs keep their hash (pinned by test). Unseeded states run neutral
  rules (honest N/A) and still stamp `asserted_state` into the hashed run.
- **First exercise of the assertion-gate path.** The EST rules declare
  `assertion_gate: "estate-checks"` (now registered in
  `REGISTERED_ASSERTION_GATES`), and `activateEstateChecks` adds them to the
  rule set only when `--estate-checks` is asserted AND the playbook is a
  will/trust/codicil — so existing will/trust runs are byte-identical (verified:
  a will with no flag is unchanged; all v4 goldens pass).
- **Share arithmetic parsed in-rule, `amounts.ts` untouched.** EST-201 extracts
  percentages and word/numeric fractions directly from the residuary clause
  text, so the hashed `amounts.ts` path (which feeds every document) is not
  modified — the safest way to keep every existing amounts golden stable. The
  `amounts.ts` percent/fraction extension is deferred as unnecessary for this
  slice.
- **EST-105 is presence-only; the count comparison landed as EST-106**
  (2026-07-17): the will's own recited witness count ("two (2) competent
  witnesses") vs. detected witness signature blocks, firing only when at least
  one block exists (the zero-block case stays EST-105's finding). Internal
  consistency, deliberately statute-independent — no overlay variants needed.
- **The statute-aware count landed as EST-107** (2026-07-17, once the
  overlay's verified `witnesses_expected` existed to compare against): built
  only in `estateCheckRulesForOverlay` for seeded states expecting witnesses,
  so the neutral path and PA keep their exact rule lists. Fires when ≥1 block
  is present but fewer than the statute expects; silent when the will's own
  recital overstates the blocks (EST-106's finding). Under the CO/ND
  notarization alternative (v1.1.0): silent when a notarial acknowledgment is
  detected — the alternative satisfies the statute — and a both-paths-missing
  warning otherwise.
