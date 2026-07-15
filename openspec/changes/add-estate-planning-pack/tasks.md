# Tasks

- [ ] 1. (DEFERRED — share arithmetic done in-rule to avoid the hashed amounts path) Extend `src/extract/amounts.ts` with percentage (`50%`, `fifty percent (50%)`) and word-fraction (`one-half (1/2)`, `a third`) forms as additive fields; regression test pins every existing amounts golden byte-identical for documents containing none.
- [x] 2. `codicil` playbook; verify `last-will-and-testament` and `revocable-living-trust` playbooks classify fixture instruments above threshold.
- [ ] 3. (DEFERRED — needs verified per-state statutory data) DKB state-formalities overlay nodes (per state: attestation expectation, notarization-alternative flag, holographic flag, e-will-regime flag, citations, `retrieved_at`) — seed with verified data: PA 20 Pa. C.S. § 2502 (no witnesses for ordinary signed will); LA arts. 1576–1577 (notarial testament: 2 witnesses + notary, per-page signatures); CO C.R.S. § 15-11-502(1)(c)(II) and ND N.D.C.C. § 30.1-08-02 (notarization in lieu of witnesses); UPC § 2-502(a) "reasonable time" phrasing for UPC states; ~27 holographic states; e-will flag from UEWA adoptions + non-uniform regimes (NY act, Dec. 2025). Resolve the Vermont 3→2 session-law citation against the official annotated statute before pinning (sources conflict between the 2005 act and 2005, No. 106 (Adj. Sess.)).
- [x] 4. New `--state` and `--estate-checks` CLI flags + browser toggles (no `--state` flag exists today); EST-1xx recital rules gated to will/codicil playbooks AND dormant until asserted — pin an unasserted-run `result_hash` regression on a shipped will golden. Rules: attestation clause presence + recited witness count; witness signature blocks vs. recital count; self-proving affidavit (UPC § 2-504 pattern); notary block; testator signature block. Jurisdiction-neutral when asserted without a state; overlay-aware wording when `--state` is asserted (e.g., under PA, absence of witness blocks is an info note citing § 2502, not a warning).
- [x] 5. EST-2xx share arithmetic: residuary-clause detection, per-beneficiary share table, sum ≠ 100% warning citing UPC § 2-604(b) / § 2-101(a); handles mixed percent + fraction forms; never fires when shares are non-numeric ("equal shares").
- [x] 6. EST-3xx presence checks: executor/trustee named; successor fiduciary; guardian nomination when minors referenced; survivorship/simultaneous-death provision; no-alternate-beneficiary note.
- [x] 7. Scope-of-review statement per proposal, rendered on every report where the pack runs.
- [x] 8. Fixtures: attested will (clean), will with mismatched witness recital, PA signed will, LA notarial testament, 105%-residue will, minor-children-no-guardian will; determinism goldens; full gate green.

## Deviations

- **Jurisdiction-neutral core shipped; per-state overlay DEFERRED.** The
  assertion-gated recital, share-arithmetic, and fiduciary/survivorship rules
  (EST-101..105, EST-201, EST-301..304) ship and run under `--estate-checks`.
  The `--state` flag and the per-state formalities overlay (PA zero-witness, LA
  notarial testament, CO/ND notarization alternative, holographic/e-will flags)
  are DEFERRED to a follow-up: the proposal itself flags this data as
  malpractice-bait if wrong and names an unresolved Vermont citation conflict to
  verify against the official annotated statute — it must not ship without
  primary-source verification. The rules are worded jurisdiction-neutrally
  today; overlay-aware wording lands with the verified data.
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
- **EST-105 is presence-only in v1** (witness-block present/absent), not a
  witness-count-vs-recital comparison — noted for a future refinement.
