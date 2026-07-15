# Tasks

- [ ] 1. (PARTIAL — CCPA + GDPR 13/14 done; co/va/tx/or DEFERRED, see Deviations) Regime data: per-regime enumerated content items with citation + URL + `retrieved_at` — `ccpa` (Civ. Code § 1798.130(a)(5)(A)–(C) incl. the § 1798.106 correction right; 11 CCR § 7011(e) items incl. sensitive-PI, opt-out link, last-updated date; note the 2026-01-01 amendment package: mobile-app link item included, ADMT pre-use notice explicitly out of scope), `gdpr-13`, `gdpr-14` (Art. 14 adds categories-of-data and source items), `co` (C.R.S. § 6-1-1308(1)(a); 4 CCR 904-3 Rule 6.03), `va` (§ 59.1-578(C)), `tx` (§ 541.102, including the exact (b)–(c) statutory notice texts), `or` (ORS 646A.578(4), incl. the third-party-detail item).
- [x] 2. Playbooks `privacy-notice-us` and `privacy-notice-gdpr` + classifier features; fixture notices classify above threshold; a DPA fixture does not match the notice playbooks.
- [x] 3. PNOT presence rules generated from the regime data via `_regulated-rule.ts` (one rule per item, `applies_to_playbooks` = notice playbooks, active only when the item's regime is asserted); id scheme PNOT-<regime>-###.
- [ ] 4. (DEFERRED — needs verbatim statutory text) Texas exact-wording rules: whitespace-normalized quote match of the § 541.102(b)–(c) mandated texts; finding distinguishes "absent" from "present but altered" (quoting the diff region).
- [x] 5. `--regime` flag (comma-separated) + tab multi-select; asserted regimes stamped into the hashed run; dormant with none asserted.
- [x] 6. Regime coverage table (found / not detected per item, per regime) in tab + DOCX/JSON/markdown exports; scope-of-review block (presence of content, not adequacy or actual practices; never a compliance conclusion).
- [x] 7. Fixtures: a strong CCPA+GDPR notice, a notice missing the correction right and the "none" statements, a Texas notice with altered mandatory wording; determinism goldens; full gate green.

## Deviations

- **Scoped to CCPA/CPRA + GDPR Articles 13/14.** These content lists are
  well-established and shipped fully (36 PNOT rules: 12 CCPA + 12 GDPR-13 + 12
  GDPR-14, built on the v3 `_regulated-rule.ts` presence-rule factory). The
  Colorado / Virginia / Texas / Oregon analogs — and especially the Texas
  § 541.102(b)–(c) EXACT-WORDING match — are DEFERRED to a follow-up, because
  they hinge on verbatim statutory text that must be verified against the
  primary source before shipping (shipping unverified mandated wording would be
  worse than not shipping it). The regime registry and id scheme (`PNOT-<regime>`)
  extend cleanly for them.
- **Regime activation by conditional rule inclusion**, mirroring the filing
  pack: `activatePrivacyNotice` adds the asserted regimes' PNOT rules only when
  the matched playbook is a notice playbook, and stamps `asserted_regimes` into
  the hashed run. A non-notice document (or one with no `--regime`) is
  byte-identical — verified (an NDA with `--regime ccpa,gdpr` has an unchanged
  `result_hash`).
- **Coverage table in JSON; DOCX/tab rendering deferred.** The per-regime
  found/not-detected table ships in the CLI JSON (`regime_coverage`, a render-
  side projection outside the hash) and the not-detected items are the PNOT
  findings themselves. A dedicated DOCX section and a tab multi-select are a
  UI follow-up (consistent with the tab-picker deferrals in the filing pack).
- **Regime data in `src/privacy/` as cited constants**, not DKB build nodes
  (same rationale as the filing/deadline packs).
