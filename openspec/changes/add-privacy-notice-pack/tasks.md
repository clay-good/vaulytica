# Tasks

- [x] 1. (CCPA + GDPR 13/14 at launch; co/va/tx/or landed 2026-07-17 — statutory lists verified against the primary source or a faithful mirror; the 4 CCR 904-3 Rule 6.03 items remain deferred pending the adopted regulation text) Regime data: per-regime enumerated content items with citation + URL + `retrieved_at` — `ccpa` (Civ. Code § 1798.130(a)(5)(A)–(C) incl. the § 1798.106 correction right; 11 CCR § 7011(e) items incl. sensitive-PI, opt-out link, last-updated date; note the 2026-01-01 amendment package: mobile-app link item included, ADMT pre-use notice explicitly out of scope), `gdpr-13`, `gdpr-14` (Art. 14 adds categories-of-data and source items), `co` (C.R.S. § 6-1-1308(1)(a); 4 CCR 904-3 Rule 6.03), `va` (§ 59.1-578(C)), `tx` (§ 541.102, including the exact (b)–(c) statutory notice texts), `or` (ORS 646A.578(4), incl. the third-party-detail item).
- [x] 2. Playbooks `privacy-notice-us` and `privacy-notice-gdpr` + classifier features; fixture notices classify above threshold; a DPA fixture does not match the notice playbooks.
- [x] 3. PNOT presence rules generated from the regime data via `_regulated-rule.ts` (one rule per item, `applies_to_playbooks` = notice playbooks, active only when the item's regime is asserted); id scheme PNOT-<regime>-###.
- [x] 4. (landed 2026-07-17) Texas exact-wording rules: whitespace-normalized quote match of the § 541.102(b)–(c) mandated texts; finding distinguishes "absent" from "present but altered" (quoting the diff region). *(PNOT-TX-007/008: verbatim match is case-sensitive and whitespace-normalized; a near-variant paragraph → "present but altered" quoting it; a sale indication with no notice → "missing"; a document that never suggests such a sale is silent (§3 honesty — the statute mandates the text only for a controller that sells that data). Mandated texts verified against Tex. Bus. & Com. Code § 541.102 via texas.public.law (official capitol site is script-rendered); verified end-to-end through the real CLI: a re-cased notice fires "present but altered", the exact text is silent.)*
- [x] 5. `--regime` flag (comma-separated) + tab multi-select; asserted regimes stamped into the hashed run; dormant with none asserted.
- [x] 6. Regime coverage table (found / not detected per item, per regime) in tab + DOCX/JSON/markdown exports; scope-of-review block (presence of content, not adequacy or actual practices; never a compliance conclusion).
- [x] 7. Fixtures: a strong CCPA+GDPR notice, a notice missing the correction right and the "none" statements, a Texas notice with altered mandatory wording; determinism goldens; full gate green.

## Deviations

- **Launched with CCPA/CPRA + GDPR Articles 13/14; state analogs landed
  2026-07-17.** Launch shipped 36 PNOT rules (12 CCPA + 12 GDPR-13 + 12
  GDPR-14). The follow-up added 27 more: CO 5 (C.R.S. § 6-1-1308(1)(a)(I)–(V)),
  VA 5 (§ 59.1-578(C)(1)–(5)), TX 6 (§ 541.102(a)(1)–(6)) + the 2 exact-wording
  rules (§ 541.102(b)–(c)), OR 9 (ORS 646A.578(4)(a)–(i), incl. the (4)(e)
  third-party-detail item) — each item verified against the primary source or a
  faithful mirror on the stamped retrieval date. Still deferred: the Colorado
  CPA *regulation* items (4 CCR 904-3 Rule 6.03) pending the adopted regulation
  text, and the VA/CO/TX sale/targeted-advertising opt-out subsections beyond
  each task's cited list.
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
