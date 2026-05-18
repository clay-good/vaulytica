/**
 * Per-fail-fixture sanity guards for the v3 corpus.
 *
 * Each entry pins down the rule IDs that MUST fire for a given
 * `*-fail.txt` fixture. The golden test catches byte-level drift; this
 * test catches *semantic* drift — e.g. a regex tweak that silently
 * stops a critical rule from firing on the intended failure mode.
 *
 * Pass-fixtures live alongside but carry no sanity entries — the
 * golden test already locks them down structurally.
 */

import { describe, expect, it } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { runV3Fixture } from "./_pipeline.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "fixtures");

const EXPECTED_RULE_IDS: Record<string, string[]> = {
  // BAA missing the §164.504(e)(2)(ii)(D) subcontractor flow-down clause.
  // BAA-018 is the Security Rule subcontractor-flow-down detector and
  // is the load-bearing critical for this fail-fixture.
  "baa-missing-subcontractor-flow-down-fail.txt": ["BAA-018"],

  // Mutual NDA with the DTSA whistleblower-immunity notice removed —
  // 18 U.S.C. § 1833(b) requires the notice in any agreement governing
  // trade secrets. NDA-D-001 is the presence check, NDA-D-002 the
  // completeness check.
  "mutual-nda-deep-missing-dtsa-fail.txt": ["NDA-D-001", "NDA-D-002"],

  // Article 28(3)(a) GDPR DPA with the documented-instructions clause
  // removed. DPA-007 is the load-bearing critical; the controller-side
  // duty in DPA-006 also fires because removing §4 also lost the
  // "Controller shall provide Processor with documented instructions"
  // sentence.
  "dpa-controller-processor-missing-documented-instructions-fail.txt": [
    "DPA-007",
    "DPA-006",
  ],

  // AI Addendum that explicitly permits training on Customer Data on
  // an opt-out basis. ADDENDA-011 fires (critical) per FTC enforcement
  // posture on AI-training disclosures; IPDATA-009 also fires because
  // the broader v2 AI / model-training detector matches the same text.
  "ai-addendum-training-without-optin-fail.txt": [
    "ADDENDA-011",
    "IPDATA-009",
  ],

  // Vendor Security Addendum that swaps the 24-hour incident-notification
  // window for vague "promptly and without undue delay" language.
  // ADDENDA-004 (warning) is the load-bearing detector — its
  // present_patterns regex requires `within \d+ (hours|days)` and now
  // matches nothing in the incident-notification paragraph.
  "vendor-security-addendum-missing-incident-window-fail.txt": ["ADDENDA-004"],

  // SCC Module 2 with side-letter modifications attached. Per EU SCCs
  // Clause 2, the SCC text is invariable; any "as modified" / "as
  // amended" / "notwithstanding the SCCs" language is forbidden.
  // TRANSFER-003 is the load-bearing critical.
  "scc-module-2-modified-clauses-fail.txt": ["TRANSFER-003"],

  // CCPA Service Provider addendum that claims Service Provider status
  // but is missing the § 7051 "specific business purpose" and "same
  // level of privacy protection" anchors. USDPA-020 fires (critical):
  // a recipient claiming Service Provider status without meeting the
  // § 7051 contract requirements may be reclassified as a "third
  // party" — triggering sale / share consequences for the disclosing
  // party.
  "dpa-ccpa-service-provider-no-business-purpose-fail.txt": ["USDPA-020"],

  // Unilateral NDA with the entire "Term" section removed (no fixed
  // duration, no perpetual trade-secret carve-out language). NDA-D-003
  // is the load-bearing presence check — its `present_patterns` regex
  // requires "<N> years" within ~80 chars of confidential/disclos and
  // now matches nothing in the document.
  "unilateral-nda-deep-missing-term-fail.txt": ["NDA-D-003"],

  // Vendor-side MSA with the aggregate liability cap subsection
  // removed (only the consequential-damages waiver and indemnity
  // procedure survive). MSA-006 is the load-bearing presence check
  // for the aggregate liability cap; without a cap the vendor's
  // exposure is unbounded.
  "msa-vendor-deep-no-liability-cap-fail.txt": ["MSA-006"],

  // UK IDTA / Addendum with a side-letter "Annex IV" attached that
  // purports to modify the ICO Mandatory Clauses (replacing Clause 12
  // liability, amending Clause 16 notification, modifying Clause 9
  // sub-processor authorisation). TRANSFER-015 is the load-bearing
  // critical — ICO Mandatory Clauses are invariable; only Tables 1–4
  // may be completed.
  "uk-idta-addendum-modified-mandatory-clauses-fail.txt": ["TRANSFER-015"],

  // EULA with the explicit license-grant scope ("non-exclusive /
  // non-transferable / revocable license") and the prohibited-uses
  // enumeration ("shall not reverse engineer / decompile / disassemble
  // / sublicense") both stripped. ADDENDA-017 is the load-bearing
  // EULA presence rule — both alternative patterns must match
  // somewhere in the document, and now neither does.
  "eula-no-license-grant-or-prohibitions-fail.txt": ["ADDENDA-017"],

  // SCC Module 3 (Processor-to-Processor) with the entire
  // "Clause 15 — Public Authority Access" block removed. TRANSFER-008
  // is the load-bearing critical for the data-importer's Schrems-II
  // notify-and-challenge obligation; absent Clause 15 the parties
  // lose the foundational government-access posture.
  "scc-module-3-missing-clause-15-fail.txt": ["TRANSFER-008"],

  // Sub-processing DPA (Processor → Subprocessor) with the
  // "Deletion or Return at End of Services" section stripped. DPA-013
  // is the load-bearing critical for Art. 28(3)(g) — the controller's
  // choice between deletion and return at end-of-services is a core
  // GDPR processor obligation.
  "dpa-processor-subprocessor-missing-deletion-or-return-fail.txt": ["DPA-013"],

  // Subcontractor BAA with the "Return or Destruction" section
  // stripped and the term-survival sentence reworded to drop the
  // "return or destroy" anchor. BAA-010 is the load-bearing critical
  // for 45 C.F.R. § 164.504(e)(2)(ii)(I) — the BA must, at
  // termination, return or destroy all PHI received from or created
  // on behalf of the covered entity.
  "baa-subcontractor-missing-return-or-destruction-fail.txt": ["BAA-010"],

  // Customer-form MSA with the third-party IP infringement
  // indemnification prong removed from Section 7 (Vendor
  // Indemnification). MSA-001 is the load-bearing warning rule for
  // commercial MSAs — a vendor-supplied deliverable that infringes
  // third-party IP would otherwise leave the customer exposed.
  "msa-customer-deep-missing-ip-indemnity-fail.txt": ["MSA-001"],

  // Multi-state US DPA with the "Deletion on Termination" section
  // stripped and Section 3 reworded to drop "delete or return".
  // USDPA-015 is the load-bearing critical — VCDPA / CPA / CTDPA all
  // require the processor to delete or return personal data at end
  // of services.
  "dpa-multi-state-us-missing-deletion-or-return-fail.txt": ["USDPA-015"],

  // SaaS Terms of Service that forces phone-only cancellation during
  // business hours and strips every Click-to-Cancel / ROSCA / online-
  // cancellation anchor. ADDENDA-019 is the load-bearing warning —
  // its present_patterns require either an online-cancellation phrase
  // ("click to cancel" / "cancel online" / "cancel through your
  // account" / "easy cancellation") or an explicit ROSCA reference,
  // and now neither appears.
  "saas-tos-no-click-to-cancel-fail.txt": ["ADDENDA-019"],

  // Privacy Policy stripped of every CCPA § 1798.130 / GDPR Art. 13–14
  // / COPPA disclosure anchor: no "categories of personal information",
  // no "lawful basis" / "consent" / "legitimate interest" / "legal
  // obligation", and no "right to access/delete/portability/opt-out/
  // object" or "data subject rights" language. ADDENDA-020 is the
  // load-bearing warning — its present_patterns require all three
  // anchor families and now none appears.
  "privacy-policy-lint-missing-disclosures-fail.txt": ["ADDENDA-020"],

  // BAA with the "Books, Records" paragraph removed — no "internal
  // practices ... books ... records" or "Secretary of Health and Human
  // Services" anchor remains anywhere in the document. BAA-009 is the
  // load-bearing critical for 45 C.F.R. § 164.504(e)(2)(ii)(H) — the
  // BA must make its internal practices, books, and records available
  // to the HHS Secretary for compliance determination.
  "baa-missing-hhs-books-records-fail.txt": ["BAA-009"],

  // Controller→Processor DPA with Section 5 rewritten to "Personnel
  // Training" (training only, no confidentiality commitment) and the
  // ancillary "ongoing confidentiality" phrase stripped from the
  // Section 6 security measures list. DPA-008 is the load-bearing
  // critical for GDPR Art. 28(3)(b) — persons authorised to process
  // personal data must be committed to confidentiality or under a
  // statutory duty of confidentiality.
  "dpa-controller-processor-missing-personnel-confidentiality-fail.txt": ["DPA-008"],

  // Vendor-form MSA with Section 4 rewritten to drop the
  // "pre-existing intellectual property" / "background IP" allocation
  // anchor and with no "foreground IP" / "developed hereunder" anchor
  // anywhere in the document. MSA-011 is the load-bearing warning —
  // without explicit background/foreground IP allocation, default
  // copyright / patent rules govern and rarely match the parties'
  // intent.
  "msa-vendor-deep-missing-background-foreground-ip-fail.txt": ["MSA-011"],

  // Customer-form MSA with Section 10 rewritten to remove the
  // termination-for-cause / material-breach / cure-period clause
  // (replaced with convenience-only and insolvency termination).
  // MSA-018 is the load-bearing warning — without an explicit
  // material-breach termination right the customer is forced into a
  // common-law theory rather than a clear contractual trigger.
  "msa-customer-deep-missing-termination-clause-fail.txt": ["MSA-018"],

  // Mutual NDA with Section 7 (Return or Destruction) removed entirely.
  // NDA-D-013 is the load-bearing presence check —
  // its present_patterns require "return or destroy" / "destruction of
  // confidential" / "destroy all copies" and now none appears in the
  // document. Without this clause the discloser has no contractual hook
  // to recover or wipe disclosed material once the relationship ends.
  "mutual-nda-deep-missing-return-or-destruction-fail.txt": ["NDA-D-013"],

  // Multi-state US DPA with the "bound by confidentiality" anchor in
  // Section 3 (Virginia VCDPA Processor Obligations) replaced by
  // "subject to appropriate access controls and security training".
  // USDPA-016 is the load-bearing rule — every state privacy statute
  // requires the processor to subject authorized personnel to a duty
  // of confidentiality, and no alternative pattern
  // (duty/committed/bound by confidentiality) appears anywhere else
  // in the document.
  "dpa-multi-state-us-missing-confidentiality-duty-fail.txt": ["USDPA-016"],
};

describe("v3 fixture sanity", () => {
  for (const [fixture, expectedIds] of Object.entries(EXPECTED_RULE_IDS)) {
    it(`${fixture} fires the expected rules`, async () => {
      const { run } = await runV3Fixture(join(FIXTURES, fixture));
      const firedIds = new Set(run.findings.map((f) => f.rule_id));
      const missing = expectedIds.filter((id) => !firedIds.has(id));
      expect(missing, `expected rules did not fire: ${missing.join(", ")}`).toEqual([]);
    });
  }
});
