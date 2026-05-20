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

  // BAA with the termination section rewritten to allow only
  // convenience-termination and insolvency-termination, stripping every
  // "material breach", "terminate...breach", and "breach...termination"
  // anchor (the Reporting section is also reworded to avoid "Breaches").
  // BAA-011 is the load-bearing critical for 45 C.F.R. § 164.504(e)(2)(iii)
  // — the covered entity must have the right to terminate for material
  // breach of HIPAA obligations.
  "baa-missing-termination-for-breach-fail.txt": ["BAA-011"],

  // Mutual NDA with Section 5 rewritten to impose a flat three-year term
  // on all confidentiality obligations with no perpetual carve-out for
  // trade secrets. NDA-D-004 is the load-bearing warning — its
  // present_patterns require "trade secret" within ~120 chars of
  // "as long as / so long as / in perpetuity / perpetual / qualifies as"
  // and now no such pairing appears. Without the carve-out the discloser
  // loses statutory UTSA / DTSA protection once the three-year term lapses.
  "mutual-nda-deep-missing-perpetual-trade-secret-fail.txt": ["NDA-D-004"],

  // Vendor-form MSA with the Section 8(b) carve-outs block removed from
  // the Limitation of Liability — the aggregate cap now absorbs
  // confidentiality-breach, indemnification, gross-negligence, and
  // wilful-misconduct claims with no exception. MSA-007 is the
  // load-bearing warning — its present_patterns require
  // "cap / limitation…shall not apply / excluded / carved out …
  // fraud / wilful misconduct / IP indemnity / confidentiality /
  // data protection" and now none of these pairings appears.
  "msa-vendor-deep-missing-cap-carveouts-fail.txt": ["MSA-007"],

  // BAA with the Reporting section rewritten to reference only "Security
  // Incidents" and "impermissible access to PHI" — every anchor for
  // "breach of unsecured PHI", "breach notification", and "164.410" is
  // stripped. BAA-019 is the load-bearing critical for 45 C.F.R. § 164.410
  // — the BA must notify the covered entity of a breach of unsecured PHI
  // without unreasonable delay and in no case later than 60 calendar days
  // after discovery; absent the statutory anchor the notification obligation
  // is legally ambiguous and may not satisfy the regulatory standard.
  "baa-missing-breach-notification-fail.txt": ["BAA-019"],

  // Mutual NDA with the Section 1 "Confidential Information" definition
  // replaced by unformatted references to "non-public information" — the
  // capitalized defined-term definition block ("Confidential Information"
  // means …) is entirely absent. NDA-D-005 is the load-bearing rule —
  // its present_patterns require a statement of the form
  // "Confidential Information means / shall mean / is defined" and now
  // no such pattern appears anywhere in the document. Without a definition,
  // the scope of the confidentiality obligation is ambiguous and may be
  // construed narrowly against the disclosing party.
  "mutual-nda-deep-missing-ci-definition-fail.txt": ["NDA-D-005"],

  // Customer-form MSA with the "Data Portability and Return on Termination"
  // section (Section 11) removed entirely — no clause requires Vendor to
  // return a machine-readable export of Customer Data or delete Vendor's
  // copies on termination. MSA-021 is the load-bearing warning — its
  // present_patterns require "return … customer data", "data portability",
  // or "export … machine-readable" and now none of these anchors appears.
  // Without an explicit return obligation the customer can be locked out of
  // its own data after the relationship ends.
  "msa-customer-deep-missing-data-return-fail.txt": ["MSA-021"],

  // BAA with the "Access, Amendment, Accounting" section rewritten to
  // reference only 45 C.F.R. § 164.524 (individual right of access) and
  // § 164.526 (right to amendment) — every "accounting of disclosures"
  // and "164.528" anchor is stripped. BAA-008 is the load-bearing critical
  // for 45 C.F.R. § 164.504(e)(2)(ii)(G) — the BA must maintain and make
  // available the information required for an accounting of disclosures
  // under § 164.528; without this hook the covered entity cannot meet its
  // obligation to provide individuals with a history of disclosures.
  "baa-missing-accounting-of-disclosures-fail.txt": ["BAA-008"],

  // Vendor-form MSA with Section 6 (Warranty) rewritten to a flat
  // "as-is / as-available" disclaimer — every anchor for "workmanlike",
  // "professional manner", "conforms to documentation / specifications",
  // and "no malicious code / virus / trojan" is removed. MSA-013 is the
  // load-bearing warning — its present_patterns require at least one of
  // the three service-warranty families to appear and now none does.
  // Without these warranties the customer has no contractual basis to
  // demand professional performance, spec conformance, or malware-free
  // deliverables.
  "msa-vendor-deep-missing-service-warranties-fail.txt": ["MSA-013"],

  // Mutual NDA with the "publicly available / public domain" carve-out
  // removed from Section 2 (Carveouts) — the standard four-exclusion list
  // (public domain, prior knowledge, third-party-lawfully, independently
  // developed) now lacks the "publicly available" prong. NDA-D-006 is the
  // load-bearing warning — its present_patterns require
  // "(publicly|generally) (available|known)" or "(public domain|in the
  // public)" and now neither appears anywhere in the document. Without this
  // exclusion the Receiving Party could technically breach the NDA by
  // referencing information that is freely available to the world.
  "mutual-nda-deep-missing-public-domain-exclusion-fail.txt": ["NDA-D-006"],

  // Controller→Processor DPA with every "demonstrate compliance" /
  // "allow for and contribute to audits" anchor stripped — the entire
  // Section 11 is replaced with an internal-records-only clause that
  // explicitly restricts Controller access. DPA-014 is the load-bearing
  // critical for GDPR Art. 28(3)(h) — the processor must make available
  // all information necessary to demonstrate compliance with Article 28
  // and must allow for and contribute to audits, including inspections,
  // conducted by the controller or its mandated auditor.
  "dpa-controller-processor-missing-compliance-demonstration-fail.txt": [
    "DPA-014",
  ],

  // Multi-state US DPA with Section 9 (Annual Security Program) replacing
  // the audit-cooperation clause — no "allow and cooperate with reasonable
  // assessments" or "assessor" anchor remains anywhere in the document.
  // USDPA-017 is the load-bearing critical — VCDPA (Va. Code § 59.1-579)
  // and several state statutes require the processor to allow and cooperate
  // with reasonable assessments by the controller or the controller's
  // designated assessor; without this clause the controller has no
  // contractual mechanism to verify processor compliance.
  "dpa-multi-state-us-missing-audit-cooperation-fail.txt": ["USDPA-017"],

  // Vendor-form MSA with no "comply with applicable laws" or
  // "non-infringement" warranty clause — Section 6 (Limited Warranty)
  // covers only workmanlike performance and malware-free deliverables
  // while Section 7 addresses IP-infringement indemnity (not a warranty).
  // MSA-014 is the load-bearing warning — its present_patterns require
  // either a comply/compliance-with-laws anchor or a non-infringement
  // warranty anchor, and now neither appears in the warranty section;
  // without this clause the customer has no contractual representation
  // that the vendor's services comply with applicable law.
  "msa-vendor-deep-missing-compliance-noninfringement-warranty-fail.txt": [
    "MSA-014",
  ],

  // Mutual NDA with the "already known / prior to disclosure" exclusion
  // removed from Section 2 (Carveouts) — the standard four-exclusion list
  // now lacks the "previously known to the recipient" prong entirely.
  // The last sentence of Section 2 is rewritten to affirmatively rope in
  // information "regardless of how or when" the Receiving Party's employees
  // came to know of it, closing off any implied prior-knowledge defence.
  // NDA-D-007 is the load-bearing rule — its present_patterns require
  // "already known", "prior to disclos", or "previously known" and now no
  // such pattern appears anywhere in the document. Without this exclusion
  // the Receiving Party risks breaching the NDA by using information they
  // possessed long before the relationship began.
  "mutual-nda-deep-missing-prior-knowledge-exclusion-fail.txt": ["NDA-D-007"],

  // Vendor-form MSA with no SLA, service-level agreement, uptime commitment,
  // or availability reference anywhere in the document — the Agreement covers
  // warranty, indemnity, and limitation of liability but is silent on any
  // performance or availability standard for the hosted service. MSA-016 is
  // the load-bearing warning — its present_patterns require
  // "service level agreement", "SLA", "uptime", or "availability commitment"
  // and now none appears; without an SLA reference, availability promises
  // are unenforceable and the customer has no contractual remedy for downtime.
  "msa-vendor-deep-missing-sla-fail.txt": ["MSA-016"],

  // Controller→Processor DPA with Section 6 (Security Measures) rewritten
  // to a vague general-security-commitment paragraph — every reference to
  // "Article 32", "technical and organisational measures", "encryption",
  // "pseudonymisation", "confidentiality, integrity, availability and
  // resilience", "restore availability", and "regularly testing" is stripped.
  // DPA-009 is the load-bearing critical for GDPR Art. 28(3)(c) — the
  // processor must take all measures required pursuant to Article 32;
  // absent the statutory anchor and the enumerated TOMs, the controller
  // cannot verify that the processor has implemented the required security
  // of processing framework.
  "dpa-controller-processor-missing-art32-security-measures-fail.txt": [
    "DPA-009",
  ],

  // Mutual NDA with the "third party lawfully obtained" carve-out removed
  // from Section 2 (Carveouts) — the standard four-exclusion list now
  // lacks the prong for information lawfully received from an unobligated
  // third party. The last sentence of Section 2 actively reincorporates
  // any information accessible from any "external party not operating
  // under a separate written NDA", closing the gap for the usual
  // third-party-channel safe harbour. NDA-D-008 is the load-bearing rule
  // — its present_patterns require "third party" within ~80 chars of
  // "without (breach|restriction)|lawfully" or "received/obtained from a
  // third party" and now no such pairing appears. Without this exclusion
  // the Receiving Party risks breaching the NDA for using identical
  // information it legitimately obtained from an independent source.
  "mutual-nda-deep-missing-third-party-exclusion-fail.txt": ["NDA-D-008"],

  // Vendor-form MSA with the force-majeure clause rewritten to a vendor-
  // only excused-performance paragraph (titled "Excused Performance") that
  // explicitly states Customer's payment obligations are not excused —
  // there is no "neither party" or "either party" bilateral framing
  // anywhere in the force-majeure section. MSA-022 is the load-bearing
  // presence check — its present_patterns require
  // "(neither party|either party).{0,80}force majeure" or
  // "force majeure.{0,160}(neither|both|each party)" and now neither
  // appears; a one-sided force-majeure clause is commercially abnormal
  // and leaves the customer without relief for its own performance
  // obligations in the event of a force-majeure event affecting it.
  "msa-vendor-deep-missing-force-majeure-fail.txt": ["MSA-022"],

  // BAA with the Term and Termination section rewritten to allow only
  // cure-based and insolvency termination — every "cure is not feasible",
  // "infeasible to cure", and "fail.*cure" anchor is absent. BAA-012 is
  // the load-bearing warning for 45 C.F.R. § 164.504(e)(2)(iii) — HHS
  // expects BAAs to permit termination when cure of a material breach is
  // not feasible (e.g., a systemic HIPAA violation that cannot be
  // remediated within a cure window); without this provision the covered
  // entity may be stuck with a non-curable breach situation and no clear
  // contractual exit.
  "baa-missing-cure-infeasible-termination-fail.txt": ["BAA-012"],

  // Mutual NDA with the "independently developed" carve-out removed from
  // Section 2 (Carveouts) — the standard exclusion list now only has
  // three prongs (publicly available, third-party-lawfully, compelled
  // disclosure); the "(b) independently developed" prong is entirely
  // gone. The last sentence of Section 2 affirmatively ropes in
  // information generated by the Receiving Party's own personnel.
  // NDA-D-009 is the load-bearing rule — its present_patterns require
  // "independently (developed|derived|created)" or
  // "without (use of|reference to) (the )?confidential" and now neither
  // appears anywhere in the document. Without this exclusion, ordinary
  // R&D by the Receiving Party's workforce could be captured as a
  // confidentiality breach merely because parallel work was conducted
  // while accessing the Disclosing Party's information.
  "mutual-nda-deep-missing-independent-development-exclusion-fail.txt": [
    "NDA-D-009",
  ],

  // BAA with the breach-notification clause rewritten to trigger from
  // "confirmation and written assessment that a reportable breach has
  // occurred" rather than from "discovery of the breach" — every anchor
  // for "discovery of the breach" and "breach.*discover" is stripped.
  // BAA-021 is the load-bearing warning for 45 C.F.R. § 164.410(a)(2)
  // — the statute defines the 60-day clock from "discovery", not from
  // a later assessment or confirmation event; shifting the trigger to
  // post-discovery confirmation may cause the covered entity to violate
  // the 60-day outer bound before the BA even starts the clock.
  "baa-missing-breach-discovery-trigger-fail.txt": ["BAA-021"],

  // Multi-state US DPA with Section 3 (Virginia VCDPA Processor
  // Obligations) rewritten to drop the "make available all information
  // necessary to demonstrate compliance" sentence — every
  // "demonstrate compliance" and "information necessary to demonstrate"
  // anchor is stripped, and Section 12 (Certification) is reworded to
  // use "attestation" and "adherence" language that avoids the patterns.
  // USDPA-019 is the load-bearing critical — Va. Code § 59.1-579 and
  // equivalent state statutes require the processor to make information
  // available demonstrating compliance; without this clause the
  // controller has no contractual basis to obtain the compliance
  // documentation required by the Applicable State Laws.
  "dpa-multi-state-us-missing-compliance-demonstration-fail.txt": [
    "USDPA-019",
  ],

  // BAA with the Reporting section rewritten to drop "without
  // unreasonable delay" from the breach-notification clause — the
  // 60-calendar-day outer bound from discovery is preserved, but
  // HIPAA's inner timing standard ("without unreasonable delay") is
  // absent. BAA-022 is the load-bearing warning for 45 C.F.R.
  // § 164.410(b) — the statute requires both "without unreasonable
  // delay AND in no case later than 60 calendar days"; omitting the
  // inner bound means a BA could lawfully notify on day 59 after
  // every breach, eliminating the practical urgency HIPAA intended.
  "baa-missing-unreasonable-delay-language-fail.txt": ["BAA-022"],

  // Multi-state US DPA with Section 7 (Sub-Processor Management)
  // rewritten to require only prior notification and vetting of
  // subprocessors — the "written contract" / "written agreement" /
  // "same obligations" anchor is stripped. USDPA-018 is the
  // load-bearing critical — Va. Code § 59.1-579 and equivalent state
  // statutes require the processor to engage subcontractors only
  // pursuant to a written contract imposing equivalent obligations;
  // without this clause the controller has no contractual guarantee
  // that downstream subprocessors are bound by the same data
  // protection requirements.
  "dpa-multi-state-us-missing-subcontractor-written-contract-fail.txt": [
    "USDPA-018",
  ],

  // Vendor-form MSA with the Section 7(c) Indemnification Procedure
  // block stripped — no "promptly notify", "control of the defense",
  // or "settlement…consent" anchor appears in the indemnification
  // section; the surviving text merely says the parties shall
  // "reasonably cooperate." MSA-002 is the load-bearing warning —
  // its present_patterns require at least one procedural mechanic
  // (notice, defense control, or settlement consent) and now none
  // appears; without these mechanics the indemnitor loses the ability
  // to control its own defense, raising moral-hazard and collusive-
  // settlement risks for whichever party bears the indemnity.
  "msa-vendor-deep-missing-indemnity-procedure-fail.txt": ["MSA-002"],

  // Mutual NDA with the return-or-destruction clause present but the
  // written certification / attestation requirement stripped — Section 7
  // says the Receiving Party shall "return or destroy" Confidential
  // Information but omits the "certify in writing" obligation. NDA-D-014
  // is the load-bearing warning — its present_patterns look for
  // certify/certification/attestation near destroy/return; without this
  // requirement the discloser has no contractual proof that destruction
  // actually occurred, leaving an unverifiable enforcement gap after
  // the relationship ends. NDA-D-013 (return-or-destroy presence) still
  // passes because the return-or-destroy language itself is intact.
  "mutual-nda-deep-missing-return-attestation-fail.txt": ["NDA-D-014"],

  // Mutual NDA with the injunctive-relief / irreparable-harm clause
  // removed — Section 9 is replaced by a generic "Remedies" clause
  // that merely preserves "all remedies at law or in equity" without
  // explicitly acknowledging irreparable harm or entitling either
  // party to injunctive relief. NDA-D-015 is the load-bearing rule —
  // its present_patterns require one of: "irreparable harm/injury",
  // "injunctive relief/remedy", or "equitable relief"; none appears in
  // the body, so the discloser must prove inadequate-remedy-at-law
  // from scratch in any emergency motion — the contractual shortcut is
  // absent.
  "mutual-nda-deep-missing-injunctive-relief-fail.txt": ["NDA-D-015"],

  // Mutual NDA with the no-license / no-ownership-transfer clause
  // omitted — the agreement says nothing about whether disclosure
  // grants any right, license, or interest in the Confidential
  // Information. NDA-D-021 is the load-bearing rule — its
  // present_patterns look for "no license" or "does not grant /
  // shall not be construed … license"; without this clause an
  // aggressive receiver could argue an implied license arose from
  // disclosure, giving the receiving party a litigation foothold the
  // discloser never intended to concede.
  "mutual-nda-deep-missing-no-license-clause-fail.txt": ["NDA-D-021"],

  // SCC Module 2 with the entire "Clause 8 — Data Protection
  // Safeguards" heading and numbering stripped — the obligations
  // survive in prose form but every "Clause 8" / "clause 8" anchor is
  // absent. TRANSFER-004 is the load-bearing presence check — its
  // present_patterns require `clause\s*8\b` anywhere in the document;
  // without the heading, automated compliance tooling and auditors
  // cannot locate the Art. 28 safeguard block, and the SCC's internal
  // cross-references to "Clause 8.9" (audit) are silently broken.
  "scc-module-2-missing-clause-8-fail.txt": ["TRANSFER-004"],

  // Controller→Processor DPA with Section 8 rewritten to an
  // "Individual Requests" cooperation paragraph — every "assist the
  // controller", "data subject rights", and "Chapter III" anchor is
  // stripped; the surviving text only references "individuals" and
  // "personal information." DPA-011 is the load-bearing rule for
  // GDPR Art. 28(3)(e) — the processor must assist the controller by
  // appropriate technical and organisational measures to fulfil its
  // obligation to respond to data-subject rights; absent the statutory
  // framing, the processor has no explicit GDPR-aligned obligation
  // covering access, erasure, portability, and objection requests.
  "dpa-controller-processor-missing-dsr-assistance-fail.txt": ["DPA-011"],

  // BAA with the Safeguards section rewritten to omit every "Security
  // Rule", "164.30X", and "administrative … physical … technical"
  // anchor — the surviving text references only "appropriate
  // safeguards" and "applicable HIPAA regulations." BAA-013 is the
  // load-bearing critical for 45 C.F.R. § 164.314(a)(2)(i) — that
  // regulation explicitly requires the BAA to mandate the BA's
  // compliance with the HIPAA Security Rule for ePHI; a generic
  // "appropriate safeguards" clause does not satisfy the regulatory
  // citation requirement and leaves the covered entity without a
  // clear contractual hook to enforce Security Rule compliance.
  "baa-missing-security-rule-compliance-fail.txt": ["BAA-013"],

  // SCC Module 2 with the entire "Clause 9 — Use of Sub-Processors"
  // heading and numbered provisions replaced by a generic "Downstream
  // Vendor Management" paragraph — every "clause 9" / "clause\s*9\b"
  // anchor is absent. TRANSFER-005 is the load-bearing presence check
  // — Clause 9 governs the prior-authorisation regime for
  // sub-processors and mandates a written contract imposing equivalent
  // obligations; absent the clause heading the SCC's internal cross-
  // references to Clause 9's authorisation mechanism are silently
  // broken and the data exporter loses the Art. 28(4) flow-down hook.
  "scc-module-2-missing-clause-9-fail.txt": ["TRANSFER-005"],

  // Vendor-form MSA with the indemnification section covering only
  // IP-infringement and Customer-violation claims — the gross
  // negligence, wilful misconduct, and data-protection prong is
  // entirely absent from Section 7 and from the carve-out list in
  // Section 8(b). MSA-004 is the load-bearing warning — its
  // present_patterns require an indemnification sentence that pairs
  // "indemnif" with "gross negligence", "wilful misconduct",
  // "data protection", "personal data", or "breach of DPA"; none of
  // those pairings appears in the document. Without this prong the
  // vendor's counterparty bears uncompensated exposure for the
  // highest-impact conduct categories.
  "msa-vendor-deep-missing-gross-negligence-indemnity-fail.txt": ["MSA-004"],

  // Controller→Processor DPA with Section 2 rewritten to enumerate
  // only the types of personal data processed ("names, email
  // addresses, IP addresses …") while omitting any identification of
  // the population of individuals affected — every "categories of
  // data subjects" / "data subjects category" anchor is stripped and
  // Annex I is retitled "Personal Data in Scope" without a subjects
  // enumeration. DPA-005 is the load-bearing rule for GDPR Art. 28(3)
  // introductory paragraph — the controller-processor contract must
  // set out the categories of data subjects; without this element
  // the scope of Art. 28 obligations is undefined and supervisory
  // authorities cannot readily assess whether the agreement covers
  // all affected individuals.
  "dpa-controller-processor-missing-data-subjects-fail.txt": ["DPA-005"],

  // BAA with the "Access, Amendment, Accounting" section rewritten as
  // "Access, Accounting" — every "amendment", "amend.*PHI", and
  // "164.526" anchor is stripped; the surviving sentence references
  // only 45 CFR § 164.524 (access) and § 164.528 (accounting). The
  // commercial substitute ("cooperate as commercially reasonable" on
  // update or correction requests) deliberately avoids the words
  // "amend" / "amendment" so neither alternation in BAA-007's
  // present_patterns matches. BAA-007 is the load-bearing rule for
  // 45 C.F.R. § 164.504(e)(2)(ii)(F) — the BAA must allow the covered
  // entity to satisfy individuals' right to amend PHI under § 164.526;
  // without this clause, an amendment request bottlenecks at the BA
  // with no contractual hook.
  "baa-missing-phi-amendment-fail.txt": ["BAA-007"],

  // Mutual NDA with Section 8 rewritten as "Dispute Resolution; Venue"
  // — every "governing law", "governed by the laws", and "laws of the
  // State of/country of" anchor is stripped; the surviving clause
  // designates a court (Wilmington) and waives forum non conveniens
  // but explicitly disclaims any choice-of-substantive-law selection,
  // deferring conflict-of-laws to the forum court. NDA-D-017 is the
  // load-bearing rule — its present_patterns require one of three
  // governing-law anchors and now none appears; without a chosen
  // governing law the parties' substantive expectations are exposed
  // to whichever forum-state conflict-of-laws regime picks up the
  // case, producing materially unpredictable enforcement outcomes.
  "mutual-nda-deep-missing-governing-law-fail.txt": ["NDA-D-017"],

  // SCC Module 2 with the "Clause 11 — Redress" heading replaced by
  // a generic "Customer Service Contact Point" paragraph — every
  // "Clause 11" anchor and every "redress" token is stripped. The
  // surviving prose preserves the contact-point obligation but loses
  // both the SCC clause-numbering and the statutory term "redress".
  // TRANSFER-006 is the load-bearing rule — its present_patterns
  // require `clause\s*11\b` or `redress\b`; without either anchor,
  // automated compliance tooling and auditors cannot locate the
  // mandatory data-subject redress disclosure, and internal cross-
  // references in the SCCs that point back to Clause 11 are silently
  // broken.
  "scc-module-2-missing-clause-11-fail.txt": ["TRANSFER-006"],

  // BAA with the "Access, Amendment, Accounting" header rewritten as
  // "Amendment, Accounting" — every `access to PHI`, `right of access`,
  // and `164.524` anchor is stripped. The surviving prose references
  // only § 164.526 (amendment) and § 164.528 (accounting) and uses
  // commercial substitutes ("inspect or obtain a copy") that
  // deliberately avoid the rule's three present_patterns. BAA-006 is
  // the load-bearing rule — § 164.504(e)(2)(ii)(E) requires the BAA
  // to enable the covered entity to satisfy individuals' right of
  // access under § 164.524; without this clause an access request
  // bottlenecks at the BA with no contractual hook.
  "baa-missing-access-to-phi-fail.txt": ["BAA-006"],

  // Mutual NDA with the governing-law clause re-pointed from Delaware
  // to Wyoming (and venue to Cheyenne) — Wyoming is outside the
  // NDA-D-018 viable-jurisdiction whitelist (Delaware / New York /
  // California / Texas / Massachusetts / Illinois / Washington /
  // England / United Kingdom). NDA-D-017 still passes (the
  // governing-law clause is present); NDA-D-018 fires at info
  // severity because the chosen jurisdiction is atypical and may
  // produce unpredictable enforcement outcomes for an NDA.
  "mutual-nda-deep-unusual-governing-law-fail.txt": ["NDA-D-018"],

  // Vendor-form MSA with Section 8(c) rewritten one-sided — "IN NO
  // EVENT SHALL EITHER PARTY BE LIABLE TO THE OTHER PARTY" becomes
  // "VENDOR SHALL NOT BE LIABLE TO CUSTOMER" and every "neither
  // party", "each party", and "mutual" scoping is stripped. The
  // consequential-damages waiver now runs in only one direction.
  // MSA-008 is the load-bearing rule — its present_patterns require
  // a mutual scoping anchor (`neither\s+party` / `each\s+party` /
  // `in\s+no\s+event\s+shall\s+either\s+party`) within 160 chars of a
  // consequential-damages token; with one-sided phrasing the
  // pattern fails to match and the rule fires at info severity.
  "msa-vendor-deep-one-sided-consequential-waiver-fail.txt": ["MSA-008"],

  // Controller-to-Processor DPA with Section 9 ("Assistance with
  // Articles 32 to 36 Obligations") replaced by a generic
  // "Cooperation on Operational Matters" paragraph — every
  // `Articles 32 to 36` and `assist ... (breach|security|DPIA)`
  // anchor is stripped. Surviving language references only
  // "commercially reasonable cooperation" with no GDPR-aligned
  // statutory framing. DPA-012 is the load-bearing rule — GDPR
  // Art. 28(3)(f) requires the processor to assist the controller
  // with the security (Art. 32), breach (Arts. 33–34), DPIA
  // (Art. 35), and prior-consultation (Art. 36) obligations;
  // without this clause the controller carries those obligations
  // alone, materially weakening Art. 28 alignment.
  "dpa-controller-processor-missing-art32-36-assistance-fail.txt": ["DPA-012"],

  // BAA with the Safeguards section narrowed from "administrative,
  // physical, and technical safeguards … 45 CFR §§ 164.308,
  // 164.310, and 164.312" to "physical and technical safeguards …
  // 45 CFR §§ 164.310 and 164.312" — every `administrative
  // safeguards` token and every `164.308` anchor is stripped, but
  // the broader "Security Rule" reference is retained so BAA-013
  // still passes. BAA-014 is the load-bearing rule — § 164.308
  // requires the BAA to anchor the administrative safeguards
  // (workforce training, contingency planning, periodic risk
  // assessment) that the Security Rule pins on every Business
  // Associate; without a § 164.308 hook the covered entity has no
  // contractual lever to enforce administrative-safeguard
  // compliance.
  "baa-missing-administrative-safeguards-fail.txt": ["BAA-014"],

  // Vendor Security Addendum with Section 2 rewritten to remove
  // every named encryption standard — "AES-256", "TLS 1.2", "TLS
  // 1.3", and any "FIPS 140-3" reference are all stripped and the
  // surviving prose references only "industry-standard symmetric
  // ciphers" and "a current version of the Transport Layer
  // Security protocol". ADDENDA-008 is the load-bearing rule —
  // FIPS 140-3 and named TLS / AES versions are the
  // practitioner-accepted contract anchors; generic "encryption" is
  // unauditable because there is no specific cipher suite or
  // protocol version against which to test the deployment.
  "vendor-security-addendum-missing-named-encryption-fail.txt": ["ADDENDA-008"],

  // SCC Module 2 with the "Clause 14 — Local Laws and Practices
  // Assessment" heading replaced by a generic "Destination-Country
  // Conditions Statement" paragraph — every `clause 14`, `local
  // laws and practices`, `transfer impact assessment`, and `TIA`
  // anchor is stripped. The surviving prose preserves a soft
  // good-faith warranty but loses the Schrems II TIA anchor.
  // TRANSFER-007 is the load-bearing rule — Clause 14 of Decision
  // 2021/914 anchors the Transfer Impact Assessment; without it
  // there is no contractual hook for the parties' Schrems II
  // analysis and supervisory authorities cannot locate the TIA
  // discussion in the document.
  "scc-module-2-missing-clause-14-fail.txt": ["TRANSFER-007"],

  // Mutual NDA with a non-solicitation clause added at Section 7
  // that runs for one year post-termination but contains no
  // general-solicitation / public-job-postings carve-out — the
  // surrounding 300-character window contains only "direct
  // contact", "indirect contact", and "executive recruiter
  // retained" language, deliberately omitting the standard
  // safe-harbor phrasing. NDA-D-020 is the load-bearing rule —
  // without a general-solicitation carve-out, ordinary recruiting
  // (LinkedIn posts, conference recruiters, public job ads)
  // becomes a contractual breach risk per the rule's negative
  // lookahead for `general\s+solicitation` /
  // `not\s+specifically\s+directed` / `general\s+advertis`.
  "mutual-nda-deep-non-solicit-no-carve-out-fail.txt": ["NDA-D-020"],

  // Vendor MSA with Section 8(b) "Carveouts" tightened so that
  // "cap shall not apply to indemnification" sits inside the
  // rule's 80-character proximity window. The pass fixture
  // separates the cap reference and the indemnification token
  // with ~95 chars of prose; the fail-fixture deliberately
  // collapses the carve-out list ("The cap shall not apply to
  // indemnification obligations under Section 7, breach of
  // confidentiality under Section 5, or liability arising from
  // gross negligence or willful misconduct."). MSA-005 (info)
  // fires because indemnification is now plainly excluded from
  // the aggregate liability cap — the rule surfaces this
  // commercially-contested choice for explicit review.
  "msa-vendor-deep-indemnity-carved-out-of-cap-fail.txt": ["MSA-005"],

  // BAA with the Safeguards section narrowed from "administrative,
  // physical, and technical safeguards … 45 CFR §§ 164.308,
  // 164.310, and 164.312" to "administrative and technical
  // safeguards … 45 CFR §§ 164.308 and 164.312" — every
  // `physical safeguards` token and every `164.310` anchor is
  // stripped while "Security Rule" is retained so BAA-013 still
  // passes. BAA-015 (warning) is the load-bearing rule —
  // § 164.310 requires the BAA to anchor physical safeguards
  // (facility access controls, workstation security, device
  // controls); without a § 164.310 hook the covered entity has no
  // contractual lever to enforce physical-safeguard compliance.
  "baa-missing-physical-safeguards-fail.txt": ["BAA-015"],

  // Controller-to-Processor DPA with Section 7 ("Subprocessors")
  // rewritten to omit any "prior written authorisation" /
  // "authorisation of Controller" anchor — the surviving clause
  // permits Processor to engage subprocessors at will, preserving
  // only a downstream notice + objection right and the flow-down
  // obligation. DPA-015 is the load-bearing rule — GDPR
  // Art. 28(2) requires the processor not to engage another
  // processor without prior specific or general written
  // authorisation; with the anchor stripped the contractual hook
  // for Art. 28(2) is lost and the controller has no upstream
  // veto over subprocessor onboarding.
  "dpa-controller-processor-missing-subprocessor-authorisation-fail.txt": ["DPA-015"],

  // Vendor Security Addendum with Section 3 rewritten so that
  // "Annual Penetration Test" becomes "Independent Penetration
  // Test" and the cadence is described as "on a periodic basis
  // as determined by Vendor's risk-management function" — every
  // `annual\w*` / `annually` / `quarter\w+` / `every \d+
  // months/years` anchor adjacent to "penetration test" /
  // "pen-test" is stripped. ADDENDA-009 (info) is the load-bearing
  // rule — annual third-party pen-tests are the
  // practitioner-accepted baseline for SaaS; without a stated
  // cadence the addendum carries no operational commitment to
  // testing frequency.
  "vendor-security-addendum-missing-pen-test-cadence-fail.txt": ["ADDENDA-009"],

  // BAA with the "Reporting" paragraph rewritten to drop the
  // "Security Incident" sentence — the breach-notification sentence
  // tied to 45 CFR § 164.410 is retained, but every `security
  // incident` token has been removed. BAA-017 is the load-bearing
  // rule — 45 CFR § 164.314(a)(2)(i)(C) requires the BAA to obligate
  // the Business Associate to report security incidents (including
  // unsuccessful attempts) to the Covered Entity; without that hook
  // the covered entity loses the contractual channel for incident
  // visibility short of a confirmed breach.
  "baa-missing-security-incident-reporting-fail.txt": ["BAA-017"],

  // Mutual NDA with Section 3 ("Permitted Use") rewritten to grant
  // use of Confidential Information "for any business purpose" of
  // the Receiving Party instead of "solely for the Permitted
  // Purpose." NDA-D-011 is the load-bearing rule — its bad_patterns
  // catch `for any (business )?purpose` / `any lawful purpose` /
  // `(unrestricted|any) use of (the )?confidential`, all of which
  // weaken the contractual basis for objecting to unrelated
  // downstream use of the disclosed information.
  "mutual-nda-deep-permitted-use-overbroad-fail.txt": ["NDA-D-011"],

  // Vendor MSA with a new Section 9 ("Service Level Agreement")
  // committing to 99.9% monthly uptime but declaring that a
  // prorated service credit is Customer's "sole and exclusive
  // remedy" for any service-level failure, including extended
  // downtime or chronic outage, and that Customer has no right to
  // terminate or seek other damages. MSA-017 is the load-bearing
  // rule — its bad_patterns catch the `(service|SLA) credit … sole
  // and exclusive remedy` and `sole and exclusive remedy … (service
  // level|SLA|downtime)` forms; an exclusive-remedy SLA bars the
  // customer from terminating or seeking damages for extended
  // outages, which is the commercially contested posture the rule
  // surfaces for explicit review.
  "msa-vendor-deep-sla-sole-exclusive-remedy-fail.txt": ["MSA-017"],

  // BAA with the Safeguards section narrowed from "administrative,
  // physical, and technical safeguards … 45 CFR §§ 164.308,
  // 164.310, and 164.312" to "administrative and physical
  // safeguards … 45 CFR §§ 164.308 and 164.310" — every
  // `technical safeguards` token and every `164.312` anchor is
  // stripped while the broader "Security Rule" reference is
  // retained so BAA-013 still passes. BAA-016 (warning) is the
  // load-bearing rule — § 164.312 requires the BAA to anchor
  // technical safeguards (access controls, audit logs, integrity
  // controls, transmission security); without a § 164.312 hook
  // the covered entity has no contractual lever to enforce
  // technical-safeguard compliance.
  "baa-missing-technical-safeguards-fail.txt": ["BAA-016"],

  // BAA with the breach-notification window widened from sixty to
  // 90 calendar days following discovery of the Breach — every
  // other anchor (`without unreasonable delay`, `discovery of the
  // Breach`, `45 CFR § 164.410`) is preserved so BAA-019 /
  // BAA-021 / BAA-022 still pass. BAA-020 (critical) is the
  // load-bearing rule — 45 CFR § 164.410(b) requires
  // notification "without unreasonable delay and in no case later
  // than 60 calendar days after discovery"; any window beyond 60
  // days violates HIPAA's outer bound.
  "baa-breach-notification-90-day-window-fail.txt": ["BAA-020"],

  // BAA with the "Return or Destruction" sentence rewritten so
  // the outer time bound is replaced with "as soon as
  // practicable thereafter" — every "thirty (30) days" /
  // "ninety (90) days" / "by no later than" anchor is stripped
  // and the surviving prose preserves only the open-ended
  // commitment. BAA-024 (warning) is the load-bearing rule — its
  // bad_patterns catch `(return|destroy|destruction) … (as soon
  // as practicable|commercially reasonable|reasonable time)`
  // within an 80-char window; HHS guidance expects a definite
  // outer bound for return or destruction of PHI at termination,
  // and open-ended timing risks indefinite PHI retention.
  "baa-return-or-destruction-open-ended-fail.txt": ["BAA-024"],

  // Vendor MSA with Section 11's bankruptcy-termination subsection
  // removed — every `bankruptc\w+` / `insolven\w+` / `receiver` /
  // `assignment for the benefit of creditors` anchor is stripped
  // while material-breach and convenience termination survive. The
  // surviving Section 11 still grants termination-for-cause on 30
  // days' notice of an uncured material breach plus a 60-day
  // termination-for-convenience right, so MSA-018 still passes.
  // MSA-019 (info) is the load-bearing rule — 11 U.S.C. § 365
  // makes pure ipso-facto clauses unenforceable in some scenarios
  // but the contract should still anchor the parties' intent that a
  // bankruptcy filing, insolvency, receivership, or assignment for
  // the benefit of creditors is a termination event.
  "msa-vendor-deep-missing-bankruptcy-termination-fail.txt": ["MSA-019"],

  // Vendor MSA with the "Transition Assistance" section removed —
  // every `wind[- ]down` / `transition (assistance|services|
  // period)` / `continued access` / `post[- ]termination
  // (access|services)` anchor is stripped while the bankruptcy
  // and material-breach termination subsections and the data-return
  // clause are preserved. MSA-020 (info) is the load-bearing rule —
  // without a wind-down period the customer can be cut off
  // mid-migration; the commercial baseline is up to N (e.g., 90)
  // days of post-termination service continuation at then-current
  // rates to facilitate transition.
  "msa-vendor-deep-missing-wind-down-fail.txt": ["MSA-020"],

  // Vendor MSA with a new Section 15 ("Assignment") that bars
  // assignment without prior written consent but is silent on
  // change-of-control / merger / acquisition. MSA-023 (info) is the
  // load-bearing rule — its bad_patterns catch `(neither party may
  // assign|no assignment)` with a negative lookahead for
  // `change of control` / `merger` / `acquisition` within the next
  // 200 chars; without a change-of-control hook an acquirer can
  // effectively step into the contract without the counterparty's
  // consent.
  "msa-vendor-deep-assignment-silent-change-of-control-fail.txt": ["MSA-023"],

  // Mutual NDA with an added Section 8 "Residuals" clause that
  // permits each Party to use information retained in the "unaided
  // memory" of its personnel "for any purpose," and disclaims any
  // royalty obligation. NDA-D-010 (info) is the load-bearing rule —
  // its bad_patterns flag the bare `\bresiduals?\b` anchor and the
  // `retained in.{0,40}(unaided )?memory` phrasing. The rule does
  // not assert wrongness; it surfaces the carve-out so the discloser
  // can make a deliberate choice about whether to keep it.
  "mutual-nda-deep-residuals-clause-fail.txt": ["NDA-D-010"],

  // Vendor MSA with an added Section 5 "Feedback License" granting
  // Vendor a perpetual, irrevocable, royalty-free, worldwide license
  // to use Customer feedback "for any purpose, without any
  // restriction whatsoever." MSA-012 (info) is the load-bearing
  // rule — its bad_patterns catch `feedback` within 80 chars of
  // `perpetual|irrevocable|royalty-free|worldwide` within another
  // 80 chars of `any purpose|without (any )?restriction`. The clause
  // is broad enough to sweep in customer ideas the customer may want
  // to commercialize separately.
  "msa-vendor-deep-feedback-license-unbounded-fail.txt": ["MSA-012"],

  // Multi-state US DPA with Section 7 rewritten to drop every
  // "equivalent obligations" / "same restrictions" anchor — the
  // subprocessor engagement clause still requires a written contract
  // (so USDPA-018 stays satisfied) but no longer flows the
  // service-provider's CCPA restrictions down to the subprocessor.
  // USDPA-010 is the load-bearing rule — Cal. Code Regs. tit. 11,
  // § 7051(b) requires the contract with subcontractors to include
  // the same CCPA provisions; without that flow-down a subprocessor
  // is operating off-contract from the business's point of view.
  "dpa-multi-state-us-missing-subprocessor-flow-down-fail.txt": ["USDPA-010"],

  // BAA with Section 1's "Permitted Uses and Disclosures" heading
  // renamed to "Scope of PHI Handling" and every `(permitted|
  // authorized) (uses|disclosures)` / `uses and disclosures of
  // PHI` anchor stripped from the body — "permitted or required"
  // language is replaced with "required" throughout. The downstream
  // safeguards / reporting / subcontractor-flow-down / access-
  // amendment-accounting / books-records / return-or-destruction /
  // minimum-necessary clauses are preserved so BAA-002..018 still
  // pass. **BAA-001** is the load-bearing rule — 45 C.F.R.
  // § 164.504(e)(2)(i) requires the BAA to set out the permitted
  // and required uses and disclosures of PHI; without that clause
  // the agreement does not satisfy HIPAA's core contracting
  // standard.
  "baa-missing-permitted-uses-and-disclosures-fail.txt": ["BAA-001"],

  // Controller→processor GDPR DPA with Section 1's "Subject-Matter,
  // Duration, Nature, and Purpose of Processing" heading rewritten
  // to "Services, Duration, Nature, and Purpose of Processing" and
  // the body's `subject-matter of the processing` / `scope of
  // processing` anchors replaced with "the services consist of."
  // The duration / nature-and-purpose / categories-of-data /
  // documented-instructions / Art. 32 / subprocessor / DSR /
  // breach-notification / deletion-or-return clauses are
  // preserved so DPA-002..016 still pass. **DPA-001** is the
  // load-bearing rule — GDPR Art. 28(3) introductory paragraph
  // requires the controller-processor contract to set out the
  // subject-matter of the processing.
  "dpa-controller-processor-missing-subject-matter-fail.txt": ["DPA-001"],

  // SCC Module 2 transfer with the "Clause 16 — Non-Compliance and
  // Suspension or Termination" section removed; every `clause\s*16`
  // / `non-compliance with (the )?clauses` anchor is stripped. A
  // generic "Termination for Breach" paragraph stands in for the
  // suspension/termination mechanic so the operative remedy isn't
  // lost commercially. **TRANSFER-009 (warning)** is the load-
  // bearing rule — EU SCCs Clause 16 governs the parties' rights
  // when the SCCs become untenable; without it neither party has
  // the SCC-defined suspension or termination right.
  "scc-module-2-missing-clause-16-fail.txt": ["TRANSFER-009"],

  // BAA with Section 1's "shall not use or disclose PHI other than
  // as permitted or required" sentence rewritten to a permissive
  // "may handle PHI in accordance with the requirements of this
  // BAA" — every `(not use or disclose|shall not use)` anchor is
  // stripped from the body. The downstream safeguards / reporting
  // / subcontractor / access-amendment-accounting / books-records /
  // return-or-destruction clauses are preserved so BAA-003..018
  // still pass. **BAA-002** fires — 45 C.F.R.
  // § 164.504(e)(2)(ii)(A) requires the contract to prohibit the
  // BA from using or further disclosing PHI other than as permitted
  // by the contract or as required by law; the permissive
  // "may handle" phrasing does not satisfy that prohibition.
  "baa-missing-use-limitation-fail.txt": ["BAA-002"],

  // Controller→processor GDPR DPA with Section 1's heading
  // rewritten to "Subject-Matter, Nature, and Purpose of
  // Processing" — every `duration of (the )?processing` anchor is
  // removed from the body. The subject-matter / nature-and-purpose
  // / categories-of-data / documented-instructions / Art. 32 /
  // subprocessor / DSR / breach-notification / deletion-or-return
  // clauses remain so DPA-001 and DPA-003..016 still pass.
  // **DPA-002** fires — GDPR Art. 28(3) introductory paragraph
  // requires the duration of the processing to be set out, so the
  // controller and processor know when the processing relationship
  // (and the data-protection obligations bundled with it) end.
  "dpa-controller-processor-missing-duration-of-processing-fail.txt": ["DPA-002"],

  // UK IDTA Addendum with the "Table 3 — Appendix Information"
  // section replaced by a generic "Annex Incorporation by
  // Reference" paragraph; every `Table\s*3\s*[—:-]\s*Appendix
  // Information` / `table\s*3\b.{0,40}appendix` anchor is removed.
  // Tables 1, 2, and 4 are preserved so TRANSFER-011 / 012 / 014 /
  // 016 still pass. **TRANSFER-013 (warning)** fires — the ICO UK
  // Addendum Mandatory Clauses require Table 3 to incorporate the
  // EU SCC Annex information (parties, transfer description,
  // supervisory authority, TOMs); a reference-only paragraph does
  // not satisfy the mandatory-clauses requirement to complete
  // Table 3.
  "uk-idta-addendum-missing-table-3-fail.txt": ["TRANSFER-013"],

  // BAA with Section 2's "administrative, physical, and technical
  // safeguards" enumeration rewritten as a generic "Security
  // Program" reference — every `appropriate safeguards` /
  // `administrative.*physical.*technical` / `reasonable
  // safeguards` anchor is removed. The 45 CFR § 164.314 cross-
  // reference survives so the contract still gestures at Security
  // Rule compliance, but no contract-level safeguards obligation
  // exists. **BAA-003** fires — § 164.504(e)(2)(ii)(B) requires
  // the BA to use appropriate safeguards (including the Security
  // Rule administrative, physical, and technical safeguards) to
  // prevent use or disclosure of PHI other than as provided for
  // by the contract; a bare program-reference does not satisfy
  // that contracting standard.
  "baa-missing-appropriate-safeguards-fail.txt": ["BAA-003"],

  // Controller→processor GDPR DPA with Section 1's heading
  // rewritten to "Subject-Matter, Duration of Processing" and
  // every `nature and purpose of (the )?processing` anchor
  // removed from the body — the Section 1 sentence describing
  // analysis of engagement data is reframed as a Processor
  // obligation rather than a description of the processing
  // nature/purpose. The subject-matter / duration / categories-
  // of-data / documented-instructions / Art. 32 / subprocessor /
  // DSR / breach-notification / deletion-or-return clauses
  // remain so DPA-001 / DPA-002 / DPA-004..016 still pass.
  // **DPA-003** fires — GDPR Art. 28(3) introductory paragraph
  // requires the nature and purpose of the processing to be
  // described so the controller's data-protection assessment
  // and the processor's scope are aligned.
  "dpa-controller-processor-missing-nature-and-purpose-fail.txt": ["DPA-003"],

  // UK IDTA Addendum with the "Table 4 — Ending this Addendum
  // when the Approved Addendum Changes" section removed; every
  // `Table\s*4\s*[—:-]\s*Ending` / `table\s*4\b.{0,40}(ending|
  // approved\s+addendum)` anchor is stripped. The Mandatory
  // Clauses 19 and 20 still cover ICO-update termination but the
  // mandatory Table 4 slot is empty. Tables 1, 2, and 3 are
  // preserved so TRANSFER-011 / 012 / 013 / 016 still pass.
  // **TRANSFER-014 (warning)** fires — the ICO UK Addendum
  // Mandatory Clauses require Table 4 to specify which party (or
  // both) may end the Addendum on a revision; without Table 4 the
  // termination-on-ICO-update mechanic is ambiguous.
  "uk-idta-addendum-missing-table-4-fail.txt": ["TRANSFER-014"],

  // BAA with the "Reporting" section renamed to "Internal Logging"
  // and the operative sentence rewritten so the BA "shall maintain
  // internal logs" of incidents and "report Breaches…to Acme Health
  // LLC's Privacy Officer" — every `(report to|notify) covered
  // entity` anchor is stripped while the 45 CFR § 164.410 breach-
  // notification cross-reference and the 60-day window survive so
  // BAA-019 / BAA-022 still pass. **BAA-004** fires — 45 C.F.R.
  // § 164.504(e)(2)(ii)(C) requires the BAA to obligate the BA to
  // report to the Covered Entity any use or disclosure not
  // authorized by the contract; logging-only / Privacy-Officer-
  // only language does not satisfy the report-to-Covered-Entity
  // obligation in the statutory text.
  "baa-missing-improper-use-reporting-fail.txt": ["BAA-004"],

  // Controller→processor GDPR DPA with Section 2's heading
  // rewritten to "Data Subjects and Information Inventory" and
  // every `type|categories of personal data` / `personal data
  // processed|categories` anchor stripped — "types of personal
  // data" is replaced with "information" in the body. Annex I is
  // renamed "Information Inventory" and rewritten to drop
  // "categories of personal data are subject" while keeping the
  // three-tier (identification / technical / behavioral) listing.
  // The categories of data subjects sentence is preserved so
  // DPA-005 still passes; DPA-001..004-other / DPA-006..016 also
  // pass. **DPA-004** fires — GDPR Art. 28(3) introductory
  // paragraph requires the type of personal data to be specified
  // so the processor's permitted-processing scope is bounded by
  // category; a bare "information inventory" without the
  // statutory "personal data" tag does not satisfy that
  // requirement.
  "dpa-controller-processor-missing-type-of-personal-data-fail.txt": ["DPA-004"],

  // UK IDTA Addendum with the "Table 2 — Selected SCCs, Modules
  // and Selected Clauses" section replaced by a generic "EU SCC
  // Incorporation" paragraph; every `Table\s*2\s*[—:-]\s*Selected
  // SCC Modules` / `table\s*2\b.{0,40}module` anchor is removed
  // and no Module (1/2/3/4) is identified. Tables 1, 3, and 4 are
  // preserved so TRANSFER-011 / 013 / 014 / 016 still pass.
  // **TRANSFER-012 (warning)** fires — the ICO UK Addendum
  // Mandatory Clauses require Table 2 to identify which EU SCC
  // Modules are being incorporated; without that anchor the
  // Importer's role (controller / processor / sub-processor) is
  // ambiguous and the Module-specific Clause-8 obligations are
  // not bound in.
  "uk-idta-addendum-missing-table-2-fail.txt": ["TRANSFER-012"],

  // UK IDTA Addendum with the "Table 1 — Parties" heading renamed
  // to a generic "Counterparty Details" section and every
  // `Table\s*1\s*[—:-]\s*Parties` / `table\s*1\b.{0,40}part`
  // anchor stripped. The Exporter / Importer identification text
  // is preserved as free-form prose so the contract is still
  // commercially legible. Tables 2, 3, and 4 are preserved so
  // TRANSFER-012 / 013 / 014 still pass. **TRANSFER-011 (warning)**
  // fires — the ICO UK Addendum Mandatory Clauses require Table 1
  // to identify the Exporter and Importer in the prescribed
  // tabular form; a free-form section does not satisfy the
  // mandatory-clauses requirement. The companion TRANSFER-016
  // (broader Parties-identification rule across both IDTA Part 1
  // and Addendum Table 1) also fires for the same anchor loss.
  "uk-idta-addendum-missing-table-1-fail.txt": ["TRANSFER-011"],

  // UK IDTA Addendum with an added "Adequacy Mechanism" paragraph
  // that asserts the Importer's certification under the EU-US
  // Data Privacy Framework (and the UK Extension) is "sufficient
  // to provide appropriate safeguards for Restricted Transfers"
  // and that "the Parties shall not be required to implement any
  // additional transfer mechanism while the DPF adequacy decision
  // remains in force." Tables 1–4 and the Mandatory Clauses are
  // preserved so TRANSFER-011..016 still pass. **TRANSFER-017
  // (warning)** fires — its bad_patterns flag any
  // `EU-US Data Privacy Framework` / `EU-US DPF` /
  // `DPF (adequacy|certification)` mention; the DPF adequacy
  // decision is permanently under litigation and a contract that
  // disclaims any fallback transfer mechanism leaves the parties
  // exposed if (or when) the DPF is invalidated again.
  "uk-idta-addendum-relies-on-dpf-fail.txt": ["TRANSFER-017"],

  // Controller→processor GDPR DPA with Section 6's measure-(e)
  // rewritten to a "defined change-management process governing
  // updates to security configurations and supporting
  // infrastructure"; every `testing.*(measures|controls)` /
  // `penetration\s+test` / `vulnerability\s+(scan|assessment)` /
  // `periodic\s+assess` anchor is removed from the entire DPA.
  // The remaining Section 6 measures (encryption, pseudonymisation,
  // confidentiality/integrity/availability/resilience, restore-
  // availability) and Articles 32–36 assistance, breach
  // notification, audit-and-inspection clauses are preserved so
  // DPA-019 / 020 / 021 / 023 still pass. **DPA-022 (warning)**
  // fires — GDPR Art. 32(1)(d) requires a process for regularly
  // testing, assessing and evaluating the effectiveness of
  // technical and organisational measures; a change-management
  // process is necessary but not sufficient to satisfy the
  // statutory testing-of-measures requirement.
  "dpa-controller-processor-missing-testing-of-measures-fail.txt": ["DPA-022"],

  // Vendor MSA with an added Section 8(d) "Exculpation" clause
  // stating that "Vendor shall not be liable for fraud, willful
  // injury, or violation of any law, and no liability shall apply
  // to fraud or willful misconduct" — and governing law switched
  // to California so the § 1668 problem actually bites. Section 8
  // (a)–(c) (cap / carveouts / consequential waiver) is preserved.
  // **MSA-009 (warning)** fires — California Civil Code § 1668
  // voids contracts that exempt anyone from responsibility for
  // their own fraud, willful injury, or violation of law; a cap
  // (or here, a stand-alone exculpation) that absorbs these
  // categories is unenforceable in California regardless of any
  // carve-out elsewhere in the agreement.
  "msa-vendor-deep-cal-1668-exculpation-fail.txt": ["MSA-009"],

  // Vendor MSA with Section 6's limited-warranty disclaimer
  // rewritten to "provided as is and with all faults, without any
  // other warranty of any kind, express or implied, and Vendor
  // disclaims any and all warranties to the maximum extent
  // permitted by applicable law" — i.e., the "as is" lead-in is
  // followed by "without any other warranty," matching MSA-015's
  // first bad_pattern. The conspicuous-MERCHANTABILITY callout
  // is dropped. **MSA-015 (info)** fires — UCC § 2-316 requires
  // merchantability disclaimers to mention "merchantability"
  // expressly and to be conspicuous; a generic "AS IS / disclaims
  // any and all warranties" without the conspicuous-MERCHANTABILITY
  // callout fails the UCC test, leaving the implied-warranty
  // disclaimer vulnerable to challenge.
  "msa-vendor-deep-as-is-without-warrant-fail.txt": ["MSA-015"],

  // Vendor MSA with Section 11 collapsed to a single sentence
  // that names Delaware as the governing law and New York County
  // courts as the forum — the governing-law / venue alignment is
  // broken and a Delaware-courts→Delaware-law symmetric structure
  // is replaced by a Delaware-law→New-York-courts mismatch.
  // **MSA-024 (info)** fires — its bad_patterns catch a
  // `governed by the laws of {State A}` clause followed within
  // 400 non-period characters by a `(courts|venue|jurisdiction|
  // forum)` reference to a different `{State B}`; choosing one
  // state's law but another state's forum forces the forum court
  // to apply foreign law, adding cost and uncertainty.
  "msa-vendor-deep-governing-law-venue-mismatch-fail.txt": ["MSA-024"],

  // Controller→processor GDPR DPA with Section 6's measure-(a)
  // rewritten as "network and storage-layer cryptographic
  // protection ... using industry-standard algorithms" and
  // measure-(b) rewritten as "data minimization, access controls,
  // and least-privilege role assignment" — every
  // `pseudonymi[sz]ation` / `encrypt(ion|ed)` anchor is removed
  // from the entire DPA. The remaining Section 6 measures
  // (CIA-R triad, restore availability, regular testing) and
  // Articles 32–36 assistance, breach notification, audit clauses
  // are preserved so DPA-020 / 021 / 022 / 023 still pass.
  // **DPA-019 (warning)** fires — GDPR Art. 32(1)(a) lists
  // pseudonymisation and encryption among the technical and
  // organisational measures appropriate to the risk; replacing
  // these named statutory measures with generic
  // "cryptographic protection" and "data minimization" drops the
  // Art. 32(1)(a) anchor.
  "dpa-controller-processor-missing-pseudonymisation-encryption-fail.txt": ["DPA-019"],

  // Controller→processor GDPR DPA with Section 6's measure-(c)
  // rewritten as "operational hardening of processing systems and
  // services through configuration management, segregation of
  // duties, and capacity planning" — every CIA-R triad anchor
  // (`confidentiality.{0,30}integrity.{0,30}availability` /
  // `availability.{0,30}resilience` /
  // `integrity.{0,30}availability`) is removed from the entire
  // DPA. The remaining Section 6 measures (encryption,
  // pseudonymisation, restore availability, regular testing) and
  // downstream clauses are preserved so DPA-019 / 021 / 022 / 023
  // still pass. **DPA-020 (warning)** fires — GDPR Art. 32(1)(b)
  // requires measures to ensure ongoing confidentiality,
  // integrity, availability and resilience of processing systems
  // and services; "operational hardening" generic language does
  // not satisfy the named four-element commitment.
  "dpa-controller-processor-missing-cia-resilience-fail.txt": ["DPA-020"],

  // Controller→processor GDPR DPA with Section 6's measure-(d)
  // rewritten as "maintenance of redundant infrastructure
  // designed to limit unplanned downtime" — every
  // `restore\s+availability` / `disaster\s+recovery` /
  // `business\s+continuity` / `backup\s+and\s+recovery` anchor is
  // removed from the entire DPA. The remaining Section 6 measures
  // (encryption, pseudonymisation, CIA-R triad, regular testing)
  // and downstream clauses are preserved so DPA-019 / 020 / 022 /
  // 023 still pass. **DPA-021 (warning)** fires — GDPR
  // Art. 32(1)(c) requires the ability to restore the availability
  // and access to personal data in a timely manner in the event of
  // an incident; the "redundant infrastructure" phrasing is a
  // partial substitute that lacks the restore-on-incident anchor.
  "dpa-controller-processor-missing-restore-availability-fail.txt": ["DPA-021"],

  // Controller→processor GDPR DPA with Section 10's "Breach
  // Notification (Article 33 GDPR)" rewritten as a generic
  // "Incident Handling" paragraph: every `personal\s+data\s+breach`
  // / `breach\s+of\s+personal\s+data` / `data\s+breach` anchor is
  // removed, and the operative sentence is reframed as "Processor
  // shall, without undue delay, work with Controller to investigate
  // and remediate the underlying issue" — i.e., no "notify
  // Controller … breach/incident" anchor in proximity. The other
  // DPA clauses (Section 9 Articles 32–36 assistance referencing
  // "breach notification" generically, Section 2 categories of
  // data subjects, Section 6 security measures, and the "without
  // undue delay" phrasing) are preserved so DPA-012 / 020 / 022 /
  // 025 / 026 still pass. **DPA-024 (critical)** fires — GDPR
  // Art. 33(2) requires the processor to notify the controller
  // without undue delay after becoming aware of a personal data
  // breach; a generic "operational anomaly / regulatory obligation"
  // framing does not satisfy the named statutory anchor.
  "dpa-controller-processor-missing-processor-breach-notice-fail.txt": ["DPA-024"],

  // Vendor MSA with Section 5's "shall survive termination of this
  // Agreement for three (3) years" rewritten to "shall continue in
  // force after the end of this Agreement for three (3) years"
  // (every `surviv\w+` anchor removed) and Section 12 swapped from
  // "Entire Agreement" to a generic "Counterparts" paragraph
  // (every `entire\s+agreement` / `integration\s+clause` /
  // `supersed\w+\s+(?:all\s+)?prior` anchor removed). **MSA-026
  // (info)** fires — its `present_patterns` need either a
  // survival-tied-to-termination phrase or an entire-agreement /
  // integration / supersedes-all-prior phrase; without survival,
  // sticky obligations (confidentiality, IP, indemnity) may not
  // outlive termination, and without integration prior
  // negotiations may be admissible.
  "msa-vendor-deep-missing-survival-entire-agreement-fail.txt": ["MSA-026"],

  // Vendor Security Addendum with Section 4(c) "quarterly access
  // reviews" rewritten to "regular access reviews on an ongoing
  // basis" — every `(annual\w*|annually|quarterly|every\s+\d+\s+
  // (?:months?|years?))` token bound within 80 non-period chars
  // of an audit / review / assessment / certification / attestation
  // / SOC 2 / ISO 27001 anchor is removed. Sections 3(a) "Annual
  // Penetration Test" and Section 11 "annual information-security
  // awareness training" survive but neither pairs a cadence token
  // with one of ADDENDA-002's listed anchors. **ADDENDA-002
  // (warning)** fires — without a stated cadence (e.g., "SOC 2
  // Type II report renewed annually," "quarterly access reviews,"
  // "ISO 27001 certification renewed every three years") the
  // addendum carries no operational commitment a customer can
  // audit against.
  "vendor-security-addendum-missing-review-cadence-fail.txt": ["ADDENDA-002"],

  // Controller→processor GDPR DPA with Section 10's "without
  // undue delay" phrase replaced with "promptly"; every
  // `without\s+undue\s+delay` anchor is removed from the entire
  // DPA. Section 10 still says "Processor shall notify Controller
  // promptly after becoming aware of a personal data breach, and
  // in any event within 48 hours" so DPA-024 (Art. 33(2) presence)
  // still passes, and Section 2 retains "categories of data
  // subjects" so DPA-026 still passes; the 48-hour window is in
  // hours, not days, so the DPA-027 loose-timing bad_pattern
  // (`within\s+\d+\s+days?`) does not fire. **DPA-025 (warning)**
  // fires — GDPR Art. 33(2) uses the "without undue delay"
  // standard and drafters should preserve the exact phrasing so
  // the processor's reporting trigger maps cleanly onto the
  // controller's Art. 33(1) 72-hour clock; "promptly" is a softer
  // standard that does not carry the same supervisory-authority
  // expectation.
  "dpa-controller-processor-missing-undue-delay-fail.txt": ["DPA-025"],

  // BAA with a new "Definitions" section that narrows "Security
  // Incident" to "only successful unauthorized access to or
  // successful disclosure of ePHI" and expressly excludes
  // unsuccessful attempts from the definition. The Reporting,
  // Safeguards, Subcontractor-Flow-Down, Access/Amendment/
  // Accounting, Books/Records, Return-or-Destruction, and
  // Breach-Notification clauses are preserved so BAA-001..022
  // still pass. **BAA-023 (warning)** fires — its bad_patterns
  // catch both `Security\s+Incident.{0,200}successful\s+(unauthorized|access)`
  // and `only\s+successful\s+(unauthorized\s+access|incidents)`;
  // OCR's interpretation of 45 CFR § 164.304 is that "Security
  // Incident" includes both successful and unsuccessful attempts,
  // so narrowing to "only successful" excludes attack telemetry
  // (failed login storms, port scans, unsuccessful intrusion
  // attempts) that the covered entity needs to track to fulfill
  // its Security Rule risk-management duty.
  "baa-security-incident-narrowed-fail.txt": ["BAA-023"],

  // Multi-state US DPA with Section 2(b) rewritten from "share
  // personal information for cross-context behavioral advertising
  // as defined in Cal. Civ. Code § 1798.140(ah)" to "make personal
  // information available to any third party for targeted
  // advertising purposes outside the Business Purpose"; every
  // `cross[- ]context\s+behavioral\s+advertising` anchor is
  // removed from the entire DPA. Section 2(a) sell-prohibition,
  // Section 2(c) Business-Purpose limitation, and Section 2(d)
  // no-combining restriction are preserved so USDPA-002 / 005 /
  // 007 / 008 still pass. **USDPA-003 (critical)** fires —
  // Cal. Civ. Code § 1798.140(ag)(1)(A) requires the service-
  // provider contract to prohibit sharing including for
  // cross-context behavioral advertising as a named statutory
  // category; a generic "targeted advertising" prohibition is
  // not equivalent because CCPA / CPRA enforcement turns on the
  // specific "cross-context behavioral advertising" statutory
  // term of art.
  "dpa-multi-state-us-missing-cross-context-prohibition-fail.txt": ["USDPA-003"],

  // Controller→processor GDPR DPA with Section 9's "Assistance
  // with Articles 32 to 36 Obligations" rewritten to drop every
  // `data\s+protection\s+impact\s+assessment` / `\bDPIA\b` /
  // `article\s*35` anchor — the sentence now reads "...including
  // obligations relating to security, breach notification, prior
  // consultation with supervisory authorities, and the
  // supplementary measures appropriate to those obligations." The
  // "Articles 32 to 36" reference survives so DPA-012 (Art. 28(3)(f)
  // assistance) still passes, and the broader breach / security
  // / consultation anchors keep DPA-008..014 intact. **DPA-029
  // (warning)** fires — GDPR Art. 35 requires a DPIA for
  // high-risk processing and Art. 28(3)(f) obliges the processor
  // to assist; a "supplementary measures" wave-off does not
  // anchor the processor's DPIA assistance duty, which auditors
  // and supervisory authorities look for as a discrete clause.
  "dpa-controller-processor-missing-dpia-assistance-fail.txt": ["DPA-029"],

  // BAA with a new "Indemnification" clause appended after the
  // Term section reciting that "Covered Entity shall indemnify,
  // defend, and hold harmless Business Associate from and against
  // any claim, loss, fine, penalty, or expense … arising out of
  // or relating to any alleged HIPAA violation … regardless of
  // the source of the underlying breach." Every other BAA clause
  // (Permitted Uses, Safeguards, Reporting, Subcontractor
  // Flow-Down, Access/Amendment/Accounting, Books/Records,
  // Return-or-Destruction, Breach Notification) is preserved so
  // BAA-001..022 still pass. **BAA-027 (warning)** fires — its
  // `bad_patterns` catch `covered\s+entity\s+(shall|will)\s+indemnif`;
  // 45 C.F.R. § 164.504(e) and HHS posture make clear that the
  // covered entity should not indemnify the business associate
  // for the BA's own HIPAA violations, because doing so inverts
  // the regulatory burden and lets the BA shift the cost of its
  // own non-compliance back to the customer.
  "baa-covered-entity-indemnifies-ba-fail.txt": ["BAA-027"],

  // SCC Module 2 with the Clause 14 heading renamed from "Local
  // Laws and Practices Assessment" to "Destination-Jurisdiction
  // Compliance Warranty" and the body's "documented transfer
  // impact assessment" rewritten to "documented internal review
  // of the destination jurisdiction"; every
  // `transfer\s+(?:impact|risk)\s+assessment` /
  // `local\s+laws\s+and\s+practices` / `\bTIA\b` / `\bTRA\b` /
  // `supplementary\s+measures` anchor is removed from the entire
  // SCC. The Clause 14 heading retains "Clause 14" so TRANSFER-007
  // (presence of Clause 14) still passes; Clause 15 public-authority
  // and Clause 16 non-compliance survive so TRANSFER-008 / 009
  // still pass. **TRANSFER-019 (critical)** fires — EDPB
  // Recommendations 01/2020 require the parties to anchor a
  // Transfer Impact Assessment (TIA) — the assessment of local
  // laws and practices of the recipient country plus any
  // supplementary measures — in the SCC; a bare "documented
  // internal review" without the named statutory anchors does
  // not satisfy the Schrems II / EDPB expectation.
  "scc-module-2-missing-tia-reference-fail.txt": ["TRANSFER-019"],

  // Controller→processor GDPR DPA with Section 7 (Subprocessors)
  // rewritten so the "thereby giving Controller the opportunity
  // to object to such changes" clause is removed; every
  // `(opportunity\s+to\s+object|right\s+to\s+object).*?
  // (sub[- ]?processor|processor)` anchor disappears. The general-
  // written-authorization recital, the 30-day prior-notice
  // requirement, the equivalent-data-protection flow-down, and
  // the processor's full-liability undertaking are preserved so
  // DPA-015 / 017 still pass. **DPA-016 (critical)** fires —
  // GDPR Art. 28(2) requires informing the controller of intended
  // subprocessor changes AND giving the controller an opportunity
  // to object; a notice-without-objection-right does not satisfy
  // the statutory standard and leaves the controller no lever to
  // block a subprocessor it cannot accept.
  "dpa-controller-processor-missing-subprocessor-objection-fail.txt": ["DPA-016"],

  // BAA with a new "Limitation of Liability" clause appended
  // after the Term section reciting that "each Party's aggregate
  // liability for any and all claims arising out of or relating
  // to this BAA shall not exceed the fees paid by Covered Entity
  // to Business Associate in the twelve (12) months immediately
  // preceding the event giving rise to the claim." Every other
  // BAA clause is preserved so BAA-001..022 still pass.
  // **BAA-025 (warning)** fires — its `bad_pattern`
  // (`(aggregate\s+liability|total\s+liability|liability.{0,40}
  // shall\s+not\s+exceed).{0,120}(fees|paid|amount)`) catches the
  // injected cap; HIPAA civil money penalties under 45 C.F.R.
  // § 160.404 can reach over $2M per violation category per year
  // (adjusted annually), so a 12-month-fees cap effectively
  // shifts HIPAA risk back to the Covered Entity rather than
  // allocating it to the BA whose breach caused the penalty.
  "baa-indemnity-cap-impairing-hipaa-fail.txt": ["BAA-025"],

  // Vendor MSA with Section 11 governing-law switched from
  // Delaware to New York and a new Section 13 "Construction
  // Project Indemnity" appended that recites "Vendor shall
  // indemnify and hold harmless Customer for any and all claims
  // and losses arising out of or related to such work, including
  // those resulting from the negligence of the indemnitee." The
  // existing Section 7 mutual indemnification, Section 8
  // liability cap with carveouts, and Section 11 venue clause
  // are preserved so MSA-002 / 005 / 006 / 008 / 024 still pass.
  // **MSA-010 (warning)** fires — N.Y. Gen. Oblig. § 5-322.1
  // voids construction-contract indemnities that require the
  // indemnitor to indemnify the indemnitee for the indemnitee's
  // own negligence; the rule's first bad_pattern catches
  // `indemnif\w+ … for any and all claims … including … negligence
  // of the indemnitee` end-to-end and surfaces the void-on-its-face
  // exposure the New-York-law clause inherits.
  "msa-vendor-deep-ny-construction-indemnity-fail.txt": ["MSA-010"],

  // Mutual NDA with §3 (Use Restriction) and §4 (Obligations of
  // Receiving Party) rewritten so the "solely for the Permitted
  // Purpose" framing is replaced with open-ended "in connection
  // with the Engagement" language; the recital "Permitted Purpose"
  // definition is dropped in favor of a vague "matter described in
  // the parties' written correspondence." Every NDA-D-001..002
  // DTSA component, the 3-year confidentiality term, trade-secret
  // perpetuity, return-or-destruction certificate, Delaware
  // governing-law clause, and mutual symmetry are preserved so the
  // rest of the NDA-deep baseline still passes. **NDA-D-012
  // (warning)** fires — its present_patterns require either
  // `solely\s+(for|to)\s+(the\s+)?purpose`,
  // `to\s+(evaluate|assess|consider)\s+(a\s+)?(potential|the)\s+(business|transaction)`,
  // or `\bpurpose\b.{0,40}(means|defined)`; none match, so the
  // narrow-purpose framing is reported missing. Without a defined
  // Purpose, the discloser loses the contractual hook to object
  // when the receiver redirects Confidential Information to
  // unrelated downstream use.
  "mutual-nda-deep-missing-purpose-narrow-framing-fail.txt": ["NDA-D-012"],

  // CCPA Service-Provider Addendum with §5 "Consumer Rights
  // Assistance" removed entirely; every other anchor (verifiable
  // consumer requests, consumer-rights wording, assist-the-business
  // language) is absent from the rest of the document so no other
  // paragraph supplies the missing recital. Sections 4
  // (Certification), 6 (Subprocessors), 7 (Security), 8 (Deletion
  // or Return), and 9 (Audit) are preserved so the rest of the
  // USDPA-001..025 baseline still passes where it was passing.
  // **USDPA-008 (critical)** fires — 11 C.C.R. § 7051(a)(8)
  // requires the service-provider contract to require the service
  // provider to enable the business to comply with verifiable
  // consumer requests under the CCPA; a contract silent on
  // consumer-rights assistance leaves the business with no
  // contractual lever to fulfill consumer-rights timelines and
  // exposes it to enforcement under § 1798.155 / § 1798.199.55.
  "dpa-ccpa-service-provider-missing-consumer-rights-assistance-fail.txt": ["USDPA-008"],

  // Vendor MSA with Section 11 governing-law switched from
  // Delaware to Texas and a new Section 13 "Construction Project
  // Indemnity" whose opening sentence pairs "this Agreement is
  // governed by the laws of the State of Texas" with "Vendor
  // shall indemnify and hold harmless Customer for any and all
  // claims and losses ... including those resulting from the
  // negligence of the indemnitee" in a single sentence. The
  // Texas anchor and the indemnity-for-indemnitee-negligence sit
  // in the same sentence so the intra-sentence `[^.]{0,400}` window
  // in MSA-029's bad_pattern captures the pairing. Section 7
  // mutual indemnification, Section 8 cap-with-carveouts, and
  // the other MSA-deep clauses are preserved so the rest of the
  // baseline still passes. **MSA-029 (warning)** fires — Tex.
  // Bus. & Com. Code Ch. 151 § 151.102 voids construction-contract
  // indemnities that cover the indemnitee's own negligence (with
  // narrow insurance-policy exceptions); the rule surfaces the
  // void-on-its-face exposure that the Texas-law clause inherits.
  // MSA-010 (NY anti-indemnity) also fires because its
  // construction-indemnity pattern is jurisdiction-neutral, but
  // MSA-029 is the load-bearing detector for the Texas failure mode.
  "msa-vendor-deep-tx-construction-indemnity-fail.txt": ["MSA-029"],

  // BAA with the "Minimum Necessary" paragraph removed entirely;
  // every other clause (Permitted Uses, Safeguards, Reporting,
  // Subcontractor Flow-Down, Access/Amendment/Accounting, Books and
  // Records, Return or Destruction, Mitigation, Workforce Training,
  // Encryption, Risk Assessment, Sanctions, Subcontractor List,
  // Governing Law, Notice, Term) is preserved so BAA-001..028 / 030+
  // baseline still passes where it was passing. **BAA-029 (warning)**
  // fires — its present_patterns require `minimum\s+necessary` or
  // `164\.502\(b\)`; neither match, so the rule reports the
  // 45 C.F.R. § 164.502(b) minimum-necessary anchor missing. Without
  // the recital the BA has no contractual hook to limit downstream
  // PHI requests, breaking the use/disclosure narrowing the Privacy
  // Rule contemplates.
  "baa-missing-minimum-necessary-fail.txt": ["BAA-029"],

  // CCPA Service-Provider Addendum with §3(d) (the no-combining-
  // with-other-data restriction) removed and the §3 enumeration
  // ending at (c); every other anchor for the combining prohibition
  // — `combin\w+\s+(personal\s+information|the\s+personal\s+data)`,
  // `7050\(c\)`, or `other\s+sources` — is absent from the rest of
  // the document so no other paragraph supplies the missing recital.
  // Sections 4 (Certification), 5 (Consumer Rights Assistance), 6
  // (Subprocessors), 7 (Security), 8 (Deletion or Return), and 9
  // (Audit) are preserved so the rest of the USDPA-001..025 baseline
  // still passes where it was passing. **USDPA-004 (warning)** fires
  // — Cal. Civ. Code § 1798.140(ag)(1)(D) requires the service-
  // provider contract to prohibit combining the business's Personal
  // Information with data the service provider receives from or
  // collects in connection with any other person, business, or
  // direct consumer interaction (except as 11 C.C.R. § 7050(c)
  // narrowly permits); a contract silent on combining leaves the
  // business exposed to enforcement risk under § 1798.155 if the
  // service provider augments the data with off-platform signals.
  "dpa-ccpa-service-provider-missing-no-combining-restriction-fail.txt": ["USDPA-004"],

  // SCC Module 2 with §8.6 (Onward Transfers) removed entirely and
  // the subsequent §8.7 ("Processing Under Authority of Data
  // Exporter") renumbered to §8.6; every anchor for the onward-
  // transfer recital — `onward\s+transfer`, `clause\s+8\.7`, or
  // `clause\s+8\.8` — is absent from the rest of the document so
  // no other paragraph supplies the missing reference. Clauses 8.1
  // through 8.5, 9, 10, 11, 12, 14, 15, 16, the docking clause, and
  // the three annexes are preserved so the rest of the TRANSFER-001
  // ..019 baseline still passes where it was passing. **TRANSFER-020
  // (warning)** fires — EU SCCs Clause 8.7 / 8.8 governs onward
  // transfers of personal data to third parties outside the EEA; an
  // SCC Module 2 transfer arrangement that is silent on onward-
  // transfer terms leaves the data exporter without a contractual
  // mechanism to ensure that downstream recipients are bound by
  // equivalent safeguards, defeating the Article 46 Schrems II
  // protection chain.
  "scc-module-2-missing-onward-transfer-terms-fail.txt": ["TRANSFER-020"],

  // BAA with the "Mitigation" paragraph removed entirely; every
  // other clause (Permitted Uses, Safeguards, Reporting,
  // Subcontractor Flow-Down, Access/Amendment/Accounting, Books and
  // Records, Return or Destruction, Minimum Necessary, Workforce
  // Training, Encryption, Risk Assessment, Sanctions, Subcontractor
  // List, Governing Law, Notice, Term) is preserved so the rest of
  // the BAA baseline still passes where it was passing.
  // **BAA-030 (critical)** fires — its present_patterns require
  // `(mitigate|mitigation).*?(harm|effect|disclosure|use)`; with
  // the paragraph gone, no remaining text pairs a mitigate verb
  // with a harm/effect/disclosure/use object. 45 C.F.R. § 164.530(f)
  // requires covered entities to mitigate harmful effects of any
  // improper use or disclosure of PHI; the BA commonly inherits the
  // duty by flow-down, and its absence leaves the covered entity
  // with no contractual lever to compel mitigation when a BA leak
  // surfaces downstream harm.
  "baa-missing-mitigation-obligation-fail.txt": ["BAA-030"],

  // BAA with the "Workforce Training" paragraph removed entirely;
  // every other clause is preserved so the rest of the BAA baseline
  // still passes where it was passing. **BAA-031 (warning)** fires
  // — its present_patterns require `workforce\s+training`,
  // `HIPAA\s+training`, or `trained\s+on.{0,40}(HIPAA|PHI)`; with
  // the paragraph gone, no remaining text matches any of the three
  // anchors. 45 C.F.R. §§ 164.530(b) and 164.308(a)(5) require
  // workforce training on HIPAA / PHI handling; BAs are expected to
  // flow the obligation down to their personnel, and a contract
  // silent on training leaves the workforce-training pillar of the
  // Security Management Process unanchored at the BA layer.
  "baa-missing-workforce-training-fail.txt": ["BAA-031"],

  // BAA with the "Encryption" paragraph removed entirely; every
  // other clause is preserved so the rest of the BAA baseline still
  // passes where it was passing, and no other paragraph mentions
  // encryption, NIST 800, or FIPS 140 (the Safeguards paragraph
  // names §§ 164.308 / 164.310 / 164.312 but does not invoke an
  // encryption / NIST / FIPS anchor). **BAA-032 (warning)** fires
  // — its present_patterns require `encrypt(ion)?`, `NIST\s*800`,
  // or `FIPS\s*140`; with the paragraph gone, none match.
  // Encryption is an addressable specification under 45 C.F.R.
  // § 164.312(a)(2)(iv) / (e)(2)(ii) and the HITECH "safe harbor"
  // for breach notification under 42 U.S.C. § 17932(h); a BAA that
  // does not anchor encryption or an equivalent NIST 800-53 /
  // 800-66 standard leaves the BA without the safe-harbor lever and
  // pushes every incident onto the breach-notification timeline.
  "baa-missing-encryption-nist-fail.txt": ["BAA-032"],

  // BAA with the "Risk Assessment" paragraph removed entirely; the
  // Safeguards paragraph still cites 45 CFR §§ 164.308 / 164.310 /
  // 164.312 but never uses the words "risk assessment" or "risk
  // analysis," so no remaining text supplies the missing anchor.
  // Every other clause is preserved so the rest of the BAA baseline
  // still passes where it was passing. **BAA-033 (warning)** fires
  // — its present_patterns require `risk\s+(assessment|analysis)`;
  // with the paragraph gone, neither phrase appears anywhere in the
  // document. 45 C.F.R. § 164.308(a)(1)(ii)(A) requires a risk
  // analysis as part of the Security Management Process; a BAA
  // silent on the BA's risk-assessment cadence leaves the covered
  // entity without a contractual hook to verify the BA's compliance
  // with the foundational Security Rule control.
  "baa-missing-risk-assessment-fail.txt": ["BAA-033"],

  // BAA with the "Subcontractor List" paragraph removed entirely;
  // the Subcontractor Flow-Down paragraph (which uses "subcontractor"
  // / "agrees in writing" wording) is preserved so BAA-018 still
  // passes, but no remaining text uses `list\s+of\s+subprocessors`,
  // `list\s+of\s+subcontractors`, or `subprocessor.{0,60}
  // (disclos|maintain.*list)`. Every other clause is preserved so
  // the rest of the BAA baseline still passes where it was passing.
  // **BAA-035 (warning)** fires — although 45 C.F.R.
  // § 164.504(e)(2)(ii)(D) speaks to flow-down, modern BAAs require
  // disclosure of the subprocessor / subcontractor identity for
  // covered-entity vetting; a BAA that does not maintain a current
  // disclosed list leaves the covered entity unable to perform
  // downstream vendor due diligence as part of its own Security
  // Management Process.
  "baa-missing-subprocessor-list-fail.txt": ["BAA-035"],

  // BAA with the "Governing Law" paragraph rewritten to subordinate
  // HIPAA to state law: "This BAA shall be governed by the laws of
  // the State of New York. Notwithstanding any provision of HIPAA or
  // the HIPAA Rules to the contrary, in the event of any conflict
  // between the terms of this BAA and any provision of New York
  // state law, state law shall control...." Every other clause is
  // preserved so the rest of the BAA baseline still passes where it
  // was passing. **BAA-042 (warning)** fires — its first
  // bad_pattern matches `notwithstanding\s+(any\s+)?(provision\s+of\s+)?HIPAA`
  // and the second matches `state\s+law\s+(shall\s+)?controls?`;
  // both appear end-to-end in the rewritten clause. 45 C.F.R.
  // § 160.203 preempts contrary state law unless an exception
  // applies, so a "notwithstanding HIPAA" / "state law controls"
  // recital is unenforceable to the extent of HIPAA conflict and
  // signals the kind of careless drafting that produces operational
  // ambiguity in a breach-response scenario.
  "baa-state-law-overrides-hipaa-fail.txt": ["BAA-042"],

  // BAA with the "Effective Date: January 1, 2026." line removed
  // from the signature block; every other clause is preserved
  // (including the Term clause and the signature block's
  // "Signed by / Title / Date" lines) so the rest of the BAA
  // baseline still passes where it was passing. **BAA-037
  // (warning)** fires — its present_patterns require
  // `effective\s+date`; with the line gone, no remaining text
  // contains the phrase. An effective date anchors the timing rules
  // in the BAA (term, breach windows, termination) — without it the
  // 60-day breach-notification clock and the BAA's coterminous
  // relationship with the underlying MSA are ambiguous on their face.
  "baa-missing-effective-date-fail.txt": ["BAA-037"],

  // BAA with the "Governing Law" paragraph removed entirely; every
  // other clause is preserved so the rest of the BAA baseline still
  // passes where it was passing, and no other paragraph uses
  // `governing\s+law`, `governed\s+by\s+the\s+laws`, or
  // `laws\s+of\s+the\s+State\s+of`. **BAA-039 (warning)** fires —
  // although HIPAA is federal and the operative substantive rules
  // are preempted, BAAs typically include a governing-law clause to
  // anchor non-HIPAA contract disputes (indemnification, notice
  // mechanics, term, fee allocation). A BAA silent on governing law
  // leaves those non-HIPAA matters subject to default conflict-of-
  // laws analysis, which can produce a different jurisdiction than
  // the parties expect.
  "baa-missing-governing-law-fail.txt": ["BAA-039"],

  // BAA with the Reporting paragraph's "Unsecured PHI" downgraded
  // to plain "PHI" and the lowercase "breach" tokens kept; the
  // citation to 45 CFR § 164.410 is preserved (so the breach-
  // reporting baseline survives) but no remaining text uses
  // `unsecured\s+PHI`, `unsecured\s+protected\s+health\s+information`,
  // `164\.402`, or `breach\s+(means|shall\s+have)`. Every other
  // clause is preserved so the rest of the BAA baseline still
  // passes where it was passing. **BAA-044 (warning)** fires —
  // post-HITECH BAAs should track the modern defined terms "Breach"
  // (45 C.F.R. § 164.402) and "Unsecured PHI" (§ 164.402); a BAA
  // that talks about "breaches of PHI" without anchoring the
  // Unsecured-PHI / § 164.402 vocabulary leaves room for argument
  // that pre-HITECH definitions govern, which materially narrows
  // the covered entity's notification obligations under HITECH.
  "baa-missing-hipaa-current-definitions-fail.txt": ["BAA-044"],

  // Controller→processor GDPR DPA with the Controller-side
  // signatory's "Title: Data Protection Officer" line rewritten to
  // "Title: Privacy Lead"; every other clause is preserved so the
  // rest of the DPA-001..030 / 032+ baseline still passes where it
  // was passing, and no remaining text uses `data\s+protection\s+officer`,
  // `\bDPO\b`, or `article\s*37`. **DPA-031 (warning)** fires —
  // GDPR Article 37 requires the designation of a Data Protection
  // Officer in certain cases (public authorities, large-scale
  // systematic monitoring, special-category processing); modern
  // DPAs reference the DPO contact details so the controller-side
  // accountability under Art. 38–39 attaches to a named office. A
  // DPA silent on the DPO leaves the Art. 37/38/39 accountability
  // chain unsigned and the data-subject notification path
  // ambiguous.
  "dpa-controller-processor-missing-dpo-reference-fail.txt": ["DPA-031"],

  // Controller→processor GDPR DPA with Section 12 (Deletion or
  // Return at End of Services) rewritten from "Processor shall, at
  // the choice of Controller, delete or return..." to "Processor
  // may choose to delete or return all personal data to Controller
  // and shall delete existing copies...". The reversal moves the
  // deletion-or-return choice from the controller to the processor.
  // Every other clause is preserved so the rest of the DPA-001..030
  // baseline still passes where it was passing. **DPA-035
  // (critical)** fires — its first bad_pattern matches
  // `processor\s+(shall|may)\s+(choose|elect)\s+to\s+(delete|return)`
  // end-to-end. GDPR Art. 28(3)(g) explicitly assigns the deletion-
  // or-return election to the controller; vendor overreach
  // commonly inverts this, and the rule surfaces the inversion as a
  // load-bearing critical because the controller loses its
  // contractual ability to compel the post-termination remediation
  // posture that fits its own retention obligations.
  "dpa-controller-processor-deletion-choice-processor-fail.txt": ["DPA-035"],

  // Controller→processor GDPR DPA with the "Effective Date:
  // February 1, 2026." line removed from the signature block and
  // both inline "as of February 1, 2026," / "dated January 1, 2026"
  // anchors stripped from the preamble; every other clause is
  // preserved (including the Term-style "duration of the
  // processing corresponds to the term of the MSA" recital in §1)
  // so the rest of the DPA-001..030 baseline still passes where it
  // was passing. **DPA-044 (warning)** fires — its present_patterns
  // require `effective\s+date`; with the anchor gone, no remaining
  // text contains the phrase. An effective date anchors the
  // timing rules in the DPA (subject-matter window, breach-notice
  // clock, deletion-or-return 30-day timer); without it, the
  // Art. 28(3) intro requirement that the DPA define the duration
  // of processing is undischarged on the face of the document.
  "dpa-controller-processor-missing-effective-date-fail.txt": ["DPA-044"],

  // Controller→processor GDPR DPA with Section 2's heading
  // rewritten from "Categories of Personal Data and Data Subjects"
  // to "Categories of Personal Data and Types of Data Subjects"
  // and the body's "The categories of data subjects are..." line
  // rewritten to "The types of data subjects are..."; the rest of
  // the DPA is preserved so the DPA-001..030 baseline still passes
  // where it was passing, and no remaining text uses
  // `nature\s+of\s+the\s+(personal\s+data\s+)?breach`,
  // `categor(?:y|ies)\s+of\s+data\s+subjects`, `likely\s+consequences`,
  // or `measures\s+taken`. **DPA-026 (warning)** fires — GDPR
  // Art. 33(3) requires the breach notification to describe the
  // nature of the breach, the categories and approximate number of
  // data subjects affected, the DPO contact, the likely
  // consequences, and the measures taken; a DPA whose Section 10
  // recites only that Processor will provide "sufficient
  // information" without anchoring the Art. 33(3) content list
  // leaves the controller without a contractual hook to demand the
  // statutorily required elements when the BA hands over its
  // intake report.
  "dpa-controller-processor-missing-breach-content-elements-fail.txt": ["DPA-026"],

  // Controller→processor GDPR DPA with Section 10 (Breach
  // Notification) rewritten to a single sentence: "Processor shall
  // notify Controller of any personal data breach no later than 30
  // days after becoming aware of the breach, providing Controller
  // with sufficient information to allow it to meet its own
  // notification obligations under Articles 33 and 34 of the
  // GDPR." The 48-hour anchor is dropped in favor of a 30-day
  // window; every other clause is preserved so the rest of the
  // DPA-001..030 baseline still passes where it was passing.
  // **DPA-027 (warning)** fires — its first bad_pattern matches
  // `\b(within|no\s+later\s+than)\s+(?:1[0-9]|2[0-9]|3[0-9]|[4-9][0-9]|[1-9][0-9]{2,})\s+days?\b.{0,80}(breach|notif)`
  // end-to-end ("no later than 30 days after becoming aware of the
  // breach"). Although GDPR Art. 33(2) does not set a strict outer
  // bound for processor notification, supervisory guidance treats
  // anything beyond ~24–72 hours as suspect; a 30-day processor-
  // notification window leaves the controller no margin to meet
  // its own Art. 33 / 34 obligations and effectively shifts the
  // supervisory-notification clock entirely onto the controller.
  "dpa-controller-processor-breach-notice-30-day-window-fail.txt": ["DPA-027"],

  // Controller→processor GDPR DPA with Section 11 (Audit and
  // Inspection Rights) rewritten to keep the first information-
  // production sentence but replace the "allow for and contribute
  // to audits, including inspections" clause with "Processor's
  // annual SOC 2 Type II report shall satisfy Controller's audit
  // rights under this DPA in lieu of any on-site inspection, and
  // the SOC 2 Type II report shall be the sole means of verifying
  // Processor's compliance with this Section." Every other clause
  // is preserved so the rest of the DPA-001..030 baseline still
  // passes where it was passing. **DPA-036 (warning)** fires —
  // its first bad_pattern matches `(SOC\s*2|ISO\s*27001).{0,160}
  // (in\s+lieu\s+of|shall\s+(satisfy|fulfill|fulfil)|the\s+sole\s+means)`
  // (both `shall satisfy` and `in lieu of` / `sole means` anchors
  // are present) end-to-end. GDPR Art. 28(3)(h) requires the
  // processor to allow for and contribute to audits; SOC 2 / ISO
  // substitution is permitted as a default, but it must not
  // eliminate the controller's right to an on-site audit on
  // reasonable cause, and a contract that designates SOC 2 as the
  // "sole means" of verification breaches the statutory floor.
  "dpa-controller-processor-soc2-eliminates-audit-fail.txt": ["DPA-036"],

  // Controller→processor GDPR DPA with Section 4 (Documented
  // Instructions Only) augmented with an injected sentence:
  // "Notwithstanding the foregoing, Processor may deviate from
  // Controller's instructions where, in Processor's reasonable
  // judgment, such deviation is necessary or appropriate to
  // operate the Services, and Processor shall not be required to
  // seek prior approval from Controller before doing so." Every
  // other clause is preserved so the rest of the DPA-001..030
  // baseline still passes where it was passing. **DPA-037
  // (warning)** fires — its first bad_pattern matches
  // `processor\s+may\s+(deviate|depart)\s+from` end-to-end. GDPR
  // Art. 28(3)(a) requires processing only on documented
  // instructions from the controller; any deviation must be
  // required by law and the processor must inform the controller
  // — a unilateral "Processor may deviate" license collapses the
  // statutory accountability chain and removes the controller's
  // ability to direct the processing.
  "dpa-controller-processor-instructions-deviation-fail.txt": ["DPA-037"],

  // Controller→processor GDPR DPA with a new Section 14
  // ("Indemnification") appended: "Controller shall indemnify,
  // defend, and hold harmless Processor and its officers,
  // directors, and employees from and against any GDPR fines,
  // penalties, administrative sanctions, supervisory-authority
  // claims, and related defense costs arising out of or relating
  // to the processing of personal data under this DPA, regardless
  // of the underlying cause or the party at fault." Every other
  // clause is preserved so the rest of the DPA-001..030 baseline
  // still passes where it was passing. **DPA-048 (warning)**
  // fires — its first bad_pattern matches
  // `controller\s+(shall|will)\s+indemnif.*?(processor|GDPR|fine)`
  // end-to-end (both "Processor" and "GDPR" / "fine" anchors are
  // within the matched span). Under GDPR Art. 82, a processor
  // remains liable for its own infringements; shifting that
  // liability to the controller through an unconditional
  // indemnity is vendor overreach and may be unenforceable to the
  // extent it purports to absolve the processor of supervisory-
  // authority sanctions attributable to its own conduct.
  "dpa-controller-processor-controller-indemnifies-gdpr-fines-fail.txt": ["DPA-048"],

  // Controller→processor GDPR DPA with Section 11 (Audit and
  // Inspection Rights) augmented with an injected closing sentence:
  // "Controller shall bear all costs of any audit conducted under
  // this Section, including any audit that uncovers a material
  // breach by Processor." Every other clause is preserved so the
  // rest of the DPA-001..030 baseline still passes where it was
  // passing. **DPA-049 (warning)** fires — its first bad_pattern
  // matches `controller\s+(shall|will)\s+bear\s+(all|the\s+entire|the\s+full)\s+costs?\s+of\s+(any\s+)?audit`
  // end-to-end. Standard practice under GDPR Art. 28(3)(h) splits
  // routine-audit cost to the controller but allocates cost to the
  // processor where the audit uncovers material breach; a clause
  // that fixes the entire audit cost on the controller — including
  // breach-confirmed audits — discourages the controller from ever
  // exercising the audit right and effectively immunizes processor
  // non-compliance.
  "dpa-controller-processor-audit-cost-controller-exclusive-fail.txt": ["DPA-049"],

  // Controller→processor GDPR DPA with Section 6 (Security Measures
  // (Article 32 GDPR)) augmented with an injected closing sentence:
  // "To the extent any of the foregoing cannot be operationally
  // implemented, Processor shall instead apply commercially reasonable
  // security measures consistent with prevailing market practice for
  // service providers of similar size and scope." Every other clause
  // is preserved so the rest of the DPA-001..030 baseline still
  // passes where it was passing. **DPA-023 (warning)** fires — its
  // first bad_pattern matches `commercially\s+reasonable\s+(security|measures)`
  // end-to-end. GDPR Art. 32 requires measures appropriate to the
  // risk; "commercially reasonable" or "industry-standard" language
  // without a specific Annex of technical and organisational measures
  // is the hand-waving the regulator has criticised, because it
  // shifts the substantive duty from a defined set of controls to
  // whatever the processor's market peers happen to be doing.
  "dpa-controller-processor-hand-waving-security-language-fail.txt": ["DPA-023"],

  // Controller→processor GDPR DPA with Section 2 (Categories of
  // Personal Data and Data Subjects) rewritten to reference "the
  // Categories of Personal Data Section" at the end of the DPA
  // instead of "Annex I"; the Annex I heading at the end of the DPA
  // is likewise renamed to "Categories of Personal Data" with no
  // "Annex I" / "Appendix I" / "Schedule I" / "Exhibit I" prefix.
  // Every other clause is preserved so the rest of the
  // DPA-001..030 baseline still passes where it was passing.
  // **DPA-038 (warning)** fires — its present_pattern
  // `(annex|appendix|exhibit|schedule)\s+(I|1|A)` is no longer
  // matched anywhere in the document. SCC Annex I (and the modern
  // DPA convention of an Annex describing the parties, transfer
  // scope, and processing operations) anchors the description of
  // the personal-data scope; without a labelled annex/appendix the
  // document loses the canonical attachment that supervisory
  // authorities and downstream subprocessors look to when scoping
  // the processing.
  "dpa-controller-processor-missing-personal-data-annex-fail.txt": ["DPA-038"],

  // Controller→processor GDPR DPA with the entire signature block
  // (party headers + "Signed by:" lines + "Title:" lines including
  // "Authorized Representative" + "Date:" lines) replaced with a
  // single recital paragraph: "This DPA is executed on behalf of
  // Globex Inc. (Controller) and Wayne Enterprises LLC (Processor)
  // through their respective representatives, with execution
  // evidenced solely by reference to the MSA cover page; no separate
  // execution lines, witness lines, or attestation blocks are
  // included in this DPA." Every other clause (including "Effective
  // Date: February 1, 2026.") is preserved so the rest of the
  // DPA-001..030 baseline still passes where it was passing.
  // **DPA-043 (warning)** fires — its present_pattern
  // `By:\s*[_\-\s]+|signature\s+block|authori[sz]ed\s+(signatory|representative)|sign(ed)?\s+by`
  // is no longer matched anywhere in the document. GDPR Art. 28(9)
  // requires the DPA to be in writing including in electronic form;
  // a signature block — even on an electronic agreement — is the
  // canonical evidence-of-execution artefact that supervisory
  // authorities and counter-parties look to when establishing that
  // the obligations attached to a named, authorised representative
  // of each party.
  "dpa-controller-processor-missing-signature-block-fail.txt": ["DPA-043"],

  // Controller→processor GDPR DPA with the two "written contract" /
  // "in writing" anchors stripped: Section 7's "by way of a written
  // contract" is rewritten as "via a duly executed contractual
  // instrument" and Section 12's "shall certify such deletion in
  // writing" is rewritten as "shall certify such deletion by formal
  // notice to Controller". Every other clause is preserved so the
  // rest of the DPA-001..030 baseline still passes where it was
  // passing. **DPA-018 (warning)** fires — its present_pattern
  // `(in\s+writing|electronic\s+form|written\s+(contract|agreement))`
  // is no longer matched anywhere in the document. GDPR Art. 28(9)
  // requires the contract to be in writing, including in electronic
  // form; a DPA that never says so on its face leaves the form
  // requirement ambiguous and removes the canonical statutory anchor
  // that supervisory authorities and counter-parties look to when
  // establishing the contract's compliance with Art. 28(9).
  "dpa-controller-processor-missing-form-of-agreement-fail.txt": ["DPA-018"],

  // Controller→processor GDPR DPA with Section 13 rewritten from
  // "Cross-Border Transfers and EU SCCs" (which named the EU SCCs
  // under Commission Implementing Decision (EU) 2021/914, Module
  // Two) to a generic "Cross-Border Movement of Personal Data"
  // paragraph that complies with applicable law and supplemental
  // documentation but does not name any Chapter V mechanism (no
  // "international transfer" / "Chapter V" / "Standard Contractual
  // Clauses" / "SCCs" / "adequacy decision" / "Binding Corporate
  // Rules" / "BCRs"). Section 4's "transfers of personal data to a
  // third country or an international organization" is rewritten to
  // "onward movement of personal data to a third country or an
  // international organization" to avoid the "international
  // transfer" anchor. Every other clause is preserved so the rest of
  // the DPA-001..030 baseline still passes where it was passing.
  // **DPA-032** fires — its present_pattern
  // `(international\s+transfer|chapter\s+V|standard\s+contractual\s+clauses|\bSCCs?\b|adequacy\s+decision|binding\s+corporate\s+rules|\bBCRs?\b)`
  // is no longer matched anywhere in the document. (DPA-033 also
  // fires because the SCC-incorporation anchor is gone, but DPA-032
  // is the load-bearing rule for this fixture; DPA-033 has its own
  // negative-path coverage at the ruleset-test level.) GDPR Arts.
  // 44–49 require an adequacy decision, SCCs, BCRs, or a derogation
  // for transfers to third countries — generic "comply with
  // applicable law" prose collapses the Chapter V mechanism into a
  // black box and removes the named anchor regulators rely on to
  // assess transfer lawfulness.
  "dpa-controller-processor-missing-transfer-mechanism-fail.txt": ["DPA-032"],

  // Controller→processor GDPR DPA with Section 12 ("Deletion or
  // Return at End of Services") rewritten as "Records at End of
  // Services. Upon termination of the MSA for any reason, Processor
  // shall, at the choice of Controller, provide Controller with an
  // inventory of personal data still held by Processor and the basis
  // on which it is retained, unless applicable law requires
  // retention of the personal data. Processor shall certify the
  // accuracy of such inventory in writing within thirty (30) days of
  // termination." The "delete or return" / "return or delete"
  // anchors are eliminated, and "in writing" is preserved so DPA-018
  // still passes. Every other clause is preserved so the rest of the
  // DPA-001..030 baseline still passes where it was passing.
  // **DPA-013 (critical)** fires — its present_pattern
  // `(delete\s+or\s+return|return\s+or\s+delete).*?(personal\s+data|end\s+of\s+(?:the\s+)?(?:provision\s+of\s+)?services)`
  // is no longer matched anywhere in the document. GDPR Art. 28(3)(g)
  // requires the processor, at the choice of the controller, to
  // delete or return all personal data to the controller after the
  // end of the provision of services — an "inventory and basis for
  // retention" substitute leaves the personal data on the
  // processor's systems and inverts the statutory default.
  "dpa-controller-processor-missing-deletion-or-return-fail.txt": ["DPA-013"],

  // Controller→processor GDPR DPA with Section 13 retitled
  // "International Transfers Under Chapter V" and rewritten so the
  // section preserves the Chapter V naming (so DPA-032 stays
  // satisfied) — keeping "international transfer", "Chapter V",
  // "adequacy decision", and "binding corporate rules" anchors —
  // but no longer names the EU SCCs by reference, Commission
  // Implementing Decision (EU) 2021/914, or Module Two. Every
  // other clause is preserved so the rest of the DPA-001..030
  // baseline still passes where it was passing. **DPA-033 (warning)**
  // fires — its present_pattern `(2021\/914|standard\s+contractual\s+clauses|EU\s+SCCs?)`
  // is no longer matched anywhere in the document. Commission
  // Implementing Decision (EU) 2021/914 requires the parties to use
  // the SCC template for in-scope transfers; a DPA that gestures at
  // Chapter V without naming the SCC mechanism leaves the parties
  // without the canonical transfer scaffold the Commission
  // designated for controller-to-processor flows.
  "dpa-controller-processor-missing-eu-sccs-incorporation-fail.txt": ["DPA-033"],

  // Controller→processor GDPR DPA with the preamble's "limited
  // liability company" rewritten as "limited company" (so no
  // "liability" anchor remains incidentally) and Section 7's "shall
  // remain fully liable to Controller" rewritten as "shall remain
  // fully responsible to Controller". Every other clause is
  // preserved so the rest of the DPA-001..030 baseline still passes
  // where it was passing. **DPA-047 (warning)** fires — its
  // present_pattern `(liability|indemnif|article\s*82)` is no longer
  // matched anywhere in the document. GDPR Art. 82 makes both
  // Controller and Processor potentially liable to data subjects;
  // DPAs are expected to allocate that liability between the parties
  // (an indemnity, a contribution scheme, or an Article 82
  // reference) so the contractual residue is well defined.
  "dpa-controller-processor-missing-liability-allocation-fail.txt": ["DPA-047"],

  // Controller→processor GDPR DPA with every "termination" /
  // "terminate" anchor stripped: Section 1's "Processing shall cease
  // upon termination of the MSA" → "upon expiry or wind-down of the
  // MSA"; "duration of the processing corresponds to the term of the
  // MSA" → "during which the MSA is in force"; Section 12's "Upon
  // termination of the MSA" → "Upon expiry or wind-down of the MSA";
  // "thirty (30) days of termination" → "thirty (30) days following
  // expiry or wind-down of the MSA". Every other clause is preserved
  // so the rest of the DPA-001..030 baseline still passes where it
  // was passing. **DPA-045 (warning)** fires — its present_pattern
  // `(term\s+of\s+(this\s+)?agreement|initial\s+term|termination|terminate)`
  // is no longer matched anywhere in the document. GDPR Art. 28(3)(g)
  // anchors the end-of-services duties on a defined term and
  // termination event; a DPA that never says "term" or "termination"
  // makes the temporal scope of every post-termination duty
  // (deletion, return, audit cooperation, survival) ambiguous.
  "dpa-controller-processor-missing-term-and-termination-fail.txt": ["DPA-045"],

  // Multi-state US DPA with every "documented instructions" anchor
  // (Sections 3, 5, and 6) rewritten as "express contractual
  // directions" (Section 3) / "the express contractual directions
  // Controller has set forth in the MSA and any annex thereto"
  // (Sections 5 and 6). Section 5's "any instruction that
  // constitutes a violation" becomes "any direction that
  // constitutes a violation" so the "instructions"-family anchor
  // disappears completely. Every other clause is preserved so the
  // rest of the USDPA-001..025 baseline still passes where it was
  // passing. **USDPA-011** fires — its present_pattern
  // `(processing\s+instructions|instructions\s+for\s+processing|documented\s+instructions)`
  // is no longer matched anywhere in the document. Every US state
  // privacy statute (CCPA, VCDPA, CPA, CTDPA, UCPA) requires the
  // processor / service-provider contract to set out the
  // controller's processing instructions; a DPA that rephrases the
  // anchor as "contractual directions" leaves a regulator and the
  // controller without the canonical statutory hook.
  "dpa-multi-state-us-missing-processing-instructions-fail.txt": ["USDPA-011"],

  // Multi-state US DPA with the consumer-rights anchors in Section
  // 8 rewritten so no "opt-out" / "opt out" / "consumer rights
  // request" / "access request" / "deletion request" /
  // "right to access|delete|opt-out|correct" pattern matches:
  // section title becomes "Consumer Requests Assistance" (was
  // "Consumer Rights Assistance"), enumerated rights become
  // "review of personal information", "erasure of personal
  // information", "correction of inaccurate personal information",
  // "portability of personal information", and "the consumer's
  // ability to decline sale or sharing". Section 4 also rewrites
  // "consumer rights requests" → "consumer requests". Every other
  // clause is preserved so the rest of the USDPA-001..025 baseline
  // still passes where it was passing. **USDPA-023 (warning)**
  // fires — its present_pattern is no longer matched anywhere in
  // the document. State privacy statutes all confer consumer rights
  // (access / deletion / correction / portability / opt-out of
  // sale or sharing); a DPA that gestures at "consumer requests"
  // generically without using the statutory anchor language leaves
  // the operational handoff between controller and processor
  // unanchored to the underlying right.
  "dpa-multi-state-us-missing-consumer-rights-process-fail.txt": ["USDPA-023"],

  // AI Addendum with Section 3 retitled "Affirmative Consent for AI
  // Processing" (was "Opt-In for AI Processing"), "affirmatively
  // opted in" rewritten as "affirmatively consented", and "Opt-out
  // consent mechanisms" rewritten as "Negative-consent mechanisms"
  // so no "opt-in" / "opt-out" / "on by default" / "enabled by
  // default" anchor remains; no "AI features" / "AI functions" /
  // "generative features" anchor exists in the fixture; and the
  // fixture's "third-party foundational model" does not match the
  // strict `third[- ]party\s+(?:provider|model|host)` shape. Every
  // other clause is preserved so the rest of the ADDENDA-010..016
  // baseline still passes where it was passing. **ADDENDA-012
  // (warning)** fires — its present_patterns are no longer matched
  // anywhere in the document. EU AI Act Article 50 + FTC
  // consumer-protection posture both require clear disclosure of
  // which features use AI, whether on by default or opt-in, and
  // whether the model is on-prem or third-party-hosted; a vendor
  // AI addendum that says "Affirmative Consent" without naming the
  // features or the hosting posture leaves customers unable to
  // audit the AI use surface.
  "ai-addendum-missing-transparency-disclosures-fail.txt": ["ADDENDA-012"],

  // BAA with the closing signature block ("Signed by: ___" /
  // "Title: Authorized Representative" / "Date: January 1, 2026")
  // replaced with a single recital paragraph: "This BAA is
  // executed by the Parties through their respective duly empowered
  // officers, with execution evidenced solely by reference to the
  // cover page of the Master Services Agreement; no separate
  // execution lines, witness lines, or attestation blocks are
  // included in this BAA." Every other clause (including
  // "Effective Date: January 1, 2026.") is preserved so the rest
  // of the BAA-001..045 baseline still passes where it was passing.
  // **BAA-036 (warning)** fires — its present_pattern
  // `By:\s*[_\-\s]+|signature\s+block|authorized\s+(signatory|representative)|sign(ed)?\s+by`
  // is no longer matched anywhere in the document. 45 CFR
  // § 164.504(e)(5) requires the covered entity to obtain
  // satisfactory assurances through a written contract — a signed
  // instrument; a BAA that gestures at execution without a
  // signature block leaves the named, authorised representative
  // of each party unidentified.
  "baa-missing-signature-block-fail.txt": ["BAA-036"],

  // Mutual NDA-Deep with Section 3 (Permitted Purpose and Use
  // Restriction) rewritten so the only anchor that previously
  // satisfied NDA-D-023 ("third party without the prior written
  // consent of the Disclosing Party") is replaced with "third
  // party absent the Disclosing Party's prior written approval".
  // "without" → "absent" and "consent" → "approval" so neither
  // `successors\s+and\s+assigns` nor `(may\s+not\s+assign|shall\s+not\s+assign|without.{0,40}consent)`
  // is matched anywhere in the document. Every other clause is
  // preserved so the rest of the NDA-D-001..025 baseline still
  // passes where it was passing. **NDA-D-023 (warning)** fires —
  // its present_patterns are no longer matched anywhere in the
  // document. Without a consent-to-assignment / successors-and-
  // assigns clause, an acquirer of the receiving party could
  // inherit access to Confidential Information without the
  // discloser's approval; the rule flags the missing scaffold.
  "mutual-nda-deep-missing-assignment-consent-fail.txt": ["NDA-D-023"],

  // AI Addendum with every "human review" / "human reviewer" /
  // "Human-in-the-Loop" anchor stripped: Section 1's "human review
  // and revision" → "qualified-workforce review and revision";
  // Section 4's "whether human review was completed" → "whether
  // qualified-workforce review was completed"; Section 5 retitled
  // "Qualified-Workforce Checkpoint" (was "Human-in-the-Loop
  // Checkpoint") and "qualified human member of Vendor's
  // workforce" → "qualified workforce member of Vendor", "human
  // reviewer" → "reviewer"; Section 10 "human-reviewer
  // documentation" → "reviewer documentation". No
  // "hallucinat" / "inaccurate output" / "not fit for" / "not
  // (professional|legal|medical|financial) advice" anchor exists
  // in the fixture either. Every other clause is preserved so the
  // rest of the ADDENDA-010..016 baseline still passes where it
  // was passing. **ADDENDA-014 (info)** fires — its
  // present_patterns are no longer matched anywhere in the
  // document. NIST AI RMF and practitioner posture both expect a
  // hallucination-risk acknowledgment and a human-review
  // obligation for high-stakes outputs; an AI addendum that
  // gestures at "qualified-workforce review" without flagging
  // hallucination risk or naming human oversight leaves customers
  // without the canonical AI-risk anchor.
  "ai-addendum-missing-hallucination-and-human-review-fail.txt": ["ADDENDA-014"],

  // Processor→subprocessor GDPR DPA with the closing signature
  // block ("Signed by: ___" / "Title: Authorized Representative" /
  // "Date: February 1, 2026") replaced with a single recital
  // paragraph: "This Agreement is executed on behalf of Globex EU
  // SARL (Upstream Processor) and Stark Cloud Ireland Ltd.
  // (Subprocessor) through their respective representatives, with
  // execution evidenced solely by reference to the MSA cover page;
  // no separate execution lines, witness lines, or attestation
  // blocks are included in this Sub-Processing Agreement." Every
  // other clause is preserved so the rest of the DPA-001..030
  // baseline still passes where it was passing. **DPA-043
  // (warning)** fires — its present_pattern
  // `By:\s*[_\-\s]+|signature\s+block|authori[sz]ed\s+(signatory|representative)|sign(ed)?\s+by`
  // is no longer matched anywhere in the document. This is the
  // dpa-processor-subprocessor playbook variant of the
  // controller-processor signature-block fixture; the rule's
  // statutory anchor (GDPR Art. 28(9) writing requirement) applies
  // identically across both playbooks.
  "dpa-processor-subprocessor-missing-signature-block-fail.txt": ["DPA-043"],

  // BA→Subcontractor BAA with the closing signature block replaced
  // with a single recital paragraph: "This Subcontractor BAA is
  // executed by the Parties through their respective duly empowered
  // officers, with execution evidenced solely by reference to the
  // cover page of the Master Services Agreement; no separate
  // execution lines, witness lines, or attestation blocks are
  // included in this Subcontractor BAA." Every other clause
  // (including "Effective Date: January 1, 2026.") is preserved so
  // the rest of the BAA-001..045 baseline still passes where it
  // was passing. **BAA-036 (warning)** fires — its present_pattern
  // is no longer matched anywhere in the document. This is the
  // baa-subcontractor playbook variant of the BAA signature-block
  // fixture; the rule's statutory anchor (45 CFR § 164.504(e)(5)
  // satisfactory-assurances writing requirement) applies
  // identically across the primary BAA and the subcontractor BAA.
  "baa-subcontractor-missing-signature-block-fail.txt": ["BAA-036"],

  // Unilateral NDA-Deep with Section 4 ("No License") rewritten as
  // "4. Scope of Use. Nothing in this Agreement shall be deemed to
  // confer to the Receiving Party any interest, right, title, or
  // other entitlement in or to the Disclosing Party's Confidential
  // Information beyond the limited authorization to use such
  // information solely for the Permitted Purpose and in accordance
  // with the terms of this Agreement." The "No License" header is
  // removed entirely so the regex `no\s+license` no longer matches
  // anywhere in the document. "Nothing in this Agreement shall be
  // deemed to confer" is intentionally not matched by the
  // alternative pattern `(does\s+not\s+(grant|convey|transfer)|shall\s+not\s+be\s+construed.{0,40}license)`.
  // Every other clause is preserved so the rest of the
  // NDA-D-001..025 baseline still passes where it was passing.
  // **NDA-D-021** fires — its present_patterns are no longer
  // matched anywhere in the document. This is the
  // unilateral-nda-deep playbook variant of the mutual-NDA
  // no-license fixture; without a one-line denial of license,
  // disclosure could be construed to grant an implied license in
  // the Confidential Information.
  "unilateral-nda-deep-missing-no-license-clause-fail.txt": ["NDA-D-021"],

  // BAA with a "Compliance Verification" paragraph that explicitly
  // disclaims any on-site or remote inspection privileges and
  // designates the BA's annual SOC 2 Type II report as the "sole
  // means" of verifying compliance; the document contains no
  // "audit rights", "right to audit", "reasonable audit", or
  // "conduct ... audit" anchor anywhere. Every other clause
  // (Permitted Uses, Safeguards, Reporting, Subcontractor
  // Flow-Down, Access/Amendment/Accounting, Books/Records,
  // Return/Destruction, Minimum Necessary, Mitigation, Workforce
  // Training, Encryption, Risk Assessment, Sanctions, Subcontractor
  // List, Governing Law, Notice, Term with explicit "shall survive
  // termination") is preserved so the rest of the BAA baseline
  // still passes where it was passing. **BAA-026 (warning)** fires
  // — its present_patterns are no longer matched anywhere in the
  // document. HHS guidance encourages audit rights as a substantive
  // complement to the books-and-records access requirement; without
  // audit rights the covered entity has no contractual mechanism
  // to verify ongoing HIPAA compliance beyond the books-and-records
  // floor.
  "baa-missing-audit-rights-fail.txt": ["BAA-026"],

  // BAA that uses "Protected Health Information" throughout but
  // never defines the term locally and never cross-references the
  // HIPAA definition; the Definitions section only says
  // "Capitalized terms used but not defined in this BAA carry the
  // meaning given to them in the Master Services Agreement" with
  // no "Protected Health Information ... means", "PHI ... shall
  // have the meaning", or "45 CFR § 160.103" anchor anywhere. Every
  // other clause is preserved so the rest of the BAA baseline still
  // passes where it was passing. **BAA-028 (warning)** fires — its
  // present_patterns are no longer matched anywhere in the
  // document. 45 C.F.R. § 160.103 defines PHI and ePHI; drafters
  // should either define these terms locally or incorporate the
  // HIPAA definition by reference. A BAA that uses "Protected
  // Health Information" without anchoring the regulatory definition
  // leaves the scope of the obligation ambiguous when the term is
  // later asserted to cover (or not cover) a borderline category
  // of data.
  "baa-missing-phi-definition-fail.txt": ["BAA-028"],

  // BAA with the Term clause rewritten to make every right and
  // duty of the parties terminate fully upon termination, with the
  // sole carve-out being a 30-day completion window for the
  // return-or-destruction obligation; the document contains no
  // "survive termination", "shall survive", or "survival" anchor
  // anywhere (the rewrite says the return-or-destruction obligation
  // "thereafter terminates without further continuing effect"
  // rather than the customary "shall survive"). Every other clause
  // is preserved so the rest of the BAA baseline still passes where
  // it was passing. **BAA-043 (warning)** fires — its
  // present_patterns are no longer matched anywhere in the
  // document. 45 C.F.R. § 164.504(e)(2)(ii)(I) and HHS guidance
  // expect HIPAA obligations to survive termination for any PHI
  // retained after termination; a BAA whose Term clause sweeps
  // every obligation to a clean cut-off leaves the covered entity
  // with no contractual hook for retained-PHI handling after the
  // commercial relationship ends.
  "baa-missing-survival-clause-fail.txt": ["BAA-043"],

  // Mutual NDA-Deep with a complete Section 9 Injunctive Relief
  // clause (acknowledging irreparable harm and entitlement to
  // injunctive/equitable relief — so NDA-D-015 stays satisfied) but
  // with the customary bond-waiver sentence stripped; the closing
  // sentence of Section 9 says "Such injunctive relief shall be
  // available subject to the requirements imposed by the court of
  // competent jurisdiction, including any requirement that the
  // movant satisfy each element of the applicable preliminary-
  // injunction standard before relief issues." No "without bond",
  // "waive ... bond", "waived bond", "no bond", "posting of a
  // bond ... waived", or "security / surety" anchor appears
  // anywhere in the document. Every other clause is preserved so
  // the rest of the NDA-D-001..025 baseline still passes where it
  // was passing. **NDA-D-016 (warning)** fires — its present_patterns
  // `(without|waive[sd]?).{0,40}(bond|security|surety)` and
  // `(no\s+bond|posting\s+of\s+a\s+bond.{0,40}waived)` are no longer
  // matched anywhere in the document. Many courts require a movant
  // to post a bond as a condition of preliminary injunctive relief;
  // a contractual waiver smooths the emergency-motion path, and a
  // mutual NDA that names injunctive relief without waiving the
  // bond leaves a delay-and-cost lever on the table that a
  // determined leaker can exploit while disclosure is in flight.
  "mutual-nda-deep-missing-bond-waiver-fail.txt": ["NDA-D-016"],

  // CCPA Service-Provider Addendum that names the Service Provider
  // designation and recites the "same level of privacy protection"
  // standard from Cal. Civ. Code § 1798.140(ag) but never anchors
  // the use of Personal Information to the "specific business
  // purpose enumerated" framing required by § 1798.140(ag)(1)(B).
  // Section 2 ("Permitted Processing") rewrites the canonical
  // anchor as "solely as reasonably necessary and proportionate to
  // perform the Services described in the MSA" and Section 3(c)
  // generalizes the use-limitation to "any commercial purpose
  // other than performing the Services described in the MSA"; no
  // "specific business purpose", "enumerated", or "business
  // purpose enumerated" anchor appears anywhere in the document.
  // Every other clause is preserved so the rest of the
  // USDPA-001..025 baseline still passes where it was passing.
  // **USDPA-001 (warning)** fires — its present_pattern
  // `(?:specific\s+business\s+purpose|enumerated\s+(?:in\s+this\s+)?(?:contract|agreement)|business\s+purpose\s+enumerated)`
  // is no longer matched anywhere in the document. Cal. Civ. Code
  // § 1798.140(ag)(1)(B) requires the contract to prohibit the
  // service provider from retaining, using, or disclosing Personal
  // Information for any purpose other than the specific business
  // purpose enumerated; "reasonably necessary and proportionate"
  // language without the statutory anchor leaves the business
  // exposed to enforcement under § 1798.155 if the service
  // provider's processing drifts beyond the enumerated purpose
  // set.
  "dpa-ccpa-service-provider-missing-purpose-limitation-fail.txt": ["USDPA-001"],

  // Vendor Security Addendum with Section 1 rewritten from
  // certifications subsections (SOC 2 Type II + ISO 27001) to a
  // generic "written information-security program aligned with
  // prevailing industry practice" paragraph that delivers only an
  // executive summary on request; Section 6 ("Verification") is
  // rewritten to explicitly disclaim any customer-initiated audit
  // privilege and to forbid reliance on any third-party assurance
  // framework or certification scheme. The encryption, MFA, and
  // vulnerability-management sections are preserved (so ADDENDA-001
  // and ADDENDA-005 still pass), but no "right to audit",
  // "Customer ... audit", "SOC 2", "ISO 27001", "ISO/IEC 27001", or
  // "in lieu of (an) audit" anchor appears anywhere in the
  // document. Every other clause is preserved so the rest of the
  // ADDENDA-001..009 baseline still passes where it was passing.
  // **ADDENDA-003 (warning)** fires — its present_pattern
  // `(right\s+to\s+audit|customer.{0,40}audit|SOC\s*2|ISO\s*27001|ISO\s*\/IEC\s*27001|in\s+lieu\s+of\s+(?:an\s+)?audit)`
  // is no longer matched anywhere in the document. Customers must be
  // able to verify the vendor's security posture either directly
  // (audit) or via an independent attestation (SOC 2 / ISO 27001);
  // a "self-assessment plus executive summary" posture leaves the
  // customer with no enforceable verification mechanism.
  "vendor-security-addendum-missing-audit-or-soc2-fail.txt": ["ADDENDA-003"],

  // Vendor MSA with a Section 13 "Modifications and Forbearance"
  // paragraph that explicitly contemplates modification of the
  // operative terms through "mutual understanding evidenced
  // through ... subsequent course of dealing, including through
  // email exchanges, executed change orders, addenda, or any
  // combination of the foregoing methods" — without using the
  // word "amend" anywhere — and the second sentence frames
  // forbearance as "operative only for the specific instance"
  // and "shall not operate as a continuing relinquishment" without
  // ever saying "no waiver", "no failure", or "shall not be deemed
  // a waiver". Every other clause is preserved so the rest of the
  // MSA-001..030 baseline still passes where it was passing.
  // **MSA-025 (info)** fires — neither
  // `amend\w+.{0,40}(?:in\s+writing|written\s+(?:and\s+)?signed)`
  // nor `(?:no\s+(?:waiver|failure)|shall\s+not\s+be\s+deemed\s+a\s+waiver)`
  // matches anywhere in the document. A "course of dealing"
  // modification clause that condones email modifications and a
  // forbearance paragraph that omits the canonical no-waiver
  // formula together leave the vendor MSA without the two
  // commercial-baseline boilerplate hooks that prevent oral
  // modifications and unintentional waivers from becoming
  // litigation risks.
  "msa-vendor-deep-missing-amendment-no-waiver-fail.txt": ["MSA-025"],

  // SCC Module 2 transfer with a new "Reliance on Adequacy
  // Decision" paragraph that explicitly anchors the parties on the
  // EU-US Data Privacy Framework (DPF) adequacy decision
  // (Commission Implementing Decision (EU) 2023/1795) "for so long
  // as it remains in force" and explicitly disclaims any
  // contractual fallback: "the Parties have not agreed any
  // contingency or alternative transfer arrangement to be
  // implemented if the DPF adequacy decision is set aside,
  // withdrawn, struck down, or otherwise ceases to provide a
  // lawful transfer basis". No "adequacy decision is invalidated /
  // revoked", "fallback to SCC", or "substitute (transfer)
  // mechanism" anchor appears anywhere in the document. Every
  // other Module 2 clause + the three Annexes are preserved so
  // the rest of the TRANSFER-001..019 baseline still passes where
  // it was passing. **TRANSFER-018 (warning)** fires — its
  // present_pattern
  // `(adequacy\s+decision\s+is\s+(?:invalidated|revoked)|fallback\s+(?:to\s+)?SCC|substitute\s+(?:transfer\s+)?mechanism)`
  // is no longer matched anywhere in the document. GDPR Art. 45
  // adequacy decisions can be invalidated (Schrems I, Schrems II);
  // the DPF was itself the third successive adequacy mechanism for
  // EU-US transfers. A transfer arrangement that relies on the
  // DPF without anchoring a contractual fallback to SCCs / IDTA on
  // invalidation creates a "transfer cliff" the moment the DPF
  // decision is set aside.
  "scc-module-2-missing-adequacy-fallback-fail.txt": ["TRANSFER-018"],

  // CCPA Service-Provider Addendum that retains the specific-
  // business-purpose anchor (USDPA-001 stays satisfied via the
  // "Business Purpose enumerated in this Agreement" recital) and
  // the no-cross-context-advertising prohibition (USDPA-003 stays
  // satisfied), but Section 3(a) is rewritten to use "shall not
  // transfer Personal Information to any third party in exchange
  // for monetary or other valuable consideration" — avoiding the
  // statutory anchor language. Section 5's "opt-out of sale or
  // sharing of Personal Information" is rewritten as "opt-out of
  // cross-context behavioral advertising or the transfer of
  // Personal Information for monetary or other valuable
  // consideration" so no "sale of personal information" tail
  // remains. No "prohibited from selling", "no sale of personal
  // information", or "shall not sell personal information" anchor
  // appears anywhere in the document. Every other clause is
  // preserved so the rest of the USDPA-001..025 baseline still
  // passes where it was passing. **USDPA-002 (warning)** fires —
  // its present_pattern
  // `(prohibited\s+from\s+selling|no\s+sale\s+of\s+personal\s+information|shall\s+not\s+sell\s+personal\s+information)`
  // is no longer matched anywhere in the document. Cal. Civ. Code
  // § 1798.140(ag)(1)(A) requires the service-provider contract
  // to expressly prohibit sale of Personal Information; a clause
  // that paraphrases the obligation as "shall not transfer for
  // monetary consideration" tracks the underlying definition of
  // "sale" at § 1798.140(ad) but loses the canonical anchor a
  // regulator searches for when establishing CCPA compliance.
  "dpa-ccpa-service-provider-missing-no-sale-prohibition-fail.txt": ["USDPA-002"],

  // Mutual NDA-Deep with a new Section 12 "Course of Dealing"
  // paragraph that does the opposite of a no-precedent clause: it
  // expressly states that "the substantive provisions of this
  // Agreement reflect the established baseline against which the
  // Parties intend to evaluate, draft, and benchmark any future
  // commercial agreement between them concerning the subject
  // matter hereof, and the deal-equivalent commercial terms reached
  // under this Agreement shall inform the Parties' subsequent
  // negotiations of any related downstream arrangement." No "no
  // precedent", "not create a precedent", "not constitute a
  // precedent", or "most favored nation" anchor appears anywhere
  // in the document. Every other clause (DTSA notice, perpetual
  // trade-secret carve-out, no-license, injunctive relief with
  // bond waiver, governing law, entire agreement) is preserved so
  // the rest of the NDA-D-001..025 baseline still passes where it
  // was passing. **NDA-D-019 (info)** fires — its present_pattern
  // `(no\s+precedent|not\s+(create|constitute)\s+a\s+precedent|most\s+favored\s+nation)`
  // is no longer matched anywhere in the document. A
  // course-of-dealing clause that affirmatively designates the NDA
  // as the commercial benchmark for future agreements is the
  // structural opposite of a no-precedent clause and exposes the
  // discloser to MFN-style argumentation if it later negotiates a
  // tighter NDA with a different counterparty under different
  // commercial assumptions.
  "mutual-nda-deep-missing-no-precedent-fail.txt": ["NDA-D-019"],

  // SCC Module 2 transfer with Clauses 1, 2, 8, 9, 11, 14, 15, and
  // 16 explicitly anchored — and Clause 10 (Data Subject Rights)
  // and Clause 12 (Liability) dropped to keep the document tight
  // while still satisfying TRANSFER-005 / TRANSFER-006 via the
  // Clause 11 redress anchor — but Clause 18 (Governing Law and
  // Forum) is replaced with a plain-English "Governing Law"
  // paragraph that picks the Republic of Ireland and Dublin venue
  // without using the canonical "Clause 18", "Governing Law and
  // Forum", "Governing Law and Jurisdiction", or "choice of forum"
  // anchor. (An "Adequacy Fallback" paragraph satisfies
  // TRANSFER-018 so the fixture is not co-flagged on the fallback
  // rule.) Every other Module 2 clause + the three Annexes are
  // preserved so the rest of the TRANSFER-001..019 baseline still
  // passes where it was passing. **TRANSFER-010 (warning)** fires —
  // its present_pattern
  // `(clause\s*18\b|governing\s+law\s+and\s+(?:forum|jurisdiction)|choice\s+of\s+forum)`
  // is no longer matched anywhere in the document. EU SCCs Clause
  // 18 fixes the governing law on an EU Member State allowing
  // third-party-beneficiary rights and the forum on a court of
  // that Member State; a "Republic of Ireland law / Dublin venue"
  // recital reaches the same operative result but loses the SCC
  // Clause 18 anchor a supervisory authority searches for when
  // verifying invariability under Clause 2.
  "scc-module-2-missing-clause-18-fail.txt": ["TRANSFER-010"],

  // CCPA Service-Provider Addendum with a new Section 2
  // ("Compliance Posture") paragraph that explicitly substitutes
  // "an equivalent privacy posture" for the canonical CCPA "same
  // level of privacy protection" recital and pre-emptively
  // disclaims incorporation of any additional statutory or
  // regulatory standard: "Service Provider's privacy obligations
  // under this Agreement are limited to the specific commitments
  // enumerated herein and the obligations expressly imposed on
  // service providers under 11 C.C.R. § 7051(a)(1)–(8), without
  // incorporation by reference of any additional statutory or
  // regulatory standard." No "same level of privacy protection" or
  // "comply with all applicable obligations / CCPA" anchor appears
  // anywhere in the document. Every other clause is preserved so
  // the rest of the USDPA-001..025 baseline still passes where it
  // was passing. **USDPA-005 (warning)** fires — its
  // present_pattern
  // `same\s+level\s+of\s+privacy\s+protection|comply\s+with\s+all\s+applicable\s+(?:obligations|ccpa)`
  // is no longer matched anywhere in the document. Cal. Civ. Code
  // § 1798.100(d) requires the contract to obligate the service
  // provider to comply with applicable CCPA obligations and to
  // provide the same level of privacy protection as required by
  // the CCPA; an "equivalent privacy posture" substitute that
  // affirmatively disclaims incorporation of any additional
  // standard leaves the business exposed to enforcement under
  // § 1798.155 because the service provider's residual obligation
  // floor is whatever the contract enumerates rather than what
  // the CCPA requires of the business.
  "dpa-ccpa-service-provider-missing-same-level-protection-fail.txt": ["USDPA-005"],

  // Mutual NDA-Deep with a new Section 12 "Representations of the
  // Parties" paragraph that recites only narrow execution
  // representations (the natural person executing is duly
  // designated; execution has been approved through customary
  // corporate-decision processes) and explicitly forecloses
  // further inquiry: "The Parties make no other representation or
  // warranty in connection with the execution of this Agreement,
  // and any further inquiry into a Party's organizational standing
  // or contractual posture is foreclosed by this Section 12." No
  // "full authority", "full power and authority", "authority to
  // enter / execute", or "no conflicting (obligation|agreement)"
  // anchor appears anywhere in the document. ("Authorized
  // Representative" in the signature block does not match the
  // regex because it begins with "authoriz-ed" rather than the
  // word "authority".) Every other clause (DTSA notice, perpetual
  // trade-secret carve-out, no-license, injunctive relief with
  // bond waiver, governing law, no-precedent entire-agreement
  // clause) is preserved so the rest of the NDA-D-001..025
  // baseline still passes where it was passing. **NDA-D-022 (info)**
  // fires — its present_patterns
  // `(full\s+(power\s+and\s+)?authority|authority\s+to\s+(enter|execute))`
  // and `no\s+conflicting\s+(obligation|agreement)` are no longer
  // matched anywhere in the document. An authority + no-conflict
  // representation is a low-cost addition that closes off a
  // defensive argument later; foreclosing the inquiry instead
  // signals concealment and is the structural opposite of the
  // Common-Paper-style anchor the rule looks for.
  "mutual-nda-deep-missing-authority-rep-fail.txt": ["NDA-D-022"],

  // Controller→processor GDPR DPA with a new Section 14 "Internal
  // Documentation" paragraph that proprietizes Processor's
  // internal documentation of personal-data flows and processing
  // activities and explicitly disclaims any obligation to assist
  // Controller with controller-side documentation requirements
  // outside Sections 8, 9, and 11: "Processor's obligation to
  // assist Controller is limited to the categories of assistance
  // enumerated in Sections 8, 9, and 11 of this DPA, and Processor
  // shall have no obligation to assist Controller in compiling,
  // maintaining, or supplementing any controller-side
  // documentation requirement under any provision of the GDPR or
  // other applicable data protection law that is not expressly
  // enumerated in this DPA." No "records of processing", "article
  // 30", or "RoPA" anchor appears anywhere in the document. Every
  // other clause is preserved so the rest of the DPA-001..030
  // baseline still passes where it was passing. **DPA-028
  // (warning)** fires — its present_pattern
  // `(records\s+of\s+processing|article\s*30|RoPA)` is no longer
  // matched anywhere in the document. GDPR Art. 30 requires
  // controllers to maintain records of processing activities; most
  // DPAs anchor processor assistance with the controller's Art. 30
  // RoPA. A DPA that proprietizes processor's internal
  // documentation and disclaims any non-enumerated assistance duty
  // leaves the controller without a contractual hook to compile
  // its own RoPA when the processor is the only party with
  // visibility into the upstream processing-activity metadata.
  "dpa-controller-processor-missing-art30-ropa-assistance-fail.txt": ["DPA-028"],

  // Vendor MSA with two distinct sole-and-exclusive-remedy
  // clauses — Section 6 ("CUSTOMER'S SOLE AND EXCLUSIVE REMEDY ...
  // SHALL BE RE-PERFORMANCE") and a new Section 7 ("Service
  // Levels") declaring service-level credits Vendor's "sole and
  // exclusive remedy" with the explicit additional statement that
  // "no additional damages, refunds, or substitute performance
  // remedies shall be available with respect to any service-level
  // failure regardless of the cause, severity, duration, or
  // recurrence of the failure" — and no "fail of (its) essential
  // purpose", "essential purpose", or "U.C.C. § 2-719" anchor
  // anywhere in the document. Every other clause is preserved so
  // the rest of the MSA-001..030 baseline still passes where it
  // was passing. **MSA-030 (info)** fires — its present_pattern
  // `(fail\w*\s+of\s+(?:its\s+)?essential\s+purpose|essential\s+purpose|U\.?C\.?C\.?\s*§\s*2-719)`
  // is no longer matched anywhere in the document. UCC § 2-719(2)
  // preserves the customer's alternative remedies when a limited
  // remedy fails of its essential purpose; an MSA whose limited
  // remedies are paired with explicit disclaimers of substitute
  // remedies forecloses the statutory escape on its face and
  // leaves the customer with no remedy when re-performance / SLA
  // credits prove worthless (e.g. extended service unavailability,
  // repeated re-performance failure).
  "msa-vendor-deep-missing-essential-purpose-fail.txt": ["MSA-030"],

  // Unilateral NDA with the "Disclosing Party" / "Receiving Party"
  // role labels swapped throughout for the more generic "Provider"
  // / "Recipient" framing. Every operative clause survives
  // (definitions, carveouts, obligations, no-license, term, DTSA
  // notice, return, governing law, entire agreement), but no
  // "Disclosing Party" / "Receiving Party" anchor appears anywhere
  // in the document. NDA-D-025 (warning) fires — its
  // present_patterns `disclosing\s+party.{0,200}receiving\s+party`
  // / `receiving\s+party.{0,200}disclosing\s+party` are no longer
  // matched. Unilateral NDAs should clearly name one party as the
  // Disclosing Party and the other as Receiving Party so the
  // statutory framing and any downstream incorporation by reference
  // (e.g., DTSA notice, residuals carve-outs) attaches to the right
  // role; a "Provider" / "Recipient" generic substitute loses the
  // unilateral-NDA template anchor and signals a template
  // mismatch.
  "unilateral-nda-deep-missing-disclosing-receiving-roles-fail.txt": ["NDA-D-025"],

  // CCPA Service-Provider Addendum with Section 4 ("Certification
  // of Compliance") rewritten to remove the "reasonable and
  // appropriate steps" anchor required by Cal. Civ. Code
  // § 1798.140(ag)(1)(C). The replacement language affirmatively
  // disclaims any Business entitlement to "supervisory action"
  // beyond the audit cadence in Section 9 and limits Service
  // Provider's compliance evidence to "certifications, deletion
  // confirmations, and audit-window deliverables expressly
  // enumerated in this CCPA Addendum." Every other clause is
  // preserved so the rest of the USDPA-001..025 baseline still
  // passes where it was passing. USDPA-007 (critical) fires — its
  // present_pattern
  // `(reasonable\s+and\s+appropriate\s+steps|monitor|oversight\s+right|right\s+to\s+(?:audit|monitor|inspect))`
  // is no longer matched anywhere in the document. § 1798.140(ag)(1)(C)
  // requires the contract to grant the business the right to take
  // reasonable and appropriate steps to ensure that the service
  // provider uses personal information in a manner consistent with
  // the business's CCPA obligations; an addendum that limits the
  // business to a once-per-year audit window leaves it without a
  // contractual hook to intervene when off-window evidence of
  // unauthorized use surfaces.
  "dpa-ccpa-service-provider-missing-monitoring-right-fail.txt": ["USDPA-007"],

  // Controller→processor GDPR DPA with both "personal data breach"
  // anchors in Section 10 ("Breach Notification") downgraded to
  // the generic "data breach" plus an explicit recital disclaiming
  // incorporation of any "defined-term framework or controlled
  // vocabulary from any specific regulator or implementing
  // regulation" with respect to that term. Every other clause is
  // preserved (Article 28 documented instructions, Article 32
  // security measures, Article 33 within-48-hours undue-delay
  // language, Annex I categories, EU SCCs incorporation) so the
  // rest of the DPA-001..030 baseline still passes where it was
  // passing. DPA-041 (warning) fires — its present_pattern
  // `(personal\s+data\s+breach|data\s+subject\s+shall\s+have|controller.{0,40}(shall\s+have\s+the\s+meaning|means)|processor.{0,40}(shall\s+have\s+the\s+meaning|means))`
  // is no longer matched anywhere in the document. GDPR Art. 4
  // defines the operative terms ("Personal Data Breach", "Data
  // Subject", "Controller", "Processor") that anchor every
  // downstream Article 28 obligation; a DPA that uses the
  // operational "data breach" shorthand and disclaims controlled
  // vocabulary loses the GDPR Art. 4 hook a supervisory authority
  // relies on when reading the agreement against the regulation.
  "dpa-controller-processor-missing-gdpr-terminology-fail.txt": ["DPA-041"],
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
