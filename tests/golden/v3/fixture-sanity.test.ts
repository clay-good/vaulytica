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
