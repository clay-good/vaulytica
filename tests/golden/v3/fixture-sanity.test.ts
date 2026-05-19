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
