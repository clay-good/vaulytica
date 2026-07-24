/**
 * BAA ruleset — 45 rules (spec-v3.md §28 / Step 23).
 *
 * Required-clause checks per 45 CFR § 164.504(e)(2)(i)–(iii), Security
 * Rule flow-down (§ 164.314(a)), breach-notification timing (§ 164.410),
 * plus language-quality and posture rules (audit rights, indemnity
 * caps, non-narrowed security incident scope, definite return-or-
 * destruction outer bound, signed by authorized representative, etc.).
 *
 * Each rule is `applies_to_playbooks: ["baa", "baa-deep",
 * "baa-subcontractor"]` so the v2 launch suite stays unchanged when no
 * BAA playbook is active. The runner already enforces that filter at
 * `src/engine/runner.ts`.
 */

import type { Rule } from "../../../finding.js";
import {
  buildBaaLanguageRule,
  buildBaaPresenceRule,
  type BaaLanguageSpec,
  type BaaPresenceSpec,
} from "./_helpers.js";

const presence = (s: BaaPresenceSpec): Rule => buildBaaPresenceRule(s);
const language = (s: BaaLanguageSpec): Rule => buildBaaLanguageRule(s);

const PHI = /(\bprotected health information\b|\bPHI\b|\bePHI\b)/i;

export const BAA_RULES: Rule[] = [
  // ────────────────────────────────────────────────────────────────
  // Required clauses — 45 C.F.R. § 164.504(e)(2)(ii)(A)–(J), (iii), (5)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "BAA-001",
    name: "Permitted uses and disclosures of PHI",
    description:
      "BAA must establish the permitted and required uses and disclosures of PHI by the business associate.",
    citation: "45 C.F.R. § 164.504(e)(2)(i)",
    missing_title: "Permitted uses-and-disclosures clause missing",
    missing_description:
      "No clause was found establishing the permitted and required uses and disclosures of PHI.",
    explanation:
      "45 CFR § 164.504(e)(2)(i) requires the BAA to set out the permitted and required uses and disclosures of Protected Health Information by the business associate. Without this clause, the agreement does not satisfy HIPAA's core contracting standard.",
    recommendation:
      "Add a section titled 'Permitted Uses and Disclosures' stating the business purposes for which the BA may use or disclose PHI.",
    present_patterns: [
      /(permitted|authorized)\s+(uses|disclosures)\b/i,
      /uses\s+and\s+disclosures\s+of\s+(PHI|protected health information)/i,
    ],
  }),

  presence({
    id: "BAA-002",
    name: "Use limited to permitted purposes",
    description:
      "Business associate may not use PHI for any purpose other than as permitted by the BAA or required by law.",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(A)",
    missing_title: "Use-limitation clause missing",
    missing_description:
      "No clause was found prohibiting use of PHI other than as permitted or required by law.",
    explanation:
      "Under § 164.504(e)(2)(ii)(A), the contract must require the BA not to use or further disclose PHI other than as permitted by the contract or as required by law.",
    recommendation:
      "Add: 'Business Associate shall not use or disclose PHI other than as permitted or required by this Agreement or as required by law.'",
    present_patterns: [/(not\s+use\s+or\s+disclose|shall\s+not\s+use)/i],
  }),

  presence({
    id: "BAA-003",
    name: "Appropriate safeguards clause",
    description:
      "BAA must require BA to use appropriate safeguards, including Security Rule administrative, physical, and technical safeguards.",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(B)",
    missing_title: "Appropriate-safeguards clause missing",
    missing_description:
      "No safeguards clause was found covering administrative, physical, or technical protections for PHI.",
    explanation:
      "Section 164.504(e)(2)(ii)(B) requires the BA to use appropriate safeguards to prevent use or disclosure of PHI other than as provided for by the contract.",
    recommendation:
      "Add a clause obligating the Business Associate to implement appropriate administrative, physical, and technical safeguards.",
    present_patterns: [
      /(appropriate\s+safeguards|administrative.*physical.*technical|reasonable\s+safeguards)/i,
    ],
  }),

  presence({
    id: "BAA-004",
    name: "Report improper uses or disclosures",
    description:
      "BAA must require BA to report to the covered entity any use or disclosure not provided for by the contract.",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(C)",
    missing_title: "Incident-reporting clause missing",
    missing_description:
      "No clause was found requiring the BA to report uses or disclosures not provided for by the contract.",
    explanation:
      "Section 164.504(e)(2)(ii)(C) requires the BAA to obligate the BA to report any use or disclosure not authorized by the contract.",
    recommendation:
      "Add: 'Business Associate shall report to Covered Entity any use or disclosure of PHI not provided for by this Agreement.'",
    present_patterns: [
      /(report\s+(to|the)\s+covered\s+entity|notify\s+covered\s+entity).*?(use|disclosure|breach|incident)/i,
    ],
  }),

  presence({
    id: "BAA-005",
    name: "Subcontractor flow-down",
    description:
      "BA must ensure subcontractors that handle PHI agree in writing to the same restrictions and conditions.",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(D)",
    missing_title: "Subcontractor flow-down clause missing",
    missing_description:
      "No clause was found requiring subcontractors handling PHI to be bound by the same restrictions.",
    explanation:
      "Section 164.504(e)(2)(ii)(D) requires the BA to ensure that any subcontractor that creates, receives, maintains, or transmits PHI agrees in writing to the same restrictions and conditions that apply to the BA.",
    recommendation:
      "Add a 'Subcontractors' clause requiring written agreements imposing the same restrictions on any subcontractor handling PHI.",
    present_patterns: [
      /(subcontractor|sub[- ]processor).*?(same restrictions|same conditions|written contract|agree)/is,
    ],
  }),

  presence({
    id: "BAA-006",
    name: "Access to PHI (164.524)",
    description:
      "BAA must require BA to make PHI available in a Designated Record Set to satisfy 45 CFR 164.524.",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(E)",
    missing_title: "Individual access clause missing",
    missing_description:
      "No clause was found requiring the BA to make PHI available for individual access under 45 CFR 164.524.",
    explanation:
      "BAAs must allow the covered entity to comply with individuals' right of access under § 164.524.",
    recommendation:
      "Add a clause: 'Business Associate shall make PHI available as necessary to comply with 45 CFR 164.524.'",
    present_patterns: [/(access\s+to\s+PHI|right\s+of\s+access|164\.524)/i],
  }),

  presence({
    id: "BAA-007",
    name: "Amendment of PHI (164.526)",
    description:
      "BAA must require BA to make PHI available for amendment to satisfy 45 CFR 164.526.",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(F)",
    missing_title: "Amendment-of-PHI clause missing",
    missing_description:
      "No clause was found requiring the BA to make PHI available for amendment under 45 CFR 164.526.",
    explanation:
      "BAAs must allow the covered entity to comply with individuals' right to amend PHI under § 164.526.",
    recommendation:
      "Add a clause: 'Business Associate shall make PHI available for amendment as required by 45 CFR 164.526.'",
    present_patterns: [/(amendment\s+of\s+PHI|amend.*?PHI|164\.526)/is],
  }),

  presence({
    id: "BAA-008",
    name: "Accounting of disclosures (164.528)",
    description:
      "BAA must require BA to maintain and make available the information required to provide an accounting of disclosures.",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(G)",
    missing_title: "Accounting-of-disclosures clause missing",
    missing_description:
      "No clause was found supporting individuals' right to an accounting of disclosures under 45 CFR 164.528.",
    explanation:
      "BAAs must enable covered entities to satisfy § 164.528's accounting-of-disclosures requirements.",
    recommendation:
      "Add: 'Business Associate shall maintain and make available the information required for an accounting of disclosures as required by 45 CFR 164.528.'",
    present_patterns: [/(accounting\s+of\s+disclosures|164\.528)/i],
  }),

  presence({
    id: "BAA-009",
    name: "Books and records available to HHS Secretary",
    description:
      "BAA must require BA to make its internal practices, books, and records available to HHS for compliance review.",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(H)",
    missing_title: "HHS books-and-records access clause missing",
    missing_description:
      "No clause was found making BA's books and records available to the HHS Secretary.",
    explanation:
      "Section 164.504(e)(2)(ii)(H) requires BAs to make their internal practices, books, and records available to the Secretary of HHS for determining compliance.",
    recommendation:
      "Add: 'Business Associate shall make its internal practices, books, and records relating to the use and disclosure of PHI available to the Secretary of HHS for purposes of determining compliance.'",
    present_patterns: [
      /(internal\s+practices.*books.*records|books.*records.*secretary|HHS\s+secretary)/is,
    ],
  }),

  presence({
    id: "BAA-010",
    name: "Return or destruction at termination",
    description:
      "BA must, at termination, return or destroy all PHI received from, or created on behalf of, the covered entity.",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(I)",
    missing_title: "Return-or-destruction clause missing",
    missing_description:
      "No clause was found requiring return or destruction of PHI at termination of the agreement.",
    explanation:
      "Section 164.504(e)(2)(ii)(I) requires the BA to return or destroy all PHI received from the covered entity, including PHI in the possession of subcontractors, at termination if feasible.",
    recommendation:
      "Add: 'Upon termination, Business Associate shall return or destroy all PHI received from or created on behalf of Covered Entity, including such PHI in the possession of any subcontractor.'",
    present_patterns: [/(return\s+or\s+destroy|destruction\s+of\s+PHI|destroy\s+all\s+PHI)/i],
  }),

  presence({
    id: "BAA-011",
    name: "Termination right for material breach",
    description:
      "Covered entity must have the right to terminate the BAA for material breach by the business associate.",
    citation: "45 C.F.R. § 164.504(e)(2)(iii)",
    missing_title: "Termination-for-breach clause missing",
    missing_description:
      "No clause was found giving Covered Entity the right to terminate for material breach.",
    explanation:
      "Section 164.504(e)(2)(iii) requires the BAA to allow the covered entity to terminate if the BA has violated a material term and either failed to cure or cure is not feasible.",
    recommendation:
      "Add a termination-for-breach clause with a defined cure period and explicit reference to material breach of HIPAA obligations.",
    present_patterns: [/(material\s+breach|terminate.*?breach|breach.*?(terminate|termination))/is],
  }),

  presence({
    id: "BAA-012",
    name: "Authorization to terminate if cure infeasible",
    description: "BAA should authorize termination when cure of a material breach is not feasible.",
    citation: "45 C.F.R. § 164.504(e)(2)(iii)",
    missing_title: "No 'cure infeasible' termination right",
    missing_description:
      "Termination clause does not address the case where cure of a material breach is infeasible.",
    explanation:
      "BAAs should permit termination when a cure is not feasible, mirroring HHS's expected drafting.",
    recommendation:
      "Add language allowing termination if cure is infeasible or if BA fails to cure within a reasonable period.",
    present_patterns: [
      /(cure\s+is\s+not\s+feasible|cure\s+is\s+infeasible|infeasible\s+to\s+cure|fail.*cure)/i,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Security Rule flow-down — § 164.314(a)(2)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "BAA-013",
    name: "Security Rule compliance required",
    description:
      "BAA must require BA to comply, where applicable, with the Security Rule with respect to ePHI.",
    citation: "45 C.F.R. § 164.314(a)(2)(i)",
    missing_title: "Security Rule compliance clause missing",
    missing_description:
      "No clause was found requiring BA to comply with the HIPAA Security Rule (45 CFR Part 164 Subpart C).",
    explanation:
      "Section 164.314(a)(2)(i) requires BAs that maintain ePHI to comply with the Security Rule.",
    recommendation:
      "Add: 'Business Associate shall comply with the Security Rule with respect to electronic PHI, including implementing administrative, physical, and technical safeguards.'",
    present_patterns: [/(security\s+rule|164\.30[0-9]|administrative.*?physical.*?technical)/i],
  }),

  presence({
    id: "BAA-014",
    version: "1.1.0",
    name: "Administrative safeguards referenced",
    description: "BAA should reference administrative safeguards required by the Security Rule.",
    citation: "45 C.F.R. § 164.308",
    missing_title: "Administrative safeguards not referenced",
    missing_description: "No reference to administrative safeguards was found.",
    explanation:
      "Section 164.308 requires administrative safeguards (workforce training, contingency planning, periodic risk assessment).",
    recommendation:
      "Reference 45 CFR § 164.308 (Administrative Safeguards) in the security clause.",
    // The § 164.504(e)(2)(ii)(B) coordinated list — "administrative,
    // physical, and technical safeguards" — is the single most common BAA
    // safeguards wording; the adjacent-bigram pattern alone missed it.
    present_patterns: [
      /administrative\s+safeguards|administrative\s*(?:,|\s+and\b)[^.]{0,40}?\bsafeguards|164\.308/i,
    ],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-015",
    version: "1.1.0",
    name: "Physical safeguards referenced",
    description: "BAA should reference physical safeguards required by the Security Rule.",
    citation: "45 C.F.R. § 164.310",
    missing_title: "Physical safeguards not referenced",
    missing_description: "No reference to physical safeguards was found.",
    explanation:
      "Section 164.310 requires physical safeguards (facility access controls, workstation security, device controls).",
    recommendation: "Reference 45 CFR § 164.310 (Physical Safeguards) in the security clause.",
    // "administrative, physical, and technical safeguards" — see BAA-014.
    present_patterns: [
      /physical\s+safeguards|physical\s*(?:,|\s+and\b)[^.]{0,40}?\bsafeguards|164\.310/i,
    ],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-016",
    name: "Technical safeguards referenced",
    description: "BAA should reference technical safeguards required by the Security Rule.",
    citation: "45 C.F.R. § 164.312",
    missing_title: "Technical safeguards not referenced",
    missing_description: "No reference to technical safeguards was found.",
    explanation:
      "Section 164.312 requires technical safeguards (access controls, audit logs, integrity controls, transmission security).",
    recommendation: "Reference 45 CFR § 164.312 (Technical Safeguards) in the security clause.",
    present_patterns: [/technical\s+safeguards|164\.312/i],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-017",
    name: "Security incident reporting",
    description: "BAA must require BA to report security incidents to the covered entity.",
    citation: "45 C.F.R. § 164.314(a)(2)(i)(C)",
    missing_title: "Security-incident reporting clause missing",
    missing_description: "No clause was found requiring BA to report security incidents.",
    explanation:
      "Section 164.314(a)(2)(i)(C) requires BAs to report security incidents — including unsuccessful attempts — of which they become aware.",
    recommendation:
      "Add: 'Business Associate shall report to Covered Entity any security incident of which it becomes aware.'",
    present_patterns: [/security\s+incident/i],
  }),

  presence({
    id: "BAA-018",
    name: "Subcontractor flow-down for Security Rule",
    description:
      "BA must ensure subcontractors handling ePHI agree to the Security Rule restrictions.",
    citation: "45 C.F.R. § 164.314(a)(2)(ii)",
    missing_title: "Security Rule subcontractor flow-down missing",
    missing_description:
      "No clause was found extending Security Rule obligations to subcontractors that maintain ePHI.",
    explanation:
      "Section 164.314(a)(2)(ii) requires BAs to ensure that any subcontractor that maintains ePHI agrees to comply with applicable Security Rule requirements.",
    recommendation:
      "Add: 'Business Associate shall ensure that any subcontractor that creates, receives, maintains, or transmits ePHI on behalf of Business Associate agrees in writing to comply with applicable Security Rule requirements.'",
    present_patterns: [
      /(subcontractor|sub[- ]processor).*?(security\s+rule|safeguards|same\s+(restrictions|conditions))/is,
    ],
  }),

  // ────────────────────────────────────────────────────────────────
  // Breach notification — § 164.410
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "BAA-019",
    name: "Breach notification clause present",
    description: "BAA must require BA to notify the covered entity of a breach of unsecured PHI.",
    citation: "45 C.F.R. § 164.410",
    missing_title: "Breach notification clause missing",
    missing_description: "No clause was found requiring breach notification under 45 CFR 164.410.",
    explanation:
      "Section 164.410 requires BAs to notify covered entities of breaches of unsecured PHI.",
    recommendation:
      "Add: 'Business Associate shall notify Covered Entity of any breach of unsecured PHI without unreasonable delay and in no case later than 60 calendar days after discovery.'",
    present_patterns: [/breach\s+of\s+unsecured\s+PHI|breach\s+notification|164\.410/i],
  }),

  language({
    id: "BAA-020",
    version: "1.1.0",
    name: "Breach notification looser than 60 days",
    description:
      "Flags breach-notice timing that exceeds the 60-day outer bound or shifts the trigger to a later event.",
    citation: "45 C.F.R. § 164.410(b)",
    bad_title: "Breach notification timing exceeds 60-day HIPAA cap",
    bad_description:
      "Detected breach-notification timing greater than 60 days or tied to an event later than discovery.",
    explanation:
      "Section 164.410(b) requires notification 'without unreasonable delay and in no case later than 60 calendar days after discovery of the breach.' Longer windows or shifted triggers violate HIPAA.",
    recommendation:
      "Reduce the breach-notification window to no more than 60 calendar days from discovery; do not tie the trigger to confirmation, assessment, or harm.",
    bad_patterns: [
      // "ninety (90) days" wraps the operative digits in a parenthetical, so a
      // `\d+\s*days` match must tolerate the ")" between the number and "days"
      // — the spelled-then-numeric convention otherwise hides an over-long
      // breach window entirely.
      /\b(9[0-9]|1[0-9]{2}|[2-9][0-9]{2})\)?\s*(calendar\s+)?days\b.{0,80}(breach|notif)/is,
      /(breach|notif).{0,80}\b(9[0-9]|1[0-9]{2}|[2-9][0-9]{2})\)?\s*(calendar\s+)?days\b/is,
      /\b(within|no\s+later\s+than)\s+(\d+)\)?\s*(business|working)\s+days?\b.{0,80}(breach|notif)/is,
    ],
    default_severity: "critical",
  }),

  presence({
    id: "BAA-021",
    name: "Breach trigger is 'discovery'",
    description:
      "Breach-notification timing should be measured from 'discovery,' not a stricter post-discovery event.",
    citation: "45 C.F.R. § 164.410(a)(2)",
    missing_title: "Breach trigger not anchored to 'discovery'",
    missing_description:
      "Could not find language tying the breach-notice clock to discovery of the breach.",
    explanation:
      "Section 164.410(a)(2) defines 'discovery' as the date the breach is known, or by exercising reasonable diligence would have been known. Shifting the trigger to a later assessment, confirmation, or harm-determination date violates HIPAA.",
    recommendation:
      "State explicitly that the notification clock begins on 'discovery' of the breach, as defined by 45 CFR § 164.410(a)(2).",
    present_patterns: [/discovery\s+of\s+(the\s+)?breach|breach.*?discover/i],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-022",
    name: "'Without unreasonable delay' language present",
    description:
      "BAA should include 'without unreasonable delay' to match HIPAA's inner timing bound.",
    citation: "45 C.F.R. § 164.410(b)",
    missing_title: "'Without unreasonable delay' language missing",
    missing_description:
      "Breach-notice clause does not include HIPAA's 'without unreasonable delay' standard.",
    explanation:
      "HIPAA's inner bound is 'without unreasonable delay' — drafters should preserve this language in addition to the 60-day outer bound.",
    recommendation:
      "Add 'without unreasonable delay and in no case later than 60 calendar days' to the breach-notification clause.",
    present_patterns: [/without\s+unreasonable\s+delay/i],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Language-quality rules
  // ────────────────────────────────────────────────────────────────
  language({
    id: "BAA-023",
    name: "Security Incident narrowed to 'successful' access",
    description:
      "Flags clauses that limit 'Security Incident' to only successful unauthorized accesses — a narrowing OCR has criticized.",
    citation: "45 C.F.R. § 164.304 (Security Incident definition)",
    bad_title: "Security Incident narrowed to 'successful' access",
    bad_description:
      "Detected a definition of 'Security Incident' that excludes unsuccessful attempts.",
    explanation:
      "OCR's interpretation of 45 CFR § 164.304 is that 'Security Incident' includes unsuccessful attempts. Narrowing to 'successful' access lets material attack telemetry escape reporting.",
    recommendation:
      "Use HIPAA's full definition: 'the attempted or successful unauthorized access, use, disclosure, modification, or destruction of information or interference with system operations in an information system.'",
    bad_patterns: [
      /Security\s+Incident.{0,200}successful\s+(unauthorized|access)/is,
      /only\s+successful\s+(unauthorized\s+access|incidents)/i,
    ],
    // "attempted or successful" IS HIPAA's full definition — the very wording
    // this rule's own recommendation asks for. Reading the "successful" half of
    // it as a narrowing accuses the compliant definition of the narrowing it
    // forecloses.
    exclude_if: [/attempted\s+or\s+successful/i],
  }),

  language({
    id: "BAA-024",
    version: "1.1.0",
    name: "Return-or-destruction lacks definite outer bound",
    description:
      "Flags return-or-destruction language that is open-ended ('as soon as practicable', 'commercially reasonable').",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(I)",
    bad_title: "Return-or-destruction lacks definite outer bound",
    bad_description:
      "Detected return-or-destruction obligation without a definite outer time bound.",
    explanation:
      "HHS guidance expects a definite outer bound for return or destruction of PHI at termination. Open-ended timing risks indefinite PHI retention.",
    recommendation:
      "Specify a fixed number of days (e.g., 30 days) after termination for return or destruction of PHI.",
    bad_patterns: [
      /(return|destroy|destruction).{0,80}(as\s+soon\s+as\s+practicable|commercially\s+reasonable|reasonable\s+time)/i,
      // "return or destroy PHI WHEN feasible" is open-ended timing. "IF
      // feasible" is deliberately excluded — that is the statutory condition
      // at 45 C.F.R. § 164.504(e)(2)(ii)(I) ("if it is infeasible to return
      // or destroy … extend the protections"), which is correct drafting.
      /(return|destroy|destruction)[^.]{0,60}\b(?:when|as)\s+feasible\b/i,
    ],
    // "commercially reasonable EFFORTS" describes the manner of performance,
    // not the timing. A clause that also states a day count ("within 30 days of
    // termination") has the definite outer bound this rule demands.
    // A definite day count IS the outer bound this rule wants — but "thirty
    // (30) days" wraps the digits in a parenthetical, so the exclude_if must
    // tolerate the ")" or a compliant bounded clause fires as unbounded (the
    // digit-in-paren class, on the suppression side).
    exclude_if: [
      /\b\d+\)?\s+(?:calendar\s+|business\s+)?days?\b/i,
      /\(\d+\)\s+(?:calendar\s+|business\s+)?days?\b/i,
    ],
    default_severity: "warning",
  }),

  language({
    id: "BAA-025",
    name: "Indemnity cap impairing HIPAA remedies",
    description:
      "Flags liability caps that limit damages below the covered entity's potential HIPAA penalty exposure.",
    citation: "45 C.F.R. § 160.404 (Civil Money Penalty caps)",
    bad_title: "Indemnity cap may impair HIPAA remedies",
    bad_description:
      "Detected an aggregate-liability cap that may not cover HIPAA Tier 4 penalties (up to $2,067,813 per violation category).",
    explanation:
      "HIPAA civil money penalties can reach over $2M per violation category per year (45 CFR § 160.404, adjusted annually). A liability cap below that effectively shifts HIPAA risk back to the Covered Entity.",
    recommendation:
      "Carve HIPAA-related liability out of the cap, or set the cap at a multiple of fees no lower than the HHS annual penalty cap.",
    bad_patterns: [
      /(aggregate\s+liability|total\s+liability|liability.{0,40}shall\s+not\s+exceed).{0,120}(fees|paid|amount)/is,
    ],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-026",
    name: "Covered entity audit rights preserved",
    description: "BAA should preserve the covered entity's right to audit BA's HIPAA compliance.",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(H)",
    missing_title: "Covered-entity audit rights not preserved",
    missing_description:
      "No clause was found granting Covered Entity audit rights over BA's PHI handling.",
    explanation:
      "HHS guidance encourages audit rights as a substantive complement to the books-and-records access requirement. Without audit rights, the covered entity has limited ability to verify ongoing compliance.",
    recommendation:
      "Add an audit-rights clause permitting reasonable on-site or remote audits of BA's HIPAA compliance.",
    present_patterns: [/(audit\s+rights|right\s+to\s+audit|reasonable\s+audit|conduct.*audit)/i],
    default_severity: "warning",
  }),

  language({
    id: "BAA-027",
    name: "Covered entity indemnifies BA for HIPAA violations",
    description:
      "Flags clauses where the covered entity indemnifies the business associate for HIPAA violations — a common vendor overreach.",
    citation: "45 C.F.R. § 164.504(e)",
    bad_title: "Covered entity indemnifies BA for HIPAA violations",
    bad_description:
      "Detected indemnification language requiring the covered entity to indemnify BA for HIPAA-related liability.",
    explanation:
      "HHS-frowned-upon drafting: shifting HIPAA liability from BA to the covered entity inverts the regulatory burden. The covered entity should not indemnify the BA for the BA's own HIPAA violations.",
    recommendation:
      "Restrict mutual indemnification to non-HIPAA matters, or remove the CE-to-BA indemnification entirely with respect to HIPAA breaches.",
    bad_patterns: [
      /covered\s+entity\s+(shall|will)\s+indemnif/i,
      /(customer|client)\s+(shall|will)\s+indemnif.*?HIPAA/i,
    ],
  }),

  // ────────────────────────────────────────────────────────────────
  // Definitions and HIPAA terminology
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "BAA-028",
    name: "PHI / ePHI defined or cross-referenced",
    description: "BAA should define PHI/ePHI or cross-reference the HIPAA definition.",
    citation: "45 C.F.R. § 160.103 (Definitions)",
    missing_title: "PHI / ePHI definition missing",
    missing_description: "No definition or HIPAA cross-reference for PHI or ePHI was found.",
    explanation:
      "Section 160.103 defines PHI and ePHI. Drafters should either define these terms locally or incorporate the HIPAA definition by reference.",
    recommendation:
      "Add a definitions clause that incorporates 'Protected Health Information' and 'electronic PHI' as defined at 45 CFR § 160.103.",
    present_patterns: [
      /(protected\s+health\s+information.{0,80}(means|shall\s+have)|160\.103|PHI.*shall\s+have\s+the\s+meaning)/is,
    ],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-029",
    name: "Minimum-necessary standard referenced",
    description: "BAA should reference HIPAA's minimum-necessary standard.",
    citation: "45 C.F.R. § 164.502(b)",
    missing_title: "Minimum-necessary standard not referenced",
    missing_description: "No reference to the minimum-necessary standard was found.",
    explanation:
      "Section 164.502(b) requires limiting use and disclosure of PHI to the minimum necessary to accomplish the intended purpose.",
    recommendation:
      "Add: 'Business Associate shall limit use and disclosure of PHI to the minimum necessary to perform its obligations under this Agreement.'",
    present_patterns: [/minimum\s+necessary|164\.502\(b\)/i],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-030",
    name: "Mitigation obligation",
    description:
      "BAA should require BA to mitigate harmful effects of any improper use or disclosure.",
    citation: "45 C.F.R. § 164.530(f) (covered-entity duty, flowed through)",
    missing_title: "Mitigation obligation missing",
    missing_description:
      "No clause was found requiring BA to mitigate harm from improper uses or disclosures.",
    explanation:
      "Section 164.530(f) requires covered entities to mitigate, to the extent practicable, any harmful effect known to them of a use or disclosure in violation of HIPAA. BAs commonly inherit this duty.",
    recommendation:
      "Add: 'Business Associate shall mitigate, to the extent practicable, any harmful effect of a use or disclosure of PHI by Business Associate in violation of this Agreement or the HIPAA Rules.'",
    present_patterns: [/(mitigate|mitigation).*?(harm|effect|disclosure|use)/is],
  }),

  presence({
    id: "BAA-031",
    name: "Workforce training requirement",
    description:
      "BAA should require BA's workforce members handling PHI to be trained on its obligations.",
    citation: "45 C.F.R. § 164.530(b) / 164.308(a)(5)",
    missing_title: "Workforce training requirement missing",
    missing_description:
      "No clause was found requiring training of BA's workforce on HIPAA / BAA obligations.",
    explanation:
      "Sections 164.530(b) and 164.308(a)(5) require workforce training; BAs should flow this obligation down to their personnel.",
    recommendation: "Add a workforce-training clause referring to BA's HIPAA training program.",
    present_patterns: [/(workforce\s+training|HIPAA\s+training|trained\s+on.{0,40}(HIPAA|PHI))/i],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-032",
    name: "Encryption or NIST safeguards referenced",
    description:
      "BAA should reference encryption / NIST-style safeguards for ePHI at rest and in transit.",
    citation: "45 C.F.R. § 164.312(a)(2)(iv), (e)(2)(ii)",
    missing_title: "Encryption / NIST safeguards not referenced",
    missing_description:
      "No reference to encryption (or equivalent NIST-style safeguards) was found.",
    explanation:
      "Encryption is an addressable specification under § 164.312, but is the 'safe harbor' for breach notification under HITECH. Strong BAAs reference encryption or NIST 800-53/800-66 explicitly.",
    recommendation:
      "Add an encryption clause referencing NIST 800-111 (data at rest) and NIST 800-52 (data in transit) or equivalent.",
    present_patterns: [/(encrypt(ion)?|NIST\s*800|FIPS\s*140)/i],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-033",
    name: "Risk assessment requirement",
    description: "BAA should require BA to conduct periodic risk assessments per § 164.308(a)(1).",
    citation: "45 C.F.R. § 164.308(a)(1)(ii)(A)",
    missing_title: "Risk-assessment requirement missing",
    missing_description: "No clause was found requiring periodic security risk assessment.",
    explanation:
      "Section 164.308(a)(1)(ii)(A) requires a risk analysis as part of the Security Management Process.",
    recommendation:
      "Add: 'Business Associate shall conduct and document periodic risk assessments per 45 CFR § 164.308(a)(1).'",
    present_patterns: [/risk\s+(assessment|analysis)/i],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-034",
    name: "Sanctions policy / personnel discipline",
    description:
      "BAA should reference BA's sanctions policy for workforce members who violate HIPAA/BAA.",
    citation: "45 C.F.R. § 164.308(a)(1)(ii)(C)",
    missing_title: "Sanctions / personnel discipline policy not referenced",
    missing_description:
      "No clause was found referencing BA's sanctions policy for workforce HIPAA violations.",
    explanation: "Section 164.308(a)(1)(ii)(C) requires workforce sanctions for HIPAA violations.",
    recommendation:
      "Add a sanctions / discipline clause noting that BA maintains a written sanctions policy.",
    present_patterns: [/(sanction|discipline)\s+(policy|workforce|employees)/i],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-035",
    name: "Subprocessor / vendor disclosure",
    description:
      "BAA should require BA to disclose subprocessors / downstream vendors that handle PHI.",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(D)",
    missing_title: "Subprocessor disclosure clause missing",
    missing_description: "No clause was found requiring BA to disclose subprocessors handling PHI.",
    explanation:
      "Although § 164.504(e)(2)(ii)(D) speaks to flow-down, modern BAAs additionally require disclosure of the subprocessor identity for vetting.",
    recommendation:
      "Add: 'Business Associate shall maintain and make available to Covered Entity a current list of subcontractors that create, receive, maintain, or transmit PHI.'",
    present_patterns: [
      /(list\s+of\s+subprocessors|list\s+of\s+subcontractors|subprocessor.{0,60}(disclos|maintain.*list))/is,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Posture and execution
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "BAA-036",
    name: "Signed by authorized representative",
    description:
      "BAA should be signed by an authorized representative of each party (satisfactory assurances).",
    citation: "45 C.F.R. § 164.504(e)(5)",
    missing_title: "Signature block missing",
    missing_description: "No signature block was detected in the document.",
    explanation:
      "Section 164.504(e)(5) requires the covered entity to obtain satisfactory assurances through a written contract — a signed instrument.",
    recommendation:
      "Add signature blocks for both parties with name, title, and date of authorized representatives.",
    present_patterns: [
      /By:\s*[_\-\s]+|signature\s+block|authorized\s+(signatory|representative)|sign(ed)?\s+by/i,
    ],
  }),

  presence({
    id: "BAA-037",
    name: "Effective date present",
    description: "BAA should state an effective date.",
    citation: "45 C.F.R. § 164.504(e)",
    missing_title: "Effective date missing",
    missing_description: "No effective date was detected in the document.",
    explanation:
      "An effective date anchors the timing rules in the BAA (term, breach windows, termination).",
    recommendation: "Add an 'Effective Date' clause near the preamble.",
    present_patterns: [/effective\s+date/i],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-038",
    version: "1.1.0",
    name: "Term / duration clause present",
    description: "BAA should specify its term.",
    citation: "45 C.F.R. § 164.504(e)",
    missing_title: "Term / duration clause missing",
    missing_description: "No term / duration clause was detected.",
    explanation:
      "BAAs should state how long the agreement is in effect, including renewal handling.",
    recommendation: "Add a 'Term' clause specifying initial term and renewal.",
    // A BAA's canonical term is not a year count — it runs until PHI
    // disposition: "effective as of the Effective Date and terminates when
    // all PHI is destroyed or returned" (§ 164.504(e) shape).
    present_patterns: [
      /(\bterm\b.{0,40}(year|month|day)|term\s+of\s+(this\s+)?agreement|initial\s+term)/i,
      /terminates?\s+when\s+all\s+(?:the\s+)?(?:PHI|protected\s+health\s+information)/i,
    ],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-039",
    name: "Governing law specified",
    description: "BAA should specify the governing law.",
    citation: "45 C.F.R. § 164.504(e)",
    missing_title: "Governing-law clause missing",
    missing_description: "No governing-law clause was detected.",
    explanation:
      "Although HIPAA is federal, BAAs typically include a governing-law clause to anchor non-HIPAA contract disputes.",
    recommendation:
      "Add a governing-law clause naming the applicable state law for non-HIPAA contract matters.",
    present_patterns: [
      /(governing\s+law|governed\s+by\s+the\s+laws|laws\s+of\s+the\s+State\s+of)/i,
    ],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-040",
    name: "Notice clause present",
    description: "BAA should specify how formal notices (including breach notices) are delivered.",
    citation: "45 C.F.R. § 164.410(c) (content of notification)",
    missing_title: "Notice clause missing",
    missing_description: "No notice clause was detected.",
    explanation:
      "A notice clause anchors how breach notifications and other formal communications travel between the parties.",
    recommendation:
      "Add a notice clause naming the methods (email, certified mail), addresses, and timing requirements.",
    present_patterns: [
      /(notice\s+(shall|must)\s+be|notices\s+(under|hereunder|shall)|notice\s+address)/i,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // PHI-specific scope and posture
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "BAA-041",
    name: "PHI referenced in document",
    description:
      "BAA should explicitly reference PHI or ePHI; absence likely means the wrong template.",
    citation: "45 C.F.R. § 160.103",
    missing_title: "Document does not reference PHI / ePHI",
    missing_description: "No references to Protected Health Information were detected.",
    explanation:
      "A BAA template that never mentions PHI is highly likely to be the wrong template or one missing core obligations.",
    recommendation: "Use a BAA template that explicitly references PHI and ePHI throughout.",
    present_patterns: [PHI],
  }),

  language({
    id: "BAA-042",
    version: "1.1.0",
    name: "Choice-of-law overrides federal HIPAA",
    description:
      "Flags clauses that purport to make state law control over HIPAA — preempted but indicates poor drafting.",
    citation: "45 C.F.R. § 160.203 (preemption)",
    bad_title: "Choice-of-law attempts to override HIPAA",
    bad_description: "Detected language that may purport to subordinate HIPAA to state law.",
    explanation:
      "HIPAA preempts contrary state law unless an exception applies (45 CFR § 160.203). A clause stating that state law controls 'notwithstanding HIPAA' is unenforceable and signals careless drafting.",
    recommendation:
      "Revise the governing-law clause to make clear that HIPAA controls in the event of conflict.",
    bad_patterns: [
      /(notwithstanding\s+(any\s+)?(provision\s+of\s+)?HIPAA|state\s+law\s+(shall\s+)?controls?|state\s+law\s+governs)/is,
      // "the laws of Texas, which shall CONTROL OVER any conflicting FEDERAL
      // requirement" — a governing-law clause purporting to override HIPAA.
      /\b(?:shall\s+)?(?:control|prevail|govern|take\s+precedence)\s+over\s+[^.]{0,60}\bfederal\b/is,
      /\bexclusively\s+by\s+the\s+laws\s+of[^.]{0,60}\bover\s+(?:any\s+)?(?:conflicting\s+)?federal\b/is,
    ],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-043",
    version: "1.1.0",
    name: "Survival of HIPAA obligations after termination",
    description: "BAA should state that HIPAA-related obligations survive termination.",
    citation: "45 C.F.R. § 164.504(e)(2)(ii)(I)",
    missing_title: "Survival clause for HIPAA obligations missing",
    missing_description:
      "No survival clause was found extending HIPAA obligations past termination.",
    explanation:
      "Section 164.504(e)(2)(ii)(I) and HHS guidance expect HIPAA obligations to survive termination for any PHI retained after termination.",
    recommendation:
      "Add: 'The obligations of Business Associate under Section [X] (Return or Destruction of PHI), and the obligations applicable to any PHI that BA retains, shall survive termination.'",
    // § 164.504(e)(2)(ii)(J)'s own survival mechanism: when return or
    // destruction is infeasible, "extend the protections of this BAA" to the
    // retained PHI. A BAA quoting the regulation's mechanism has a survival
    // clause, whether or not it uses the word.
    present_patterns: [
      /survive\s+(the\s+)?termination|survival/i,
      /extend\s+the\s+protections\s+of\s+this\s+(?:BAA|Agreement)/i,
    ],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-044",
    name: "Definitions track current HIPAA terminology",
    description:
      "BAA should track current HIPAA / HITECH terminology (Breach, Unsecured PHI, Covered Entity, Business Associate).",
    citation: "45 C.F.R. § 160.103; § 164.402",
    missing_title: "HIPAA-current terminology not present",
    missing_description: "Could not detect the post-HITECH defined terms (Breach, Unsecured PHI).",
    explanation:
      "Post-HITECH BAAs should track the modern definitions of 'Breach' (§ 164.402) and 'Unsecured PHI' (§ 164.402).",
    recommendation:
      "Add definitions for 'Breach' and 'Unsecured PHI' that cross-reference 45 CFR § 164.402.",
    present_patterns: [
      /(unsecured\s+PHI|unsecured\s+protected\s+health\s+information|164\.402|breach\s+(means|shall\s+have))/i,
    ],
    default_severity: "warning",
  }),

  presence({
    id: "BAA-045",
    name: "Covered entity / business associate roles named",
    description:
      "BAA should clearly identify which party is the Covered Entity and which is the Business Associate.",
    citation: "45 C.F.R. § 160.103",
    missing_title: "Covered entity / business associate roles unclear",
    missing_description:
      "Could not detect both 'Covered Entity' and 'Business Associate' role labels.",
    explanation: "Both party roles must be named so the regulatory framework attaches correctly.",
    recommendation:
      "Use 'Covered Entity' and 'Business Associate' (capitalized defined terms) consistently in the preamble and throughout.",
    present_patterns: [
      /covered\s+entity.*?business\s+associate|business\s+associate.*?covered\s+entity/is,
    ],
  }),
];

if (BAA_RULES.length !== 45) {
  throw new Error(`BAA ruleset must export exactly 45 rules; got ${BAA_RULES.length}`);
}
