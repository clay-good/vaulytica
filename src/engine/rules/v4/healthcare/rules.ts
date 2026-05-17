/**
 * v4 Healthcare ruleset — 25 rules
 * (spec-v4.md §6.J, Step 53).
 *
 * Three new playbooks: informed consent (research / clinical, prose
 * elements only), patient authorization for release of PHI (45
 * C.F.R. § 164.508), and HIPAA NPP acknowledgment (§ 164.520(c)(2)(ii)).
 *
 * Rule ids are flat `HC-NNN` (001..025).
 */

import type { Rule } from "../../../finding.js";
import { buildV4PresenceRule, type V4PresenceSpec } from "../_helpers.js";
import {
  HC_PLAYBOOK_INFORMED_CONSENT,
  HC_PLAYBOOK_PHI_AUTH,
  HC_PLAYBOOK_NPP_ACK,
  commonRule,
  fdaIc,
  hipaa,
  hcPractice,
} from "./_helpers.js";

const CATEGORY = "healthcare";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// J.3 — Informed consent (research / clinical). 9 rules: HC-001..HC-009.
// ────────────────────────────────────────────────────────────────────

const INFORMED_CONSENT_RULES: Rule[] = [
  presence({
    id: "HC-001",
    name: "Statement that the study involves research + purpose / duration",
    description:
      "Informed consent must state that the study involves research, the purpose, and the expected duration of participation.",
    citation: commonRule("116(b)(1)", "Basic elements"),
    playbooks: [HC_PLAYBOOK_INFORMED_CONSENT],
    missing_title: "Research / purpose / duration clause missing",
    missing_description:
      "No clause was found stating that the study involves research, its purpose, and expected duration.",
    explanation:
      "45 C.F.R. § 46.116(b)(1) requires a statement that the study involves research, an explanation of the purposes, the expected duration of participation, and a description of procedures.",
    recommendation:
      "Add 'Research Study' clause stating the study involves research, the purpose, the expected duration, and the procedures involved.",
    present_patterns: [
      /(research|study)/i,
      /(purpose|objective)/i,
      /(duration|time\s+commitment|expected\s+to\s+(last|take))/i,
    ],
  }),
  presence({
    id: "HC-002",
    name: "Risks / discomforts disclosure",
    description: "Informed consent must describe reasonably foreseeable risks / discomforts.",
    citation: commonRule("116(b)(2)", "Risks"),
    playbooks: [HC_PLAYBOOK_INFORMED_CONSENT],
    missing_title: "Risks / discomforts clause missing",
    missing_description: "No clause was found describing risks or discomforts.",
    explanation:
      "45 C.F.R. § 46.116(b)(2) requires a description of any reasonably foreseeable risks or discomforts to the subject.",
    recommendation:
      "Add 'Risks and Discomforts' enumerating reasonably foreseeable risks (medical, psychological, social, financial).",
    present_patterns: [
      /(risks?|discomforts?)/i,
      /(reasonably\s+foreseeable|side\s+effects?|adverse)/i,
    ],
  }),
  presence({
    id: "HC-003",
    name: "Benefits — direct and indirect",
    description:
      "Informed consent must describe benefits (or absence of direct benefit) to the subject and to others.",
    citation: commonRule("116(b)(3)", "Benefits"),
    playbooks: [HC_PLAYBOOK_INFORMED_CONSENT],
    missing_title: "Benefits clause missing",
    missing_description:
      "No clause was found describing benefits (or absence of direct benefit).",
    explanation:
      "§ 46.116(b)(3) requires a description of any reasonably expected benefits to the subject or to others — and a candid statement when there is no direct benefit.",
    recommendation:
      "Add 'Benefits' describing direct benefits, indirect benefits, and stating when no direct benefit is expected.",
    present_patterns: [
      /benefits?/i,
      /(no\s+direct\s+benefit|may\s+not\s+benefit|other(s)?\s+may\s+benefit)/i,
    ],
  }),
  presence({
    id: "HC-004",
    name: "Alternative procedures / treatments",
    description: "Informed consent must disclose appropriate alternatives.",
    citation: commonRule("116(b)(4)", "Alternatives"),
    playbooks: [HC_PLAYBOOK_INFORMED_CONSENT],
    missing_title: "Alternatives clause missing",
    missing_description: "No clause was found disclosing alternative procedures / treatments.",
    explanation:
      "§ 46.116(b)(4) requires disclosure of appropriate alternative procedures or courses of treatment, if any, that might be advantageous to the subject.",
    recommendation:
      "Add 'Alternatives' describing available alternative procedures or treatments and any decision to forgo treatment.",
    present_patterns: [
      /alternative/i,
      /(procedures?|treatments?|courses?\s+of\s+treatment)/i,
    ],
  }),
  presence({
    id: "HC-005",
    name: "Confidentiality of records",
    description: "Informed consent must describe how confidentiality of records is maintained.",
    citation: commonRule("116(b)(5)", "Confidentiality"),
    playbooks: [HC_PLAYBOOK_INFORMED_CONSENT],
    missing_title: "Confidentiality-of-records clause missing",
    missing_description: "No clause was found describing the confidentiality of subject records.",
    explanation:
      "§ 46.116(b)(5) requires a statement describing the extent, if any, to which confidentiality of records identifying the subject will be maintained, including any FDA inspection.",
    recommendation:
      "Add 'Confidentiality' describing how records are protected, who may access them (e.g., FDA, sponsor, IRB), and any limits on confidentiality.",
    present_patterns: [
      /confidential/i,
      /(records|information)/i,
      /(fda|sponsor|monitor|irb|institutional\s+review\s+board)/i,
    ],
  }),
  presence({
    id: "HC-006",
    name: "Voluntary participation + withdrawal right (no penalty / loss of benefits)",
    description:
      "Informed consent must state that participation is voluntary and the subject may withdraw without penalty / loss of benefits.",
    citation: commonRule("116(b)(8)", "Voluntary / withdrawal"),
    playbooks: [HC_PLAYBOOK_INFORMED_CONSENT],
    missing_title: "Voluntary / withdrawal clause missing",
    missing_description:
      "No clause was found stating participation is voluntary and the subject may withdraw without penalty.",
    explanation:
      "§ 46.116(b)(8) requires a statement that participation is voluntary, refusal will not involve penalty / loss of benefits, and the subject may discontinue at any time without penalty.",
    recommendation:
      "Add 'Voluntary Participation' stating that participation is voluntary, refusal involves no penalty, and the subject may withdraw at any time without loss of benefits.",
    present_patterns: [
      /(voluntary|voluntarily)/i,
      /(withdraw|discontinue|stop\s+participating)/i,
      /(no\s+penalty|without\s+penalty|no\s+loss\s+of\s+benefits)/i,
    ],
  }),
  presence({
    id: "HC-007",
    name: "Contact persons — research questions + research-related injury + subject rights",
    description:
      "Informed consent must identify contacts for research questions, research-related injuries, and subject rights.",
    citation: commonRule("116(b)(7)", "Contacts"),
    playbooks: [HC_PLAYBOOK_INFORMED_CONSENT],
    missing_title: "Contacts clause missing",
    missing_description:
      "No clause identifying research-question / injury / subject-rights contacts was found.",
    explanation:
      "§ 46.116(b)(7) requires an explanation of whom to contact for answers to research questions, for research-related injury, and for questions about subject rights.",
    recommendation:
      "Add 'Contact Information' listing the principal investigator (research questions), research-injury contact, and IRB contact (subject rights).",
    present_patterns: [
      /(contact|principal\s+investigator|pi)/i,
      /(injury|research.related)/i,
      /(irb|subjects?\s+rights?)/i,
    ],
  }),
  presence({
    id: "HC-008",
    name: "FDA-regulated study — § 50.25 additional elements (when applicable)",
    description:
      "If the study is FDA-regulated, the consent must include § 50.25 additional elements (clinicaltrials.gov statement, FDA inspection of records).",
    citation: fdaIc("25", "FDA additional elements"),
    playbooks: [HC_PLAYBOOK_INFORMED_CONSENT],
    missing_title: "FDA § 50.25 additional elements clause missing",
    missing_description:
      "No § 50.25 additional elements were found for an FDA-regulated study.",
    explanation:
      "21 C.F.R. § 50.25 requires additional elements for FDA-regulated trials including disclosure that the trial is registered on clinicaltrials.gov and that FDA may inspect records.",
    recommendation:
      "Add 'FDA Additional Elements' (when applicable) covering clinicaltrials.gov registration and FDA inspection of records.",
    present_patterns: [
      /(clinicaltrials\.gov|clinical\s+trial\s+registry)/i,
      /(fda\s+(may\s+)?inspect|fda\s+oversight)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "HC-009",
    name: "Compensation for injury (when applicable)",
    description:
      "For research involving more than minimal risk, the consent should describe compensation / medical treatment for research-related injury.",
    citation: commonRule("116(b)(6)", "Compensation"),
    playbooks: [HC_PLAYBOOK_INFORMED_CONSENT],
    missing_title: "Injury compensation / treatment clause missing",
    missing_description:
      "No clause addressing compensation or medical treatment for research-related injury was found.",
    explanation:
      "§ 46.116(b)(6) requires a statement (for research involving more than minimal risk) explaining whether compensation and medical treatments are available for injury.",
    recommendation:
      "Add 'Research-Related Injury' describing available compensation / medical treatment and where additional information can be obtained.",
    present_patterns: [
      /(injury|injuries|harm)/i,
      /(compensation|medical\s+(treatment|care))/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// J.4 — PHI Authorization (45 C.F.R. § 164.508). 9 rules: HC-010..HC-018.
// ────────────────────────────────────────────────────────────────────

const PHI_AUTHORIZATION_RULES: Rule[] = [
  presence({
    id: "HC-010",
    name: "Specific description of information to be used / disclosed",
    description:
      "Authorization must contain a specific and meaningful description of the information to be used or disclosed.",
    citation: hipaa("508(c)(1)(i)", "Specific information"),
    playbooks: [HC_PLAYBOOK_PHI_AUTH],
    missing_title: "Specific information description missing",
    missing_description:
      "No specific description of information to be used / disclosed was found.",
    explanation:
      "45 C.F.R. § 164.508(c)(1)(i) requires a specific and meaningful description of the information ('all medical records' is acceptable; 'any and all information' is not specific enough in practice).",
    recommendation:
      "Add 'Information to be Disclosed' with specific records (e.g., 'medical records dated [range]', 'lab results', 'imaging reports').",
    present_patterns: [
      /(specific|specifically)/i,
      /(information|records|phi|protected\s+health\s+information)/i,
      /(use|disclos)/i,
    ],
  }),
  presence({
    id: "HC-011",
    name: "Name of person / class authorized to make the use / disclosure",
    description:
      "Authorization must identify the person(s) or class authorized to make the use or disclosure.",
    citation: hipaa("508(c)(1)(ii)", "Authorized discloser"),
    playbooks: [HC_PLAYBOOK_PHI_AUTH],
    missing_title: "Authorized-discloser clause missing",
    missing_description:
      "No clause was found identifying the person / class authorized to make the disclosure.",
    explanation:
      "§ 164.508(c)(1)(ii) requires identification of the person(s) or class of persons authorized to make the requested use or disclosure.",
    recommendation:
      "Add a line identifying the discloser by name or class (e.g., 'Dr. Jane Smith', 'all treating providers at Acme Hospital').",
    present_patterns: [
      /(authoriz(e|ed)|permission).{0,40}(use|disclos)/is,
      /(provider|physician|hospital|covered\s+entity|name)/i,
    ],
  }),
  presence({
    id: "HC-012",
    name: "Name of person / class to whom the disclosure is made",
    description:
      "Authorization must identify the person(s) or class to whom the use or disclosure may be made.",
    citation: hipaa("508(c)(1)(iii)", "Recipient"),
    playbooks: [HC_PLAYBOOK_PHI_AUTH],
    missing_title: "Recipient identification missing",
    missing_description:
      "No clause was found identifying the recipient of the disclosure.",
    explanation:
      "§ 164.508(c)(1)(iii) requires identification of the recipient (person or class).",
    recommendation:
      "Add a line identifying the recipient (e.g., 'attorney John Doe', 'Acme Life Insurance underwriting department').",
    present_patterns: [
      /(recipient|to\s+whom|disclos.{0,40}to)/i,
      /(name|firm|insurance|attorney|family\s+member)/i,
    ],
  }),
  presence({
    id: "HC-013",
    name: "Description of purpose",
    description: "Authorization must describe the purpose of the use or disclosure.",
    citation: hipaa("508(c)(1)(iv)", "Purpose"),
    playbooks: [HC_PLAYBOOK_PHI_AUTH],
    missing_title: "Purpose clause missing",
    missing_description: "No clause was found describing the purpose of the use / disclosure.",
    explanation:
      "§ 164.508(c)(1)(iv) requires a description of each purpose ('at the request of the individual' is sufficient when the individual initiates the authorization).",
    recommendation:
      "Add 'Purpose' describing the specific purpose (e.g., 'for litigation', 'for life-insurance underwriting', 'at the request of the individual').",
    present_patterns: [
      /purpose/i,
      /(at\s+the\s+request\s+of|for\s+(litigation|life\s+insurance|treatment|payment|research|marketing))/i,
    ],
  }),
  presence({
    id: "HC-014",
    name: "Expiration date or event",
    description:
      "Authorization must include an expiration date or expiration event.",
    citation: hipaa("508(c)(1)(v)", "Expiration"),
    playbooks: [HC_PLAYBOOK_PHI_AUTH],
    missing_title: "Expiration date / event missing",
    missing_description:
      "No expiration date or expiration event was found.",
    explanation:
      "§ 164.508(c)(1)(v) requires an expiration date or an expiration event that relates to the individual or the purpose ('end of the research study' is acceptable; 'none' is generally not).",
    recommendation:
      "Add 'Expiration' with a specific date or a clear expiration event (e.g., 'one year from signature', 'upon conclusion of the litigation').",
    present_patterns: [
      /(expir(es?|ation|ing)|expir\b)/i,
      /((on|by)\s+\d|years?\s+from|end\s+of|conclusion\s+of)/i,
    ],
  }),
  presence({
    id: "HC-015",
    name: "Right to revoke authorization",
    description:
      "Authorization must include a statement of the individual's right to revoke in writing and the exceptions.",
    citation: hipaa("508(c)(2)(i)", "Right to revoke"),
    playbooks: [HC_PLAYBOOK_PHI_AUTH],
    missing_title: "Right-to-revoke statement missing",
    missing_description:
      "No statement of the right to revoke the authorization was found.",
    explanation:
      "§ 164.508(c)(2)(i) requires a statement of the right to revoke the authorization in writing, the exceptions to the right to revoke (e.g., actions already taken in reliance), and how to revoke.",
    recommendation:
      "Add 'Right to Revoke' stating the individual may revoke in writing at any time except to the extent actions have already been taken in reliance, and provide revocation instructions.",
    present_patterns: [
      /(revoke|revoking|revocation)/i,
      /(in\s+writing|written\s+notice)/i,
      /(except|reliance)/i,
    ],
  }),
  presence({
    id: "HC-016",
    name: "No conditioning on treatment / payment / enrollment / benefits",
    description:
      "Authorization must state whether treatment / payment / enrollment / benefits are conditioned on the authorization.",
    citation: hipaa("508(c)(2)(ii)", "Conditioning"),
    playbooks: [HC_PLAYBOOK_PHI_AUTH],
    missing_title: "Conditioning statement missing",
    missing_description:
      "No statement addressing whether treatment / payment / enrollment / benefits are conditioned on the authorization was found.",
    explanation:
      "§ 164.508(c)(2)(ii) requires a statement that treatment / payment / enrollment / eligibility for benefits cannot be conditioned on the authorization (with limited research / pre-enrollment underwriting exceptions).",
    recommendation:
      "Add 'No Conditioning' stating that treatment, payment, enrollment, or eligibility for benefits is not conditioned on signing the authorization (or recite the limited exception).",
    present_patterns: [
      /(treatment|payment|enrollment|eligibility|benefits)/i,
      /(not\s+conditioned|cannot\s+(refuse|condition)|will\s+not\s+(affect|condition))/i,
    ],
  }),
  presence({
    id: "HC-017",
    name: "Risk of re-disclosure by recipient",
    description:
      "Authorization must state that information disclosed may be re-disclosed by the recipient and no longer protected by HIPAA.",
    citation: hipaa("508(c)(2)(iii)", "Re-disclosure"),
    playbooks: [HC_PLAYBOOK_PHI_AUTH],
    missing_title: "Re-disclosure risk statement missing",
    missing_description: "No statement of re-disclosure risk was found.",
    explanation:
      "§ 164.508(c)(2)(iii) requires a statement of the potential that information disclosed pursuant to the authorization will be subject to re-disclosure by the recipient and no longer protected by HIPAA.",
    recommendation:
      "Add 'Re-disclosure' stating that information disclosed may be re-disclosed by the recipient and no longer protected by federal privacy rules.",
    present_patterns: [
      /(re.?disclos|further\s+disclos)/i,
      /(no\s+longer\s+protected|not\s+protected\s+by\s+(federal|hipaa))/i,
    ],
  }),
  presence({
    id: "HC-018",
    name: "Signature + date + authority (if not the individual)",
    description:
      "Authorization must be signed and dated by the individual or by a personal representative with authority recital.",
    citation: hipaa("508(c)(1)(vi)", "Signature / authority"),
    playbooks: [HC_PLAYBOOK_PHI_AUTH],
    missing_title: "Signature / date / authority clause missing",
    missing_description:
      "No signature / date / authority clause was found.",
    explanation:
      "§ 164.508(c)(1)(vi) requires the signature of the individual (or a personal representative with a description of authority) and the date.",
    recommendation:
      "Add signature line, date line, and (if signed by a representative) a description of the representative's authority (parent, guardian, power of attorney).",
    present_patterns: [
      /(signature|signed\s+by)/i,
      /(date)/i,
      /(personal\s+representative|parent|guardian|power\s+of\s+attorney|authority)/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// J.5 — NPP Acknowledgment. 7 rules: HC-019..HC-025.
// ────────────────────────────────────────────────────────────────────

const NPP_ACK_RULES: Rule[] = [
  presence({
    id: "HC-019",
    name: "Acknowledgment of receipt language",
    description: "Acknowledgment must affirm receipt of the Notice of Privacy Practices.",
    citation: hipaa("520(c)(2)(ii)", "Acknowledgment"),
    playbooks: [HC_PLAYBOOK_NPP_ACK],
    missing_title: "Acknowledgment-of-receipt language missing",
    missing_description:
      "No clause was found affirming receipt of the Notice of Privacy Practices.",
    explanation:
      "45 C.F.R. § 164.520(c)(2)(ii) requires the covered entity to make a good faith effort to obtain a written acknowledgment of receipt of the NPP.",
    recommendation:
      "Add 'Acknowledgment of Receipt' stating the individual has received the Notice of Privacy Practices.",
    present_patterns: [
      /(acknowledg(e|ment|ing)?\s+(of\s+)?receipt|i\s+(have|hereby)\s+receiv)/i,
      /(notice\s+of\s+privacy\s+practices|npp)/i,
    ],
  }),
  presence({
    id: "HC-020",
    name: "Date of receipt",
    description: "Acknowledgment must include the date of receipt.",
    citation: hipaa("520(c)(2)(ii)", "Date"),
    playbooks: [HC_PLAYBOOK_NPP_ACK],
    missing_title: "Date of receipt missing",
    missing_description: "No date of receipt was found.",
    explanation:
      "The acknowledgment must include the date the NPP was received so the covered entity can document compliance with the timing requirements.",
    recommendation: "Add a 'Date Received' line.",
    present_patterns: [
      /(date\s+(received|of\s+receipt)|received\s+on|signed\s+on)/i,
      /\d/,
    ],
  }),
  presence({
    id: "HC-021",
    name: "Signature of individual / personal representative",
    description:
      "Acknowledgment must be signed by the individual or a personal representative with authority recital.",
    citation: hipaa("520(c)(2)(ii)", "Signature"),
    playbooks: [HC_PLAYBOOK_NPP_ACK],
    missing_title: "Signature clause missing",
    missing_description:
      "No signature clause was found.",
    explanation:
      "The acknowledgment must be signed by the individual or a personal representative. Identify the representative's authority where applicable.",
    recommendation:
      "Add 'Signature' and (if signed by a representative) a description of authority (parent, guardian, POA).",
    present_patterns: [
      /(signature|signed|sign\s+here)/i,
      /(individual|patient|representative|guardian)/i,
    ],
  }),
  presence({
    id: "HC-022",
    name: "Good-faith-effort failure recital (if applicable)",
    description:
      "If acknowledgment was not obtained, the form should document the good-faith effort and the reason.",
    citation: hipaa("520(c)(2)(ii)", "Good-faith effort"),
    playbooks: [HC_PLAYBOOK_NPP_ACK],
    missing_title: "Good-faith-effort failure recital missing",
    missing_description:
      "No clause was found documenting the good-faith effort to obtain the acknowledgment.",
    explanation:
      "§ 164.520(c)(2)(ii) requires the covered entity to document the good faith effort and the reason the acknowledgment was not obtained if the individual declines to sign.",
    recommendation:
      "Add 'Good Faith Effort' field for cases where the patient does not sign — record the effort and the reason (emergency, refusal, language barrier).",
    present_patterns: [
      /(good\s+faith\s+effort|unable\s+to\s+obtain)/i,
      /(reason|declined|refused|emergency)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "HC-023",
    name: "Statement of right to a copy of the NPP",
    description: "Acknowledgment should state the individual's right to a copy of the NPP.",
    citation: hipaa("520(c)(2)(iii)", "Copy of NPP"),
    playbooks: [HC_PLAYBOOK_NPP_ACK],
    missing_title: "Right-to-copy statement missing",
    missing_description: "No statement of the right to a copy of the NPP was found.",
    explanation:
      "Section 164.520(c)(2)(iii): individuals have a right to a paper copy of the NPP upon request.",
    recommendation:
      "Add 'Right to Copy' stating the individual may request a paper copy of the NPP at any time.",
    present_patterns: [
      /(right\s+to\s+(a\s+)?copy|paper\s+copy|copy\s+of\s+the\s+notice)/i,
      /(upon\s+request|at\s+any\s+time)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "HC-024",
    name: "Covered entity identification",
    description: "Acknowledgment must identify the covered entity.",
    citation: hipaa("520(c)(2)(ii)", "Covered entity"),
    playbooks: [HC_PLAYBOOK_NPP_ACK],
    missing_title: "Covered-entity identification missing",
    missing_description: "No covered-entity identification was found.",
    explanation:
      "The acknowledgment should identify the covered entity (provider / health plan) so individuals can later request a copy or file a complaint.",
    recommendation:
      "Add identification of the covered entity (name and any DBA) at the top of the acknowledgment.",
    present_patterns: [
      /(covered\s+entity|provider|hospital|clinic|health\s+plan)/i,
      /(name)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "HC-025",
    name: "Retention by covered entity",
    description:
      "Acknowledgment template should reflect the § 164.530(j) 6-year retention requirement.",
    citation: hcPractice(
      "hipaa-retention",
      "45 C.F.R. § 164.530(j) — 6-year retention",
      "https://www.law.cornell.edu/cfr/text/45/164.530",
    ),
    playbooks: [HC_PLAYBOOK_NPP_ACK],
    missing_title: "Retention notation missing",
    missing_description:
      "No notation reflecting the 6-year retention requirement was found.",
    explanation:
      "§ 164.530(j)(2) requires retention of NPP acknowledgments for 6 years from creation or last effective date. A template should reflect that retention is needed.",
    recommendation:
      "Add 'Retention' notation (or process reference) noting 6-year retention per § 164.530(j).",
    present_patterns: [
      /(retain(ed|ing)?|retention|preserved?)/i,
      /(6\s+years?|six\s+years?|164\.530)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate. 25 rules total.
// ────────────────────────────────────────────────────────────────────

export const HEALTHCARE_RULES: Rule[] = [
  ...INFORMED_CONSENT_RULES,
  ...PHI_AUTHORIZATION_RULES,
  ...NPP_ACK_RULES,
];

export { INFORMED_CONSENT_RULES, PHI_AUTHORIZATION_RULES, NPP_ACK_RULES };
