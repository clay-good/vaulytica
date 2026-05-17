/**
 * v4 Privacy (extended) ruleset — 40 rules
 * (spec-v4.md §6.I, Step 52).
 *
 * Six new playbooks: cookie / tracking notice, HIPAA Notice of
 * Privacy Practices, GDPR Art. 30 records of processing activities
 * (ROPA), GDPR Art. 35 data protection impact assessment (DPIA),
 * vendor security questionnaire (SIG / CAIQ-style), and data-incident
 * notification template. v3 BAA / DPA-GDPR / DPA-US-state / SCC /
 * IDTA / privacy-policy continue under their existing rulesets.
 *
 * Rule ids are flat `PRV-NNN` (001..040).
 */

import type { Rule } from "../../../finding.js";
import { buildV4PresenceRule, type V4PresenceSpec } from "../_helpers.js";
import {
  PRV_PLAYBOOK_COOKIE,
  PRV_PLAYBOOK_NPP,
  PRV_PLAYBOOK_ROPA,
  PRV_PLAYBOOK_DPIA,
  PRV_PLAYBOOK_VSQ,
  PRV_PLAYBOOK_INCIDENT,
  gdprArt,
  ePrivacy,
  ccpa,
  hipaa,
  stateBreach,
  nistIso,
  edpb,
} from "./_helpers.js";

const CATEGORY = "privacy-extended";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// I.7 — Cookie / tracking notice. 6 rules: PRV-001..PRV-006.
// ────────────────────────────────────────────────────────────────────

const COOKIE_NOTICE_RULES: Rule[] = [
  presence({
    id: "PRV-001",
    name: "Cookie categories disclosed (strictly necessary / functional / analytics / advertising)",
    description:
      "Cookie notice must categorize cookies (strictly necessary, functional / preferences, analytics / performance, targeting / advertising).",
    citation: ePrivacy(),
    playbooks: [PRV_PLAYBOOK_COOKIE],
    missing_title: "Cookie categories clause missing",
    missing_description:
      "No clause was found categorizing cookies (strictly necessary / functional / analytics / advertising).",
    explanation:
      "ePrivacy Directive Art. 5(3) requires informed consent for non-strictly-necessary cookies. EDPB / ICO / CNIL guidance treats a categorized inventory as the baseline.",
    recommendation:
      "Add a 'Categories of Cookies' section listing strictly necessary, functional, analytics, and targeting / advertising cookies with concrete examples.",
    present_patterns: [
      /(strictly\s+necessary|essential)/i,
      /(functional|preferences?)/i,
      /(analytics|performance|targeting|advertising)/i,
    ],
  }),
  presence({
    id: "PRV-002",
    name: "Consent mechanism (opt-in for non-essential)",
    description:
      "Cookie notice must disclose the consent mechanism for non-essential cookies (banner / preference center).",
    citation: ePrivacy(),
    playbooks: [PRV_PLAYBOOK_COOKIE],
    missing_title: "Consent mechanism clause missing",
    missing_description: "No consent mechanism for non-essential cookies was disclosed.",
    explanation:
      "Under ePrivacy Art. 5(3) + GDPR Art. 7, consent must be freely given, specific, informed, and unambiguous, by clear affirmative action; pre-ticked boxes are not consent (CJEU *Planet49*).",
    recommendation:
      "Add 'How We Obtain Consent' describing the banner / preference center, the affirmative-action requirement, and how the user can change consent later.",
    present_patterns: [
      /consent/i,
      /(banner|preference\s+center|cookie\s+preference)/i,
      /(accept|reject|manage)/i,
    ],
  }),
  presence({
    id: "PRV-003",
    name: "Per-cookie disclosure — name / provider / purpose / duration",
    description:
      "Cookie notice should disclose per-cookie details: name, provider, purpose, and retention duration.",
    citation: edpb(
      "cookie-guidance",
      "EDPB Guidelines 5/2020 on consent + ICO cookie guidance",
    ),
    playbooks: [PRV_PLAYBOOK_COOKIE],
    missing_title: "Per-cookie disclosure table missing",
    missing_description:
      "No per-cookie disclosure (name / provider / purpose / duration) was found.",
    explanation:
      "ICO / CNIL / Garante guidance: users need to know which specific cookies are set, by whom, why, and for how long. A tabular disclosure is the practical norm.",
    recommendation:
      "Add a 'Cookies We Use' table with columns: Name, Provider (first / third party), Purpose, Retention (session / N days).",
    present_patterns: [
      /(name|cookie\s+name)/i,
      /(provider|third.?party)/i,
      /(purpose|duration|retention|expir)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "PRV-004",
    name: "Withdraw consent — instructions",
    description:
      "Cookie notice must explain how users can withdraw consent (as easy as giving it — GDPR Art. 7(3)).",
    citation: gdprArt("7", "Conditions for consent"),
    playbooks: [PRV_PLAYBOOK_COOKIE],
    missing_title: "Withdraw-consent instructions missing",
    missing_description: "No clause was found explaining how users can withdraw cookie consent.",
    explanation:
      "GDPR Art. 7(3): 'It shall be as easy to withdraw as to give consent.' EDPB Guidelines 5/2020 emphasize equal-prominence withdraw.",
    recommendation:
      "Add 'How to Withdraw Consent' with link / button to the cookie-preference center; explain that withdrawal does not affect prior lawful processing.",
    present_patterns: [
      /(withdraw|change|update|revoke).{0,40}consent/i,
      /(cookie\s+(preferences?|settings)|preference\s+center)/i,
    ],
  }),
  presence({
    id: "PRV-005",
    name: "CCPA / CPRA opt-out (Sale / Share / Cross-context targeted advertising)",
    description:
      "Cookie notice for CCPA / CPRA-covered businesses must explain the right to opt out of sale / share / cross-context targeted advertising (GPC support).",
    citation: ccpa("135"),
    playbooks: [PRV_PLAYBOOK_COOKIE],
    missing_title: "CCPA / CPRA opt-out clause missing",
    missing_description: "No CCPA / CPRA opt-out or GPC-support clause was found.",
    explanation:
      "CCPA § 1798.135 + CPRA + CPPA regulations require a 'Do Not Sell or Share My Personal Information' link, recognition of the Global Privacy Control (GPC) signal, and disclosure of cross-context targeted advertising.",
    recommendation:
      "Add a 'Do Not Sell or Share' link, an explanation of GPC processing, and treatment of cross-context targeted advertising.",
    present_patterns: [
      /(do\s+not\s+sell|do\s+not\s+share)/i,
      /(opt.?out|opt\s+out)/i,
      /(gpc|global\s+privacy\s+control|cross.context)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "PRV-006",
    name: "Third-party recipients / international transfers",
    description:
      "Cookie notice must disclose third-party recipients and any international transfers.",
    citation: gdprArt("13", "Information to be provided"),
    playbooks: [PRV_PLAYBOOK_COOKIE],
    missing_title: "Third-party recipients / transfers clause missing",
    missing_description:
      "No clause was found disclosing third-party cookie recipients or international transfers.",
    explanation:
      "GDPR Art. 13(1)(e)–(f) requires disclosure of recipients and international transfer mechanisms. Cookie data routinely flows to third-party analytics / ad-tech in the US and elsewhere.",
    recommendation:
      "Add 'Third-Party Recipients' and 'International Transfers' (e.g., 'Google Analytics may transfer data to the US under the EU-US Data Privacy Framework').",
    present_patterns: [
      /(third.?party|recipients?)/i,
      /(international\s+transfers?|outside\s+the\s+(eu|eea|uk))/i,
      /(scc|dpf|data\s+privacy\s+framework)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// I.8 — HIPAA Notice of Privacy Practices. 8 rules: PRV-007..PRV-014.
// ────────────────────────────────────────────────────────────────────

const NPP_RULES: Rule[] = [
  presence({
    id: "PRV-007",
    name: "Header statement — 45 C.F.R. § 164.520(b)(1)(i)",
    description:
      "NPP must include the prominent header statement: 'THIS NOTICE DESCRIBES HOW MEDICAL INFORMATION ABOUT YOU MAY BE USED AND DISCLOSED AND HOW YOU CAN GET ACCESS TO THIS INFORMATION. PLEASE REVIEW IT CAREFULLY.'",
    citation: hipaa("520(b)(1)(i)", "NPP header"),
    playbooks: [PRV_PLAYBOOK_NPP],
    missing_title: "Required NPP header statement missing",
    missing_description: "The required § 164.520(b)(1)(i) header statement was not found.",
    explanation:
      "45 C.F.R. § 164.520(b)(1)(i) prescribes the specific NPP header statement; this is one of the few HIPAA texts that must appear verbatim.",
    recommendation:
      "Add the prescribed header: 'THIS NOTICE DESCRIBES HOW MEDICAL INFORMATION ABOUT YOU MAY BE USED AND DISCLOSED AND HOW YOU CAN GET ACCESS TO THIS INFORMATION. PLEASE REVIEW IT CAREFULLY.'",
    present_patterns: [
      /this\s+notice\s+describes\s+how\s+medical\s+information/i,
      /please\s+review\s+it\s+carefully/i,
    ],
  }),
  presence({
    id: "PRV-008",
    name: "Uses and disclosures — TPO + required + permitted + authorization",
    description:
      "NPP must describe uses and disclosures for treatment, payment, and health-care operations (TPO), plus required, permitted, and authorization-based disclosures.",
    citation: hipaa("520(b)(1)(ii)", "Uses and disclosures"),
    playbooks: [PRV_PLAYBOOK_NPP],
    missing_title: "Uses-and-disclosures section missing",
    missing_description: "No section was found describing TPO and other uses / disclosures.",
    explanation:
      "§ 164.520(b)(1)(ii)(A)–(D) requires the NPP to describe each category of uses / disclosures, with at least one example per category.",
    recommendation:
      "Add 'Uses and Disclosures' covering Treatment, Payment, Health Care Operations, and other permitted / required uses, with one example each.",
    present_patterns: [
      /(treatment|payment|health\s+care\s+operations|tpo)/i,
      /(uses\s+and\s+disclosures?|use\s+or\s+disclos)/i,
    ],
  }),
  presence({
    id: "PRV-009",
    name: "Individual rights enumeration — § 164.520(b)(1)(iv)",
    description:
      "NPP must enumerate individual rights: access, amendment, accounting, restriction, confidential communications, paper copy, breach notification.",
    citation: hipaa("520(b)(1)(iv)", "Individual rights in NPP"),
    playbooks: [PRV_PLAYBOOK_NPP],
    missing_title: "Individual-rights enumeration missing",
    missing_description: "No section enumerating individual rights was found.",
    explanation:
      "§ 164.520(b)(1)(iv) requires the NPP to describe the individual's rights, including the right to access PHI, request amendment, receive an accounting, request restrictions, request confidential communications, obtain a paper copy, and receive breach notifications.",
    recommendation:
      "Add 'Your Rights' with bullets for access, amendment, accounting, restrictions, confidential communications, paper copy, and breach notification.",
    present_patterns: [
      /(right\s+to\s+(access|inspect|copy))/i,
      /(right\s+to\s+(amend|amendment))/i,
      /(accounting\s+of\s+disclosures|breach\s+notification)/i,
    ],
  }),
  presence({
    id: "PRV-010",
    name: "Covered entity duties statement",
    description:
      "NPP must describe the covered entity's duties (maintain privacy, provide notice, abide by current notice).",
    citation: hipaa("520(b)(1)(v)", "Covered entity duties"),
    playbooks: [PRV_PLAYBOOK_NPP],
    missing_title: "Covered-entity-duties statement missing",
    missing_description: "No statement of the covered entity's duties was found.",
    explanation:
      "§ 164.520(b)(1)(v): the NPP must state that the covered entity is required by law to maintain privacy, provide notice, and abide by the terms of the currently effective notice.",
    recommendation:
      "Add 'Our Duties' with the required statement: required by law to maintain privacy, provide notice, and abide by the terms of the current notice.",
    present_patterns: [
      /(required\s+by\s+law|our\s+duties)/i,
      /(maintain\s+the\s+privacy|protect\s+(your|the)\s+(health\s+)?information)/i,
      /(abide\s+by\s+the\s+terms|provide\s+notice)/i,
    ],
  }),
  presence({
    id: "PRV-011",
    name: "Right to complain — HHS / OCR + no retaliation",
    description:
      "NPP must inform individuals of the right to complain to the covered entity and to HHS, and that the entity will not retaliate.",
    citation: hipaa("520(b)(1)(vi)", "Right to complain"),
    playbooks: [PRV_PLAYBOOK_NPP],
    missing_title: "Right-to-complain clause missing",
    missing_description:
      "No clause was found informing individuals of the right to complain to HHS / OCR without retaliation.",
    explanation:
      "§ 164.520(b)(1)(vi) requires the NPP to inform individuals that they may complain to the covered entity and to the Secretary of HHS, and that no retaliatory action will be taken.",
    recommendation:
      "Add 'Complaints' explaining how to file a complaint with the covered entity and with the U.S. Department of Health & Human Services Office for Civil Rights (HHS OCR), and stating no retaliation.",
    present_patterns: [
      /(complain|complaint|file\s+a\s+complaint)/i,
      /(hhs|secretary|office\s+for\s+civil\s+rights|ocr)/i,
      /(no\s+retaliation|will\s+not\s+retaliate)/i,
    ],
  }),
  presence({
    id: "PRV-012",
    name: "Effective date of notice",
    description: "NPP must include an effective date.",
    citation: hipaa("520(b)(1)(v)(C)", "Effective date"),
    playbooks: [PRV_PLAYBOOK_NPP],
    missing_title: "Effective-date clause missing",
    missing_description: "No effective date was found.",
    explanation:
      "§ 164.520(b)(1)(v)(C) requires the NPP to state its effective date. Without it, individuals cannot tell which version applies.",
    recommendation: "Add 'Effective Date' with the date the notice took effect.",
    present_patterns: [
      /(effective\s+date|effective\s+as\s+of)/i,
      /(20\d{2}|19\d{2})/,
    ],
  }),
  presence({
    id: "PRV-013",
    name: "Contact information for privacy questions",
    description: "NPP must provide contact information for privacy questions.",
    citation: hipaa("520(b)(1)(vii)", "Contact information"),
    playbooks: [PRV_PLAYBOOK_NPP],
    missing_title: "Contact-information clause missing",
    missing_description: "No contact-information clause was found.",
    explanation:
      "§ 164.520(b)(1)(vii) requires the NPP to provide a name / title and telephone number for someone individuals can contact for further information.",
    recommendation:
      "Add 'Contact Us' with the privacy officer's name / title, phone number, and address.",
    present_patterns: [
      /(privacy\s+(officer|official)|contact\s+us)/i,
      /(phone|telephone|email|@)/i,
    ],
  }),
  presence({
    id: "PRV-014",
    name: "Specific high-sensitivity disclosure provisions (substance use / mental health / HIV / genetic)",
    description:
      "NPP should address specific protections that may apply to substance use, mental health, HIV, or genetic information.",
    citation: hipaa("520(b)(1)(ii)(E)", "Heightened disclosures"),
    playbooks: [PRV_PLAYBOOK_NPP],
    missing_title: "High-sensitivity disclosures clause missing",
    missing_description:
      "No clause was found addressing substance-use / mental-health / HIV / genetic information.",
    explanation:
      "42 C.F.R. Part 2 (substance use), 42 U.S.C. § 290dd-2, state mental-health-record statutes, GINA (genetic information), and many state HIV-confidentiality statutes impose stricter disclosure rules. NPPs covering these categories should describe the heightened protection.",
    recommendation:
      "Add a paragraph addressing substance-use disorder (Part 2), mental-health, HIV / AIDS, and genetic (GINA) information protections where applicable.",
    present_patterns: [
      /(substance\s+(use|abuse)|part\s+2|42\s+c\.?f\.?r\.?\s+part\s+2)/i,
      /(mental\s+health|psychotherapy)/i,
      /(hiv|aids|genetic|gina)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// I.9 — ROPA (GDPR Art. 30). 6 rules: PRV-015..PRV-020.
// ────────────────────────────────────────────────────────────────────

const ROPA_RULES: Rule[] = [
  presence({
    id: "PRV-015",
    name: "Controller / DPO identification — Art. 30(1)(a)",
    description: "ROPA must identify controller (and joint controller / representative / DPO).",
    citation: gdprArt("30", "Records of processing activities"),
    playbooks: [PRV_PLAYBOOK_ROPA],
    missing_title: "Controller / DPO identification missing",
    missing_description:
      "No clause was found identifying the controller, joint controllers, representative, or DPO.",
    explanation:
      "Art. 30(1)(a) requires the record to contain the name and contact details of the controller, any joint controllers, the controller's representative (if applicable), and the DPO.",
    recommendation:
      "Add a 'Controller / DPO Identification' section with name, contact details, joint-controller info, and DPO contact.",
    present_patterns: [
      /(controller|joint\s+controller|representative)/i,
      /(data\s+protection\s+officer|dpo)/i,
      /(contact|address|email)/i,
    ],
  }),
  presence({
    id: "PRV-016",
    name: "Purposes of processing — Art. 30(1)(b)",
    description: "ROPA must state the purposes of processing.",
    citation: gdprArt("30", "Purposes"),
    playbooks: [PRV_PLAYBOOK_ROPA],
    missing_title: "Purposes of processing missing",
    missing_description: "No section listing purposes of processing was found.",
    explanation:
      "Art. 30(1)(b) requires the record to state the purposes of the processing — concrete, specific, and explicit.",
    recommendation:
      "Add 'Purposes of Processing' with each distinct purpose (HR / payroll, customer support, marketing, etc.).",
    present_patterns: [
      /(purpose|purposes\s+of\s+(the\s+)?processing)/i,
      /(art\.?\s*30|article\s+30)/i,
    ],
  }),
  presence({
    id: "PRV-017",
    name: "Categories of data subjects and personal data — Art. 30(1)(c)",
    description:
      "ROPA must describe the categories of data subjects and the categories of personal data.",
    citation: gdprArt("30", "Categories"),
    playbooks: [PRV_PLAYBOOK_ROPA],
    missing_title: "Categories of data subjects / personal data missing",
    missing_description:
      "No section was found describing categories of data subjects and personal data.",
    explanation:
      "Art. 30(1)(c) requires the categories of data subjects (employees, customers, suppliers, etc.) AND categories of personal data (identification, contact, financial, special categories).",
    recommendation:
      "Add 'Categories' separately enumerating data-subject categories and personal-data categories (identifying any Art. 9 special categories).",
    present_patterns: [
      /categor(y|ies)\s+of\s+(data\s+subjects?|personal\s+data)/i,
      /(employees?|customers?|suppliers?|users?)/i,
      /(special\s+categor|article\s+9|art\.?\s*9)/i,
    ],
  }),
  presence({
    id: "PRV-018",
    name: "Recipients — Art. 30(1)(d)",
    description: "ROPA must enumerate categories of recipients.",
    citation: gdprArt("30", "Recipients"),
    playbooks: [PRV_PLAYBOOK_ROPA],
    missing_title: "Recipients section missing",
    missing_description: "No section enumerating categories of recipients was found.",
    explanation:
      "Art. 30(1)(d) requires categories of recipients to whom personal data have been or will be disclosed, including recipients in third countries or international organizations.",
    recommendation:
      "Add 'Categories of Recipients' enumerating processors, joint controllers, third-country recipients, and any law-enforcement / regulator disclosures.",
    present_patterns: [
      /recipients?/i,
      /(processors?|subprocessors?|joint\s+controllers?)/i,
      /(third\s+countr|international\s+organi[sz]ation)/i,
    ],
  }),
  presence({
    id: "PRV-019",
    name: "International transfers — Art. 30(1)(e)",
    description:
      "ROPA must identify transfers to third countries with the safeguards in place.",
    citation: gdprArt("30", "Transfers"),
    playbooks: [PRV_PLAYBOOK_ROPA],
    missing_title: "International-transfers clause missing",
    missing_description:
      "No clause was found identifying third-country transfers or the safeguards used.",
    explanation:
      "Art. 30(1)(e) requires identification of third-country transfers, including documentation of the suitable safeguards (Art. 46) or derogations (Art. 49).",
    recommendation:
      "Add 'International Transfers' listing third-country destinations and the safeguards (adequacy decision, SCCs + TIA, BCRs, or Art. 49 derogation).",
    present_patterns: [
      /(transfers?\s+to\s+(third|outside))/i,
      /(adequacy|scc|standard\s+contractual\s+clauses?|bcr|binding\s+corporate\s+rules)/i,
      /(art\.?\s*46|art\.?\s*49)/i,
    ],
  }),
  presence({
    id: "PRV-020",
    name: "Retention periods and security measures — Art. 30(1)(f)–(g)",
    description:
      "ROPA must state retention periods (where possible) and a general description of Art. 32 security measures.",
    citation: gdprArt("30", "Retention and security"),
    playbooks: [PRV_PLAYBOOK_ROPA],
    missing_title: "Retention / security measures section missing",
    missing_description:
      "No section was found describing retention periods or Art. 32 security measures.",
    explanation:
      "Art. 30(1)(f)–(g) requires (where possible) the envisaged time limits for erasure AND a general description of the technical and organisational security measures (Art. 32).",
    recommendation:
      "Add 'Retention' (per category / purpose) and 'Security Measures' summarizing encryption, access control, pseudonymisation, and resilience controls.",
    present_patterns: [
      /(retention|retention\s+period|time\s+limits|erasure)/i,
      /(security\s+measures?|technical\s+and\s+organi[sz]ational|art\.?\s*32|article\s+32)/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// I.10 — DPIA (GDPR Art. 35). 6 rules: PRV-021..PRV-026.
// ────────────────────────────────────────────────────────────────────

const DPIA_RULES: Rule[] = [
  presence({
    id: "PRV-021",
    name: "Systematic description of processing — Art. 35(7)(a)",
    description:
      "DPIA must contain a systematic description of the envisaged processing operations and purposes.",
    citation: gdprArt("35", "DPIA contents"),
    playbooks: [PRV_PLAYBOOK_DPIA],
    missing_title: "Systematic description clause missing",
    missing_description:
      "No section was found systematically describing the envisaged processing.",
    explanation:
      "Art. 35(7)(a) requires the DPIA to describe the processing operations, purposes, and (where applicable) the legitimate-interest pursued.",
    recommendation:
      "Add 'Description of Processing' with operations, data flows, purposes, and (where applicable) the legitimate interest pursued.",
    present_patterns: [
      /(description\s+of\s+(the\s+)?processing|systematic\s+description)/i,
      /(purpose|legitimate\s+interest)/i,
    ],
  }),
  presence({
    id: "PRV-022",
    name: "Necessity and proportionality assessment — Art. 35(7)(b)",
    description:
      "DPIA must assess the necessity and proportionality of processing in relation to the purposes.",
    citation: gdprArt("35", "Necessity and proportionality"),
    playbooks: [PRV_PLAYBOOK_DPIA],
    missing_title: "Necessity / proportionality assessment missing",
    missing_description:
      "No section was found assessing necessity and proportionality.",
    explanation:
      "Art. 35(7)(b) requires an assessment of whether the processing is necessary and proportionate; if it is not, the processing should be modified.",
    recommendation:
      "Add 'Necessity and Proportionality' showing data-minimisation, purpose-limitation, accuracy, and storage-limitation analysis.",
    present_patterns: [
      /(necessity\s+and\s+proportionality|necessary\s+and\s+proportionate)/i,
      /(data\s+minimi[sz]ation|purpose\s+limitation)/i,
    ],
  }),
  presence({
    id: "PRV-023",
    name: "Risk assessment — likelihood and severity",
    description:
      "DPIA must assess the risks to the rights and freedoms of data subjects (likelihood × severity).",
    citation: gdprArt("35", "Risk assessment"),
    playbooks: [PRV_PLAYBOOK_DPIA],
    missing_title: "Risk-assessment clause missing",
    missing_description: "No risk assessment (likelihood + severity) was found.",
    explanation:
      "Art. 35(7)(c) requires assessment of risks to rights and freedoms; the EDPB / CNIL methodology evaluates likelihood and severity for each risk scenario.",
    recommendation:
      "Add 'Risk Assessment' rating each identified risk by likelihood and severity, with a residual-risk view after mitigations.",
    present_patterns: [
      /(risk(s)?\s+(to|assessment)|rights\s+and\s+freedoms)/i,
      /(likelihood|severity|impact)/i,
    ],
  }),
  presence({
    id: "PRV-024",
    name: "Mitigation measures and safeguards",
    description:
      "DPIA must describe the measures envisaged to address the risks (technical, organisational, contractual).",
    citation: gdprArt("35", "Mitigations"),
    playbooks: [PRV_PLAYBOOK_DPIA],
    missing_title: "Mitigation-measures clause missing",
    missing_description: "No section was found describing mitigation measures and safeguards.",
    explanation:
      "Art. 35(7)(d) requires the measures envisaged to address the risks, including safeguards, security measures, and mechanisms to demonstrate compliance.",
    recommendation:
      "Add 'Mitigations and Safeguards' covering technical (encryption, pseudonymisation, access control), organisational (training, policy), and contractual (DPA, SCCs) measures.",
    present_patterns: [
      /(measures?\s+(envisaged|to\s+address)|mitigat(e|ion|ions))/i,
      /(safeguards?|controls?)/i,
    ],
  }),
  presence({
    id: "PRV-025",
    name: "DPO consultation",
    description:
      "DPIA must record the DPO's advice (Art. 35(2)) and the controller's decision (whether followed).",
    citation: gdprArt("35", "DPO consultation"),
    playbooks: [PRV_PLAYBOOK_DPIA],
    missing_title: "DPO consultation clause missing",
    missing_description: "No record of DPO consultation was found.",
    explanation:
      "Art. 35(2) requires the controller to seek the advice of the DPO when carrying out a DPIA. Documentation evidences the consultation (and any non-acceptance with reasons).",
    recommendation:
      "Add 'DPO Advice' summarizing the DPO's input and the controller's response.",
    present_patterns: [
      /(dpo|data\s+protection\s+officer)/i,
      /(advice|consult|consultation|opinion)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "PRV-026",
    name: "Prior consultation trigger (Art. 36)",
    description:
      "If residual high risk remains, DPIA must record the Art. 36 prior-consultation analysis.",
    citation: gdprArt("36", "Prior consultation"),
    playbooks: [PRV_PLAYBOOK_DPIA],
    missing_title: "Art. 36 prior-consultation analysis missing",
    missing_description: "No clause was found addressing Art. 36 prior-consultation.",
    explanation:
      "Art. 36(1) requires the controller to consult the supervisory authority if the DPIA shows the processing would result in a high risk in the absence of mitigations.",
    recommendation:
      "Add 'Art. 36 Prior Consultation' stating whether residual high risk remains and, if so, that the supervisory authority will be consulted.",
    present_patterns: [
      /(prior\s+consultation|supervisory\s+authority)/i,
      /(art\.?\s*36|article\s+36)/i,
      /(high\s+risk|residual\s+risk)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// I.11 — Vendor security questionnaire (SIG / CAIQ). 7 rules: PRV-027..PRV-033.
// ────────────────────────────────────────────────────────────────────

const VENDOR_QUESTIONNAIRE_RULES: Rule[] = [
  presence({
    id: "PRV-027",
    name: "Information security policy / governance",
    description:
      "VSQ must confirm a written information security policy approved by management.",
    citation: nistIso(),
    playbooks: [PRV_PLAYBOOK_VSQ],
    missing_title: "Information security policy clause missing",
    missing_description:
      "No clause was found confirming a written information security policy.",
    explanation:
      "ISO 27001 A.5 and NIST CSF Govern require a documented, management-approved security policy. Absent vendor must remediate before processing.",
    recommendation:
      "Add 'Information Security Policy' confirming a written policy approved by management with stated review cadence.",
    present_patterns: [
      /(information\s+security\s+policy|security\s+policy)/i,
      /(approved|reviewed)/i,
    ],
  }),
  presence({
    id: "PRV-028",
    name: "Access control — role-based, least privilege, MFA",
    description:
      "VSQ must describe access control: RBAC, least privilege, MFA, and quarterly access reviews.",
    citation: nistIso(),
    playbooks: [PRV_PLAYBOOK_VSQ],
    missing_title: "Access control clause missing",
    missing_description: "No access-control description was found.",
    explanation:
      "ISO 27001 A.8 / A.9 and NIST CSF Protect.AC require RBAC, least privilege, MFA, and periodic access reviews. Customers expect specific affirmation.",
    recommendation:
      "Add 'Access Control' describing RBAC, least-privilege provisioning, MFA enforcement (incl. for admins), and quarterly access reviews.",
    present_patterns: [
      /(access\s+control|rbac|role.based)/i,
      /(mfa|multi.?factor|2fa|sso)/i,
      /(least\s+privilege|access\s+review)/i,
    ],
  }),
  presence({
    id: "PRV-029",
    name: "Encryption at rest and in transit",
    description: "VSQ must confirm encryption at rest and in transit with stated algorithms.",
    citation: nistIso(),
    playbooks: [PRV_PLAYBOOK_VSQ],
    missing_title: "Encryption-at-rest/in-transit clause missing",
    missing_description: "No encryption description (at rest and in transit) was found.",
    explanation:
      "ISO 27001 A.10 and NIST CSF Protect.DS require encryption controls. Modern practice: AES-256 at rest, TLS 1.2+ in transit; identify any plaintext fallback.",
    recommendation:
      "Add 'Encryption' confirming AES-256 (or equivalent) at rest and TLS 1.2+ in transit; identify any storage that is not encrypted.",
    present_patterns: [
      /(encryption|encrypted)/i,
      /(at\s+rest|in\s+transit)/i,
      /(aes.?256|tls\s+1\.[23]|rsa|ssh)/i,
    ],
  }),
  presence({
    id: "PRV-030",
    name: "Audit / certifications — SOC 2 / ISO 27001",
    description:
      "VSQ must identify current third-party audits / certifications and provide a contact for report distribution.",
    citation: nistIso(),
    playbooks: [PRV_PLAYBOOK_VSQ],
    missing_title: "Audit / certifications clause missing",
    missing_description:
      "No clause was found identifying SOC 2 / ISO 27001 / equivalent audits.",
    explanation:
      "Customers rely on third-party attestations (SOC 2 Type II, ISO 27001, HITRUST) to validate VSQ claims.",
    recommendation:
      "Add 'Audits / Certifications' listing current attestations (SOC 2 Type II, ISO 27001, HITRUST, FedRAMP) and contact for report distribution under NDA.",
    present_patterns: [
      /(soc\s*2|aicpa)/i,
      /(iso\s*27001|hitrust|fedramp|pci\s*dss)/i,
      /(audit|certification|attestation)/i,
    ],
  }),
  presence({
    id: "PRV-031",
    name: "Vulnerability management + penetration testing",
    description:
      "VSQ must describe patch / vulnerability management cadence and annual third-party penetration testing.",
    citation: nistIso(),
    playbooks: [PRV_PLAYBOOK_VSQ],
    missing_title: "Vulnerability management clause missing",
    missing_description:
      "No clause was found describing patch / vulnerability management or penetration testing.",
    explanation:
      "NIST CSF Detect / Respond + ISO 27001 A.12 require vulnerability management. Customers expect critical-severity SLAs and annual penetration tests.",
    recommendation:
      "Add 'Vulnerability Management' with patch SLAs by severity (critical 7d / high 30d / medium 90d) and annual third-party penetration testing.",
    present_patterns: [
      /(vulnerability\s+management|patch\s+management)/i,
      /(penetration\s+test|pen.?test)/i,
      /(critical|high|severity)/i,
    ],
  }),
  presence({
    id: "PRV-032",
    name: "Incident response + breach notification SLA",
    description:
      "VSQ must describe the incident-response process and breach-notification SLA to customers.",
    citation: nistIso(),
    playbooks: [PRV_PLAYBOOK_VSQ],
    missing_title: "Incident response / notification clause missing",
    missing_description: "No incident-response / breach-notification clause was found.",
    explanation:
      "ISO 27001 A.16 / NIST CSF Respond. Customers expect a defined IR plan and a contractual breach-notification SLA (commonly 24–72 hours).",
    recommendation:
      "Add 'Incident Response' with documented IR plan, tabletop cadence, and breach-notification SLA to customer (e.g., without undue delay, within 72 hours).",
    present_patterns: [
      /(incident\s+response|ir\s+plan)/i,
      /(breach\s+notification|notify)/i,
      /(without\s+undue\s+delay|24|48|72)\s+hours?/i,
    ],
  }),
  presence({
    id: "PRV-033",
    name: "Subprocessor / fourth-party disclosure",
    description:
      "VSQ must list material subprocessors / fourth parties and their function.",
    citation: gdprArt("28", "Subprocessor disclosure"),
    playbooks: [PRV_PLAYBOOK_VSQ],
    missing_title: "Subprocessor / fourth-party disclosure missing",
    missing_description: "No subprocessor / fourth-party list was found.",
    explanation:
      "GDPR Art. 28(2)–(4) require controller authorization of subprocessors and contractual flow-down. Customers expect a current list with function and location.",
    recommendation:
      "Add 'Subprocessors' listing each material subprocessor, function, and location, with a process for change notification.",
    present_patterns: [
      /(subprocessors?|sub.processors?|fourth.?part(y|ies))/i,
      /(list|register)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// I.12 — Data-incident notification. 7 rules: PRV-034..PRV-040.
// ────────────────────────────────────────────────────────────────────

const INCIDENT_NOTIFICATION_RULES: Rule[] = [
  presence({
    id: "PRV-034",
    name: "Nature of the incident",
    description:
      "Incident notification must describe the nature of the personal-data breach.",
    citation: gdprArt("33", "Breach notification"),
    playbooks: [PRV_PLAYBOOK_INCIDENT],
    missing_title: "Nature-of-incident clause missing",
    missing_description: "No clause describing the nature of the incident was found.",
    explanation:
      "GDPR Art. 33(3)(a) (and many state breach laws) require description of the nature of the breach — what happened, when, and how.",
    recommendation:
      "Add 'Nature of Incident' describing what happened, when discovered, root cause (preliminary), and discovery method.",
    present_patterns: [
      /(nature\s+of\s+the\s+(incident|breach)|what\s+happened)/i,
      /(date|when|discovered)/i,
    ],
  }),
  presence({
    id: "PRV-035",
    name: "Categories and approximate number of data subjects / records affected",
    description:
      "Notification must identify categories and approximate numbers of data subjects and personal-data records affected.",
    citation: gdprArt("33", "Breach contents"),
    playbooks: [PRV_PLAYBOOK_INCIDENT],
    missing_title: "Categories / number of affected subjects missing",
    missing_description:
      "No clause was found identifying categories / approximate number of data subjects / records.",
    explanation:
      "GDPR Art. 33(3)(a) and US state breach laws require disclosure of categories of records / number of affected individuals (often a state-specific threshold for AG notification).",
    recommendation:
      "Add 'Affected Individuals' with categories of data subjects, types of personal data, and approximate numbers (including state-AG thresholds for US notice).",
    present_patterns: [
      /(categor(y|ies)\s+of\s+data\s+subjects?|affected\s+(individuals?|records?))/i,
      /(approximately|approximate|number\s+of)/i,
    ],
  }),
  presence({
    id: "PRV-036",
    name: "DPO / privacy contact information",
    description: "Notification must identify the DPO / privacy contact.",
    citation: gdprArt("33", "Contact"),
    playbooks: [PRV_PLAYBOOK_INCIDENT],
    missing_title: "DPO / privacy contact clause missing",
    missing_description: "No DPO / privacy contact was identified.",
    explanation:
      "GDPR Art. 33(3)(b) requires DPO (or equivalent contact) identification. US state laws typically require a toll-free / privacy contact for affected individuals.",
    recommendation:
      "Add 'Contact' with DPO / privacy contact name, email, and phone.",
    present_patterns: [
      /(dpo|data\s+protection\s+officer|privacy\s+officer|privacy\s+contact)/i,
      /(@|phone|telephone)/i,
    ],
  }),
  presence({
    id: "PRV-037",
    name: "Likely consequences for individuals",
    description: "Notification must describe the likely consequences of the breach.",
    citation: gdprArt("33", "Consequences"),
    playbooks: [PRV_PLAYBOOK_INCIDENT],
    missing_title: "Likely-consequences clause missing",
    missing_description:
      "No clause describing likely consequences for individuals was found.",
    explanation:
      "GDPR Art. 33(3)(c) requires description of likely consequences (financial loss, identity theft, reputational damage, discrimination, etc.).",
    recommendation:
      "Add 'Likely Consequences' describing potential harms (identity theft, fraud, account compromise, reputational harm).",
    present_patterns: [
      /(likely\s+consequences|risk\s+to)/i,
      /(identity\s+theft|fraud|financial\s+loss|harm)/i,
    ],
  }),
  presence({
    id: "PRV-038",
    name: "Measures taken / proposed to address the breach",
    description:
      "Notification must describe the measures taken / proposed to address the breach and mitigate consequences.",
    citation: gdprArt("33", "Mitigations"),
    playbooks: [PRV_PLAYBOOK_INCIDENT],
    missing_title: "Measures-taken clause missing",
    missing_description:
      "No clause was found describing measures taken / proposed to address the breach.",
    explanation:
      "GDPR Art. 33(3)(d) and US state breach laws require disclosure of remediation steps (containment, password reset, credit monitoring offer, security improvements).",
    recommendation:
      "Add 'Measures Taken' describing containment, eradication, recovery, credit monitoring (where appropriate), and longer-term mitigations.",
    present_patterns: [
      /(measures\s+(taken|proposed)|remediation|mitigat)/i,
      /(contain|eradicat|recover|credit\s+monitoring)/i,
    ],
  }),
  presence({
    id: "PRV-039",
    name: "Timing — 72 hour notification (GDPR Art. 33) + state thresholds",
    description:
      "Notification template must address GDPR Art. 33 72-hour timing and applicable state-specific thresholds.",
    citation: stateBreach(),
    playbooks: [PRV_PLAYBOOK_INCIDENT],
    missing_title: "Timing / 72-hour clause missing",
    missing_description: "No timing or notification-deadline clause was found.",
    explanation:
      "GDPR Art. 33(1) requires notification within 72 hours of awareness; HIPAA Breach Rule § 164.408 requires individual notice without unreasonable delay and within 60 days; state laws vary (e.g., CA 'most expedient time', MA 'as soon as practicable').",
    recommendation:
      "Add 'Timing' addressing the GDPR 72-hour deadline, HIPAA 60-day timing, and applicable state-specific maxima.",
    present_patterns: [
      /(72\s+hours?|without\s+undue\s+delay)/i,
      /(art\.?\s*33|article\s+33)/i,
      /(60\s+days?|expedient|practicable)/i,
    ],
  }),
  presence({
    id: "PRV-040",
    name: "Regulatory / AG notification trigger threshold",
    description:
      "Template must address state-AG / supervisory-authority notification triggers (typically 500 / 1,000 affected residents).",
    citation: stateBreach(),
    playbooks: [PRV_PLAYBOOK_INCIDENT],
    missing_title: "Regulator / AG notification trigger missing",
    missing_description: "No clause was found addressing regulator / AG notification triggers.",
    explanation:
      "Many state laws set an AG-notification trigger at 500 or 1,000 affected residents (e.g., CA, NY, MA); HIPAA requires media notice at 500+ residents in a state.",
    recommendation:
      "Add 'Regulator Notification' covering state-AG triggers (typically 500 / 1,000+), HIPAA 500-resident media notice, and EU supervisory-authority notification under Art. 33.",
    present_patterns: [
      /(state\s+(ag|attorney\s+general)|supervisory\s+authority)/i,
      /(500|1,?000|threshold)/i,
      /(media|notice|notification)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate. 40 rules total.
// ────────────────────────────────────────────────────────────────────

export const PRIVACY_EXTENDED_RULES: Rule[] = [
  ...COOKIE_NOTICE_RULES,
  ...NPP_RULES,
  ...ROPA_RULES,
  ...DPIA_RULES,
  ...VENDOR_QUESTIONNAIRE_RULES,
  ...INCIDENT_NOTIFICATION_RULES,
];

export {
  COOKIE_NOTICE_RULES,
  NPP_RULES,
  ROPA_RULES,
  DPIA_RULES,
  VENDOR_QUESTIONNAIRE_RULES,
  INCIDENT_NOTIFICATION_RULES,
};
