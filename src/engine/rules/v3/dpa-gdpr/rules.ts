/**
 * DPA-GDPR ruleset — 55 rules (spec-v3.md §29 / Step 24).
 *
 * Article 28(3) enumerated clauses + Article 28(2)/(4)/(9) governance +
 * Articles 30, 32, 33, 35, 27, 37 + Chapter V international transfer
 * rules + quality-of-text rules.
 *
 * Each rule is scoped to `["dpa-controller-processor",
 * "dpa-processor-subprocessor", "scc-module-2", "scc-module-3"]` so
 * the v2 launch suite is untouched when no DPA playbook is active.
 */

import type { Rule } from "../../../finding.js";
import {
  buildLanguageRule,
  buildPresenceRule,
  type LanguageSpec,
  type PresenceSpec,
  type RegulatedRuleConfig,
} from "../_regulated-rule.js";

const DPA_PLAYBOOKS = [
  "dpa-controller-processor",
  "dpa-processor-subprocessor",
  "scc-module-2",
  "scc-module-3",
];

const CONFIG: RegulatedRuleConfig = {
  category: "dpa-gdpr",
  applies_to_playbooks: DPA_PLAYBOOKS,
  cite_for(citation: string) {
    return {
      id: `gdpr-${citation.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
      source_url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
    };
  },
};

const presence = (s: PresenceSpec): Rule => buildPresenceRule(s, CONFIG);
const language = (s: LanguageSpec): Rule => buildLanguageRule(s, CONFIG);

export const DPA_GDPR_RULES: Rule[] = [
  // ────────────────────────────────────────────────────────────────
  // Article 28(3) introductory paragraph — subject-matter, duration,
  // nature, purpose, type of personal data, categories of data
  // subjects, controller obligations
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-001",
    name: "Subject-matter of processing identified",
    description: "DPA must identify the subject-matter of the processing.",
    citation: "GDPR Art. 28(3) introductory",
    missing_title: "Subject-matter of processing not identified",
    missing_description: "No clause was found identifying the subject-matter of the processing.",
    explanation:
      "Article 28(3) requires the controller-processor contract to set out the subject-matter and duration of the processing, the nature and purpose, the type of personal data, the categories of data subjects, and the obligations and rights of the controller.",
    recommendation:
      "Add a 'Subject-matter of Processing' clause or an Annex describing the services giving rise to processing.",
    present_patterns: [/subject[- ]matter\s+of\s+(the\s+)?processing/i, /scope\s+of\s+processing/i],
  }),
  presence({
    id: "DPA-002",
    name: "Duration of processing specified",
    description: "DPA must specify the duration of the processing.",
    citation: "GDPR Art. 28(3) introductory",
    missing_title: "Duration of processing not specified",
    missing_description: "No clause was found specifying how long the processing will continue.",
    explanation: "Article 28(3) requires the duration of the processing to be set out.",
    recommendation:
      "State that processing continues for the term of the agreement plus a defined wind-down period.",
    present_patterns: [
      /duration\s+of\s+(the\s+)?processing|processing\s+(shall|will)\s+continue\s+for/i,
    ],
  }),
  presence({
    id: "DPA-003",
    name: "Nature and purpose of processing",
    description: "DPA must describe the nature and purpose of the processing.",
    citation: "GDPR Art. 28(3) introductory",
    missing_title: "Nature and purpose of processing not described",
    missing_description: "No clause was found describing the nature and purpose of the processing.",
    explanation: "Art. 28(3) requires the nature and purpose of the processing to be stated.",
    recommendation:
      "Add a 'Nature and Purpose of Processing' clause naming the services and processing operations.",
    present_patterns: [/nature\s+and\s+purpose\s+of\s+(the\s+)?processing/i],
  }),
  presence({
    id: "DPA-004",
    name: "Type of personal data identified",
    description: "DPA must identify the type of personal data processed.",
    citation: "GDPR Art. 28(3) introductory",
    missing_title: "Type of personal data not identified",
    missing_description:
      "No clause was found identifying the categories of personal data processed.",
    explanation:
      "Article 28(3) requires the type of personal data to be specified — typically in an Annex.",
    recommendation:
      "Add an Annex listing the categories of personal data (e.g., name, email, IP, account identifiers).",
    present_patterns: [
      /(type|categories)\s+of\s+personal\s+data|personal\s+data\s+(processed|categories)/i,
    ],
  }),
  presence({
    id: "DPA-005",
    name: "Categories of data subjects identified",
    description: "DPA must identify the categories of data subjects.",
    citation: "GDPR Art. 28(3) introductory",
    missing_title: "Categories of data subjects not identified",
    missing_description: "No clause was found identifying the categories of data subjects.",
    explanation:
      "Art. 28(3) requires the categories of data subjects (e.g., customers, employees, end users) to be set out.",
    recommendation: "Add an Annex listing the categories of data subjects.",
    present_patterns: [/categor(?:y|ies)\s+of\s+data\s+subjects|data\s+subjects?\s+categor/i],
  }),
  presence({
    id: "DPA-006",
    name: "Obligations and rights of the controller stated",
    description: "DPA must state the obligations and rights of the controller.",
    citation: "GDPR Art. 28(3) introductory",
    missing_title: "Obligations and rights of the controller not stated",
    missing_description:
      "No clause was found stating the obligations and rights of the controller.",
    explanation: "Art. 28(3) requires the controller's obligations and rights to be set out.",
    recommendation:
      "Add a clause cross-referencing the controller's responsibilities under the agreement and GDPR.",
    present_patterns: [
      /(obligations\s+and\s+rights\s+of\s+the\s+controller|controller\s+(shall|will)\s+(comply|determine))/i,
    ],
  }),

  // ────────────────────────────────────────────────────────────────
  // Article 28(3)(a)–(h) — the eight required categories
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-007",
    name: "Processing only on documented instructions",
    description:
      "Processor must process personal data only on documented instructions from the controller.",
    citation: "GDPR Art. 28(3)(a)",
    missing_title: "Documented-instructions clause missing",
    missing_description:
      "No clause was found requiring processing only on documented instructions from the controller.",
    explanation:
      "Art. 28(3)(a) requires the processor to act only on documented instructions, including for international transfers (subject to law).",
    recommendation:
      "Add: 'Processor shall process Personal Data only on documented instructions from Controller.'",
    present_patterns: [
      /(only|exclusively)\s+on\s+(the\s+)?(documented\s+)?instructions\s+(from|of)\s+(the\s+)?controller/i,
    ],
  }),
  presence({
    id: "DPA-008",
    name: "Confidentiality of authorised persons",
    description:
      "Persons authorised to process personal data must commit themselves to confidentiality.",
    citation: "GDPR Art. 28(3)(b)",
    missing_title: "Confidentiality-commitment clause missing",
    missing_description:
      "No clause was found requiring authorised persons to be subject to confidentiality.",
    explanation:
      "Art. 28(3)(b) requires personnel processing personal data to be bound by confidentiality.",
    recommendation:
      "Add: 'Processor shall ensure that persons authorised to process Personal Data have committed themselves to confidentiality.'",
    present_patterns: [
      /(committed\s+(themselves\s+)?to\s+confidentiality|duty\s+of\s+confidentiality|bound\s+by\s+confidentiality)/i,
    ],
  }),
  presence({
    id: "DPA-009",
    name: "Article 32 security measures incorporated",
    description:
      "DPA must require the processor to take all measures required pursuant to Article 32.",
    citation: "GDPR Art. 28(3)(c)",
    missing_title: "Art. 32 security measures clause missing",
    missing_description: "No clause was found incorporating Article 32 security obligations.",
    explanation:
      "Art. 28(3)(c) requires the processor to take all measures required pursuant to Article 32 (security of processing).",
    recommendation:
      "Add a security clause cross-referencing Article 32 and an Annex of technical and organisational measures.",
    present_patterns: [/article\s*32|technical\s+and\s+organisational\s+measures/i],
  }),
  presence({
    id: "DPA-010",
    name: "Subprocessor terms (Art. 28(2) and (4))",
    description: "DPA must respect the conditions for engaging another processor.",
    citation: "GDPR Art. 28(3)(d)",
    missing_title: "Subprocessor terms missing",
    missing_description: "No clause was found governing engagement of subprocessors.",
    explanation:
      "Art. 28(3)(d) requires the processor to respect the conditions in paragraphs 2 and 4 for engaging another processor (prior authorisation + flow-down of the same obligations).",
    recommendation:
      "Add a 'Sub-processors' clause specifying prior written authorisation (general or specific) and flow-down of GDPR-equivalent obligations.",
    present_patterns: [/(sub[- ]?processor|another\s+processor)/i],
  }),
  presence({
    id: "DPA-011",
    name: "Assist controller in responding to data-subject rights",
    description:
      "Processor must assist the controller in responding to data-subject rights requests.",
    citation: "GDPR Art. 28(3)(e)",
    missing_title: "Data-subject-rights assistance clause missing",
    missing_description:
      "No clause was found requiring processor assistance with Chapter III data-subject rights.",
    explanation:
      "Art. 28(3)(e) requires the processor to assist the controller, taking into account the nature of processing, by appropriate technical and organisational measures to fulfil the controller's obligation to respond to data subjects' rights.",
    recommendation:
      "Add: 'Processor shall assist Controller, taking into account the nature of processing, in fulfilling its obligation to respond to requests for exercising data subject rights.'",
    present_patterns: [/(assist\s+(the\s+)?controller|data\s+subject\s+rights|chapter\s+III)/i],
  }),
  presence({
    id: "DPA-012",
    name: "Assist controller with Articles 32–36 obligations",
    description:
      "Processor must assist the controller with Articles 32–36 obligations (security, breach, DPIA, prior consultation).",
    citation: "GDPR Art. 28(3)(f)",
    missing_title: "Articles 32–36 assistance clause missing",
    missing_description: "No clause was found requiring processor assistance with Arts. 32–36.",
    explanation:
      "Art. 28(3)(f) requires the processor to assist the controller in ensuring compliance with security (Art. 32), breach (Arts. 33–34), DPIA (Art. 35), and prior consultation (Art. 36) obligations.",
    recommendation:
      "Add a clause obligating the processor to assist with Articles 32–36 obligations, taking into account the nature of processing and information available.",
    present_patterns: [
      /(articles?\s*32.{0,8}(to|–|-)\s*36|articles?\s*33.{0,8}(to|–|-)\s*36|assist.*?(breach|security|DPIA))/i,
    ],
  }),
  presence({
    id: "DPA-013",
    name: "Deletion or return at end of services",
    description:
      "Processor must, at the choice of the controller, delete or return all personal data after the end of the provision of services.",
    citation: "GDPR Art. 28(3)(g)",
    missing_title: "Deletion-or-return clause missing",
    missing_description:
      "No clause was found requiring deletion or return of personal data at end of services.",
    explanation:
      "Art. 28(3)(g) requires the processor, at the choice of the controller, to delete or return all the personal data to the controller after the end of the provision of services.",
    recommendation:
      "Add a clause: 'At the choice of the Controller, Processor shall delete or return all Personal Data after the end of the provision of services relating to processing.'",
    present_patterns: [
      /(delete\s+or\s+return|return\s+or\s+delete).*?(personal\s+data|end\s+of\s+(?:the\s+)?(?:provision\s+of\s+)?services)/is,
    ],
  }),
  presence({
    id: "DPA-014",
    name: "Information available for compliance demonstration",
    description:
      "Processor must make available all information necessary to demonstrate compliance with Article 28.",
    citation: "GDPR Art. 28(3)(h)",
    missing_title: "Compliance-demonstration clause missing",
    missing_description:
      "No clause was found requiring the processor to make information available demonstrating Art. 28 compliance.",
    explanation:
      "Art. 28(3)(h) requires the processor to make available to the controller all information necessary to demonstrate compliance with Article 28 and to allow for and contribute to audits, including inspections.",
    recommendation:
      "Add: 'Processor shall make available to Controller all information necessary to demonstrate compliance with Article 28 and shall allow for and contribute to audits, including inspections, conducted by Controller or its mandated auditor.'",
    present_patterns: [
      /(demonstrate\s+compliance|information\s+necessary\s+to\s+demonstrate|allow\s+for\s+and\s+contribute\s+to\s+audits)/i,
    ],
  }),

  // ────────────────────────────────────────────────────────────────
  // Article 28(2), (4), (9) — subprocessor & form
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-015",
    name: "Subprocessor prior written authorisation (Art. 28(2))",
    description:
      "Processor must obtain prior specific or general written authorisation before engaging a subprocessor.",
    citation: "GDPR Art. 28(2)",
    missing_title: "Subprocessor authorisation clause missing",
    missing_description:
      "No clause was found requiring prior written authorisation for subprocessors.",
    explanation:
      "Art. 28(2) requires the processor not to engage another processor without prior specific or general written authorisation. With general authorisation, the processor must inform the controller of intended changes and give the controller the opportunity to object.",
    recommendation:
      "Add: 'Processor shall not engage another processor without prior specific or general written authorisation of Controller.'",
    present_patterns: [
      /(prior\s+(specific\s+or\s+general\s+)?written\s+authori[sz]ation|authori[sz]ation\s+of\s+(the\s+)?controller).*?(processor|subprocessor)/is,
    ],
  }),
  presence({
    id: "DPA-016",
    name: "Subprocessor change notification + objection right",
    description:
      "Where general authorisation is used, controller must be informed of intended changes and have the opportunity to object.",
    citation: "GDPR Art. 28(2)",
    missing_title: "Subprocessor change notification / objection missing",
    missing_description:
      "No clause was found giving Controller notification of subprocessor changes and a right to object.",
    explanation:
      "Art. 28(2) requires informing the controller of intended subprocessor changes and giving an opportunity to object.",
    recommendation:
      "Add: 'Processor shall inform Controller of any intended changes concerning the addition or replacement of Sub-processors with reasonable notice, giving Controller the opportunity to object.'",
    present_patterns: [
      /(opportunity\s+to\s+object|right\s+to\s+object).*?(sub[- ]?processor|processor)/is,
    ],
  }),
  presence({
    id: "DPA-017",
    name: "Subprocessor flow-down of same obligations (Art. 28(4))",
    description:
      "Where the processor engages a subprocessor, the same data-protection obligations must be imposed on the subprocessor by contract.",
    citation: "GDPR Art. 28(4)",
    missing_title: "Subprocessor flow-down clause missing",
    missing_description:
      "No clause was found imposing the same data-protection obligations on subprocessors.",
    explanation:
      "Art. 28(4) requires the processor to impose, by contract or other legal act, the same data-protection obligations on the subprocessor as set out in the contract between the controller and processor.",
    recommendation:
      "Add: 'Where Processor engages a Sub-processor, the same data protection obligations shall be imposed on the Sub-processor by contract.'",
    present_patterns: [
      /(sub[- ]?processor|another\s+processor).*?(same\s+(data[- ]protection\s+)?obligations|same\s+obligations|same\s+terms|equivalent\s+obligations)/is,
    ],
  }),
  presence({
    id: "DPA-018",
    name: "DPA in writing including electronic form",
    description: "DPA must be in writing, including in electronic form.",
    citation: "GDPR Art. 28(9)",
    missing_title: "Form-of-agreement clause missing",
    missing_description: "No reference to written / electronic form was found.",
    explanation: "Art. 28(9) requires the contract to be in writing, including in electronic form.",
    recommendation:
      "State: 'This Agreement is in writing, including electronic form, in accordance with Article 28(9) GDPR.'",
    present_patterns: [/(in\s+writing|electronic\s+form|written\s+(contract|agreement))/i],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Article 32 — security
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-019",
    name: "Pseudonymisation / encryption referenced",
    description:
      "Art. 32(1)(a) lists pseudonymisation and encryption as appropriate measures where relevant.",
    citation: "GDPR Art. 32(1)(a)",
    missing_title: "Pseudonymisation / encryption not referenced",
    missing_description: "No reference to pseudonymisation or encryption was found.",
    explanation:
      "Art. 32(1)(a) lists pseudonymisation and encryption among the technical and organisational measures appropriate to the risk.",
    recommendation: "Reference pseudonymisation or encryption in the security clause / Annex II.",
    present_patterns: [/(pseudonymi[sz]ation|encrypt(?:ion|ed))/i],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-020",
    name: "Confidentiality / integrity / availability / resilience",
    description:
      "Art. 32(1)(b) — ability to ensure ongoing confidentiality, integrity, availability and resilience of processing systems.",
    citation: "GDPR Art. 32(1)(b)",
    missing_title: "Confidentiality / integrity / availability / resilience clause missing",
    missing_description:
      "No reference to ongoing confidentiality, integrity, availability, and resilience was found.",
    explanation:
      "Art. 32(1)(b) requires measures to ensure ongoing confidentiality, integrity, availability and resilience of processing systems and services.",
    recommendation:
      "Add a clause referencing CIA-R (confidentiality, integrity, availability, resilience) of processing systems.",
    present_patterns: [
      /(confidentiality.{0,30}integrity.{0,30}availability|availability.{0,30}resilience|integrity.{0,30}availability)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-021",
    name: "Restore availability after incident",
    description:
      "Art. 32(1)(c) — ability to restore availability and access to personal data in a timely manner.",
    citation: "GDPR Art. 32(1)(c)",
    missing_title: "Restore-availability clause missing",
    missing_description: "No reference to restoring availability after an incident was found.",
    explanation:
      "Art. 32(1)(c) requires the ability to restore the availability and access to personal data in a timely manner in the event of an incident.",
    recommendation: "Add a backup / disaster-recovery clause aligned with Art. 32(1)(c).",
    present_patterns: [
      /(restore\s+availability|disaster\s+recovery|business\s+continuity|backup\s+and\s+recovery)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-022",
    name: "Regular testing of measures",
    description:
      "Art. 32(1)(d) — process for regularly testing, assessing and evaluating effectiveness.",
    citation: "GDPR Art. 32(1)(d)",
    missing_title: "Testing-of-measures clause missing",
    missing_description:
      "No reference to regular testing / assessing of security measures was found.",
    explanation:
      "Art. 32(1)(d) requires a process for regularly testing, assessing and evaluating the effectiveness of measures.",
    recommendation:
      "Reference periodic penetration testing, vulnerability scanning, or independent assessments.",
    present_patterns: [
      /(testing.*(measures|controls)|penetration\s+test|vulnerability\s+(scan|assessment)|periodic\s+assess)/i,
    ],
    default_severity: "warning",
  }),
  language({
    id: "DPA-023",
    name: "'Appropriate measures' undefined hand-waving",
    description:
      "Flags DPAs that reference 'appropriate measures' without an Annex of technical and organisational measures.",
    citation: "GDPR Art. 32",
    bad_title: "'Appropriate measures' is undefined hand-waving",
    bad_description: "Detected 'appropriate measures' language without any specific measures.",
    explanation:
      "Art. 32 requires measures appropriate to the risk; 'appropriate' alone, without an Annex or specifics, is hand-waving the regulator has criticised.",
    recommendation:
      "Replace with a specific Annex of technical and organisational measures (TOMs).",
    bad_patterns: [
      /commercially\s+reasonable\s+(security|measures)/i,
      /industry[- ]standard\s+security\b(?!.*?(?:annex|appendix|exhibit))/is,
    ],
  }),

  // ────────────────────────────────────────────────────────────────
  // Article 33 — controller / processor breach notification
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-024",
    name: "Processor breach notice to controller (Art. 33(2))",
    description:
      "Processor must notify the controller without undue delay after becoming aware of a personal data breach.",
    citation: "GDPR Art. 33(2)",
    missing_title: "Processor breach-notification clause missing",
    missing_description:
      "No clause was found requiring the processor to notify the controller of a personal data breach.",
    explanation:
      "Art. 33(2) requires the processor to notify the controller without undue delay after becoming aware of a personal data breach.",
    recommendation:
      "Add: 'Processor shall notify Controller without undue delay after becoming aware of a Personal Data Breach.'",
    present_patterns: [
      /(personal\s+data\s+breach|breach\s+of\s+personal\s+data|data\s+breach).{0,160}(notify|notification)/is,
      /(notify|notification).{0,80}(controller).{0,80}(breach|incident)/is,
    ],
  }),
  presence({
    id: "DPA-025",
    name: "'Without undue delay' present",
    description: "Breach-notification clause should include 'without undue delay'.",
    citation: "GDPR Art. 33(2)",
    missing_title: "'Without undue delay' language missing",
    missing_description: "Breach-notice clause does not include 'without undue delay'.",
    explanation:
      "Art. 33(2) uses the 'without undue delay' standard; drafters should preserve this exact phrasing.",
    recommendation: "Add 'without undue delay' to the breach-notification clause.",
    present_patterns: [/without\s+undue\s+delay/i],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-026",
    name: "Breach-notice content elements (Art. 33(3))",
    description:
      "Breach notification should include the Article 33(3) content elements (nature, categories, contact, consequences, measures).",
    citation: "GDPR Art. 33(3)",
    missing_title: "Breach-notice content elements not specified",
    missing_description:
      "No clause was found requiring the Art. 33(3) breach-notification content elements.",
    explanation:
      "Art. 33(3) requires the breach notification to describe the nature, categories and approximate numbers, name and contact of the DPO, likely consequences, and measures taken to address.",
    recommendation:
      "Add a clause requiring the processor's breach notice to include the Article 33(3) content elements.",
    present_patterns: [
      /(nature\s+of\s+the\s+(personal\s+data\s+)?breach|categor(?:y|ies)\s+of\s+data\s+subjects|likely\s+consequences|measures\s+taken)/i,
    ],
    default_severity: "warning",
  }),
  language({
    id: "DPA-027",
    name: "Breach notice timing stricter than 'undue delay'",
    description:
      "Flags fixed breach-notice deadlines that exceed regulator expectations (e.g., > 72 hours from controller awareness, > 5 days from processor awareness).",
    citation: "GDPR Art. 33(2)",
    bad_title: "Breach-notification timing too loose",
    bad_description:
      "Detected a breach-notice window longer than is consistent with 'without undue delay.'",
    explanation:
      "Although Art. 33(2) does not set a strict outer bound for the processor, supervisory guidance treats anything beyond ~24–72 hours as suspect.",
    recommendation:
      "Tighten the processor's notification window to no more than 48–72 hours after becoming aware.",
    bad_patterns: [
      /\b(within|no\s+later\s+than)\s+(?:1[0-9]|2[0-9]|3[0-9]|[4-9][0-9]|[1-9][0-9]{2,})\s+days?\b.{0,80}(breach|notif)/is,
      /(breach|notif).{0,80}\b(within|no\s+later\s+than)\s+(?:1[0-9]|2[0-9]|3[0-9]|[4-9][0-9]|[1-9][0-9]{2,})\s+days?\b/is,
    ],
  }),

  // ────────────────────────────────────────────────────────────────
  // Article 30 — records of processing assistance
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-028",
    name: "Article 30 records of processing assistance",
    description:
      "Processor should assist controller with Art. 30 records of processing activities (RoPA).",
    citation: "GDPR Art. 30",
    missing_title: "RoPA assistance clause missing",
    missing_description:
      "No clause was found regarding records of processing activities assistance.",
    explanation:
      "Art. 30 requires records of processing activities; processors typically assist controllers by providing relevant information.",
    recommendation:
      "Add a clause obligating the processor to provide information needed for the controller's Art. 30 RoPA.",
    present_patterns: [/(records\s+of\s+processing|article\s*30|RoPA)/i],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Article 35 — DPIA assistance
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-029",
    name: "DPIA assistance (Art. 35)",
    description:
      "Processor should assist controller with Data Protection Impact Assessments under Art. 35.",
    citation: "GDPR Art. 35",
    missing_title: "DPIA assistance clause missing",
    missing_description: "No clause was found requiring DPIA assistance.",
    explanation:
      "Art. 35 requires a DPIA for high-risk processing; the processor is required by Art. 28(3)(f) to assist.",
    recommendation: "Add a DPIA assistance clause referencing Article 35 and the processor's role.",
    present_patterns: [/(data\s+protection\s+impact\s+assessment|DPIA|article\s*35)/i],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Article 27 — EU representative
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-030",
    name: "Article 27 EU representative referenced (where applicable)",
    description: "Non-EU processors should reference their EU representative under Art. 27.",
    citation: "GDPR Art. 27",
    missing_title: "Article 27 EU representative not referenced",
    missing_description: "No reference to an Art. 27 EU representative was found.",
    explanation:
      "Art. 27 requires non-EU controllers and processors to designate an EU representative (with exceptions).",
    recommendation:
      "If processor is non-EU, designate and name an Art. 27 EU representative in the DPA.",
    present_patterns: [
      /(article\s*27|EU\s+representative|representative\s+in\s+the\s+Union|representative\s+under\s+Article\s*27)/i,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Article 37 — DPO reference
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-031",
    name: "Article 37 DPO referenced (where applicable)",
    description:
      "Where required, the DPA should reference the Data Protection Officer under Art. 37.",
    citation: "GDPR Art. 37",
    missing_title: "Data Protection Officer not referenced",
    missing_description: "No reference to a Data Protection Officer was found.",
    explanation:
      "Art. 37 requires a DPO in certain cases; modern DPAs reference contact details for the DPO.",
    recommendation: "Reference the DPO's contact information and Article 37 designation.",
    present_patterns: [/(data\s+protection\s+officer|\bDPO\b|article\s*37)/i],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // International transfers — Chapter V (Arts. 44–49)
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-032",
    name: "International transfer mechanism named",
    description: "Where international transfers occur, the DPA must name a Chapter V mechanism.",
    citation: "GDPR Arts. 44–49",
    missing_title: "International transfer mechanism not named",
    missing_description: "No reference to an international transfer mechanism was found.",
    explanation:
      "Articles 44–49 require an adequacy decision, SCCs, BCRs, or a derogation for transfers to third countries.",
    recommendation:
      "Name the relevant mechanism (adequacy decision, EU SCCs Module 2/3, BCRs, or a Chapter V derogation).",
    present_patterns: [
      /(international\s+transfer|chapter\s+V|standard\s+contractual\s+clauses|\bSCCs?\b|adequacy\s+decision|binding\s+corporate\s+rules|\bBCRs?\b)/i,
    ],
  }),
  presence({
    id: "DPA-033",
    name: "EU SCCs incorporated by reference",
    description: "DPA should incorporate EU SCCs by reference where transfers require them.",
    citation: "Commission Implementing Decision (EU) 2021/914",
    missing_title: "EU SCCs not incorporated",
    missing_description: "No clause was found incorporating the EU Standard Contractual Clauses.",
    explanation:
      "Decision 2021/914 requires the parties to use the SCC template for in-scope transfers.",
    recommendation: "Incorporate the EU SCCs by reference and complete Annexes I, II, III.",
    present_patterns: [/(2021\/914|standard\s+contractual\s+clauses|EU\s+SCCs?)/i],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-034",
    name: "Transfer Impact Assessment (TIA) referenced",
    description:
      "Following Schrems II, parties should reference a TIA where Chapter V transfers occur.",
    citation: "Commission Implementing Decision (EU) 2021/914, Clause 14",
    missing_title: "Transfer Impact Assessment not referenced",
    missing_description: "No reference to a TIA was found.",
    explanation:
      "Schrems II / SCC Clause 14 requires parties to assess local laws and practices of the recipient country.",
    recommendation:
      "Reference a TIA / Transfer Risk Assessment and the parties' obligations under Clause 14 SCCs.",
    present_patterns: [
      /(transfer\s+impact\s+assessment|TIA\b|transfer\s+risk\s+assessment|TRA\b|local\s+laws\s+and\s+practices)/i,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Quality-of-text rules
  // ────────────────────────────────────────────────────────────────
  language({
    id: "DPA-035",
    name: "Deletion-or-return choice belongs to processor",
    description:
      "Flags clauses where the processor (not the controller) chooses between deletion and return.",
    citation: "GDPR Art. 28(3)(g)",
    bad_title: "Deletion-or-return choice misallocated to processor",
    bad_description:
      "Detected language giving the processor (not the controller) the choice between deletion and return.",
    explanation:
      "Art. 28(3)(g) says deletion or return is 'at the choice of the controller.' Vendor overreach commonly inverts this.",
    recommendation:
      "Reassign the choice to the controller: 'At the Controller's choice, Processor shall delete or return Personal Data.'",
    bad_patterns: [
      /processor\s+(shall|may)\s+(choose|elect)\s+to\s+(delete|return)/i,
      /at\s+the\s+(option|choice)\s+of\s+(the\s+)?processor.*?(delete|return)/is,
    ],
  }),
  language({
    id: "DPA-036",
    name: "Audit-substitution eliminates audit entirely",
    description:
      "Flags SOC 2 / ISO substitution that eliminates the controller's audit right rather than substituting it.",
    citation: "GDPR Art. 28(3)(h)",
    bad_title: "Audit right eliminated by certification substitution",
    bad_description:
      "Detected language that uses SOC 2 / ISO 27001 to eliminate (not substitute) the controller's audit right.",
    explanation:
      "Art. 28(3)(h) requires the processor to allow for and contribute to audits. SOC 2 / ISO substitution is permitted, but it must not eliminate the right entirely.",
    recommendation:
      "Permit SOC 2 / ISO substitution as a default, but preserve the controller's right to an on-site audit on reasonable cause.",
    bad_patterns: [
      /(SOC\s*2|ISO\s*27001).{0,160}(in\s+lieu\s+of|shall\s+(satisfy|fulfill|fulfil)|the\s+sole\s+means)/is,
      /(no\s+(other|additional)\s+audit\s+rights|audit\s+rights?\s+are\s+limited\s+to)/i,
    ],
  }),
  language({
    id: "DPA-037",
    name: "Processor unilaterally amends instructions",
    description:
      "Flags clauses where the processor may deviate from controller instructions unilaterally.",
    citation: "GDPR Art. 28(3)(a)",
    bad_title: "Processor permitted to deviate from instructions unilaterally",
    bad_description:
      "Detected language allowing the processor to act outside controller instructions.",
    explanation:
      "Art. 28(3)(a) requires processing only on documented instructions; any deviation must be required by law and the processor must inform the controller.",
    recommendation:
      "Limit deviation to mandatory legal requirements and require advance notice to the controller (unless prohibited by law).",
    bad_patterns: [
      /processor\s+may\s+(deviate|depart)\s+from/i,
      /processor.{0,80}(at\s+its\s+(sole\s+)?discretion).{0,80}(instructions|processing)/is,
    ],
  }),
  presence({
    id: "DPA-038",
    name: "Personal data scope defined or annexed",
    description: "DPA should define personal data scope in an Annex (Annex I for SCCs).",
    citation: "GDPR Art. 28(3) intro / SCC Annex I",
    missing_title: "Personal-data scope annex missing",
    missing_description: "No Annex / appendix was found describing the processing scope.",
    explanation:
      "Modern DPAs and SCCs require an Annex describing the parties, transfer scope, and processing operations.",
    recommendation: "Add an 'Annex I — Description of Transfer' or equivalent appendix.",
    present_patterns: [/(annex|appendix|exhibit|schedule)\s+(I|1|A)/i],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-039",
    name: "Technical and organisational measures annex",
    description:
      "DPA should include an Annex describing technical and organisational measures (Annex II for SCCs).",
    citation: "GDPR Art. 32 / SCC Annex II",
    missing_title: "Technical-and-organisational-measures annex missing",
    missing_description: "No Annex of technical and organisational measures was found.",
    explanation: "Annex II of the SCCs (and the equivalent in DPAs) lists the TOMs.",
    recommendation: "Add an Annex II describing the technical and organisational measures.",
    present_patterns: [
      /(annex|appendix|exhibit|schedule)\s+(II|2|B).{0,40}(technical|organisational|TOM)/i,
      /annex\s+of\s+technical\s+and\s+organisational/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-040",
    name: "Subprocessor list annex",
    description:
      "DPA should include a list of approved subprocessors (Annex III for SCCs Modules 2 & 3).",
    citation: "Commission Implementing Decision (EU) 2021/914, Annex III",
    missing_title: "Subprocessor list annex missing",
    missing_description: "No Annex listing subprocessors was found.",
    explanation:
      "SCC Modules 2 and 3 require Annex III listing sub-processors at the time of signature.",
    recommendation:
      "Add an Annex III listing approved sub-processors with the categories of data they process.",
    present_patterns: [
      /(annex|appendix|exhibit|schedule)\s+(III|3|C).{0,40}(sub[- ]?processor|sub-processor\s+list)/i,
      /list\s+of\s+sub[- ]?processors/i,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Definitions / role identification
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-041",
    name: "GDPR-current terminology (Personal Data Breach defined)",
    description:
      "DPA should track GDPR terminology (Personal Data Breach, Data Subject, Processor, Controller).",
    citation: "GDPR Art. 4",
    missing_title: "GDPR-current terminology not present",
    missing_description:
      "Could not detect the GDPR-style terms 'Personal Data Breach' or 'Data Subject.'",
    explanation:
      "Art. 4 defines the operative terms; modern DPAs use these capitalised defined terms throughout.",
    recommendation:
      "Define 'Personal Data Breach,' 'Data Subject,' 'Controller,' and 'Processor' cross-referencing Article 4 GDPR.",
    present_patterns: [
      /(personal\s+data\s+breach|data\s+subject\s+shall\s+have|controller.{0,40}(shall\s+have\s+the\s+meaning|means)|processor.{0,40}(shall\s+have\s+the\s+meaning|means))/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-042",
    name: "Controller / Processor roles named",
    description:
      "DPA should clearly identify which party is the Controller and which is the Processor.",
    citation: "GDPR Art. 4(7) and (8)",
    missing_title: "Controller / Processor roles unclear",
    missing_description: "Could not detect both 'Controller' and 'Processor' role labels.",
    explanation: "Both party roles must be named so the regulatory framework attaches correctly.",
    recommendation:
      "Use 'Controller' and 'Processor' (capitalised defined terms) consistently in the preamble and throughout.",
    present_patterns: [/controller.*?processor|processor.*?controller/is],
  }),

  // ────────────────────────────────────────────────────────────────
  // Posture / execution
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-043",
    name: "Signature block present",
    description: "DPA should be signed by an authorised representative of each party.",
    citation: "GDPR Art. 28(9)",
    missing_title: "Signature block missing",
    missing_description: "No signature block was detected.",
    explanation: "DPAs must be in writing (Art. 28(9)); a signature block evidences execution.",
    recommendation: "Add signature blocks for both parties with name, title, and date.",
    present_patterns: [
      /By:\s*[_\-\s]+|signature\s+block|authori[sz]ed\s+(signatory|representative)|sign(ed)?\s+by/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-044",
    name: "Effective date present",
    description: "DPA should state an effective date.",
    citation: "GDPR Art. 28(3) intro",
    missing_title: "Effective date missing",
    missing_description: "No effective date was detected.",
    explanation: "An effective date anchors the timing rules in the DPA.",
    recommendation: "Add an 'Effective Date' clause near the preamble.",
    present_patterns: [/effective\s+date/i],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-045",
    name: "Term and termination clauses",
    description: "DPA should state its term and termination conditions.",
    citation: "GDPR Art. 28(3)(g)",
    missing_title: "Term / termination clauses missing",
    missing_description: "No term or termination clause was detected.",
    explanation:
      "DPAs should state how long the agreement is in effect and the conditions for termination.",
    recommendation: "Add 'Term' and 'Termination' clauses.",
    present_patterns: [/(term\s+of\s+(this\s+)?agreement|initial\s+term|termination|terminate)/i],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-046",
    name: "Governing-law clause present",
    description: "DPA should specify governing law (typically EU Member State or UK).",
    citation: "GDPR Art. 28(3)",
    missing_title: "Governing-law clause missing",
    missing_description: "No governing-law clause was detected.",
    explanation:
      "GDPR does not specify governing law, but SCC clauses require a Member State choice; DPAs commonly mirror this.",
    recommendation: "Add a governing-law clause naming the applicable Member State (or UK) law.",
    present_patterns: [
      /(governing\s+law|governed\s+by\s+the\s+laws|laws\s+of\s+(?:the\s+)?(?:republic\s+of\s+)?[A-Z])/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-047",
    name: "Liability allocation",
    description: "DPA should allocate liability between Controller and Processor.",
    citation: "GDPR Art. 82",
    missing_title: "Liability allocation clause missing",
    missing_description: "No clause was found allocating liability between the parties.",
    explanation:
      "Art. 82 makes both Controller and Processor potentially liable; DPAs should allocate as between the parties.",
    recommendation: "Add a liability-allocation clause aligned with Article 82 GDPR.",
    present_patterns: [/(liability|indemnif|article\s*82)/i],
    default_severity: "warning",
  }),
  language({
    id: "DPA-048",
    name: "Controller indemnifies Processor for GDPR fines",
    description:
      "Flags clauses where the controller indemnifies the processor for the processor's own GDPR liability.",
    citation: "GDPR Art. 82",
    bad_title: "Controller indemnifies Processor for GDPR liability",
    bad_description:
      "Detected language requiring the Controller to indemnify the Processor for GDPR-related fines or claims.",
    explanation:
      "Under Art. 82, a processor remains liable for its own infringements. Shifting that liability to the controller is vendor overreach and may be invalid.",
    recommendation:
      "Limit indemnification to non-GDPR contract claims, or align with the parties' actual fault.",
    bad_patterns: [
      /controller\s+(shall|will)\s+indemnif.*?(processor|GDPR|fine)/is,
      /customer\s+(shall|will)\s+indemnif.*?(processor|GDPR|fine)/is,
    ],
  }),
  language({
    id: "DPA-049",
    name: "Processor caps audit cost on controller exclusively",
    description:
      "Flags clauses where the controller must bear the entire cost of any audit, including audits triggered by processor breach.",
    citation: "GDPR Art. 28(3)(h)",
    bad_title: "Audit cost allocated exclusively to controller",
    bad_description:
      "Detected language allocating all audit costs to the controller without exception.",
    explanation:
      "Standard practice splits routine-audit cost to the controller but allocates cost to the processor where the audit uncovers material breach.",
    recommendation:
      "Carve out an exception for audits revealing material breach (cost shifts to the processor).",
    bad_patterns: [
      /controller\s+(shall|will)\s+bear\s+(all|the\s+entire|the\s+full)\s+costs?\s+of\s+(any\s+)?audit/i,
      /audit.{0,80}(at\s+(the\s+)?controller'?s?\s+(sole\s+)?(cost|expense))/is,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Compliance posture
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "DPA-050",
    name: "Personal data referenced in document",
    description: "DPA should reference 'personal data'; absence likely means the wrong template.",
    citation: "GDPR Art. 4(1)",
    missing_title: "Document does not reference personal data",
    missing_description: "No references to personal data were detected.",
    explanation:
      "A DPA template that never mentions 'personal data' is highly likely to be the wrong template.",
    recommendation: "Use a DPA template that explicitly references Personal Data throughout.",
    present_patterns: [/personal\s+data/i],
  }),
  presence({
    id: "DPA-051",
    name: "Notice clause present",
    description: "DPA should specify how formal notices (including breach notices) are delivered.",
    citation: "GDPR Art. 33(2)",
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
  presence({
    id: "DPA-052",
    name: "Survival of GDPR obligations post-termination",
    description:
      "DPA should state that obligations applicable to retained personal data survive termination.",
    citation: "GDPR Art. 28(3)(g)",
    missing_title: "Survival clause missing",
    missing_description: "No survival clause was found extending obligations past termination.",
    explanation:
      "Where personal data is retained post-termination, the protective obligations should survive.",
    recommendation:
      "Add: 'Obligations applicable to retained Personal Data shall survive termination.'",
    present_patterns: [/survive\s+(the\s+)?termination|survival/i],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-053",
    name: "Records of subprocessor changes available",
    description: "Processor should keep records of subprocessor changes available on request.",
    citation: "GDPR Art. 28(2)",
    missing_title: "Records of subprocessor changes not referenced",
    missing_description:
      "No clause was found making subprocessor-change history available to the controller.",
    explanation:
      "Best-practice DPAs require the processor to maintain a record of subprocessor changes for the controller.",
    recommendation:
      "Add: 'Processor shall maintain a record of Sub-processors and changes thereto, available to Controller on request.'",
    present_patterns: [
      /(record\s+of\s+sub[- ]?processors|sub[- ]?processor\s+(history|log)|maintain.{0,80}sub[- ]?processor)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-054",
    name: "Onward transfer obligations (SCC Clause 8.8)",
    description:
      "Where SCCs apply, the DPA should reference onward-transfer obligations per SCC Clause 8.8.",
    citation: "Commission Implementing Decision (EU) 2021/914, Clause 8.8",
    missing_title: "Onward-transfer clause missing",
    missing_description: "No clause was found governing onward transfers.",
    explanation:
      "SCC Clause 8.8 requires onward transfers to be subject to the same data protection obligations.",
    recommendation:
      "Add: 'Onward transfers shall be subject to the same data protection obligations as set out in this Agreement.'",
    present_patterns: [/(onward\s+transfer|clause\s+8\.8|onward[- ]transfer)/i],
    default_severity: "warning",
  }),
  presence({
    id: "DPA-055",
    name: "Local-law disclosure obligations (Clause 14 / 15)",
    description:
      "Where SCCs apply, processor must notify controller of legally-binding requests by public authorities.",
    citation: "Commission Implementing Decision (EU) 2021/914, Clauses 14 and 15",
    missing_title: "Local-law disclosure obligation missing",
    missing_description:
      "No clause was found requiring notification of public-authority requests for personal data.",
    explanation:
      "SCC Clauses 14 and 15 require the processor to notify the controller of legally-binding requests from public authorities and to challenge such requests where possible.",
    recommendation:
      "Add a clause requiring notification of public-authority requests and an obligation to challenge where permitted.",
    present_patterns: [
      /(public\s+authority|government\s+request|law\s+enforcement\s+request|clause\s+14|clause\s+15)/i,
    ],
    default_severity: "warning",
  }),
];

if (DPA_GDPR_RULES.length !== 55) {
  throw new Error(`DPA-GDPR ruleset must export exactly 55 rules; got ${DPA_GDPR_RULES.length}`);
}
