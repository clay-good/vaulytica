/**
 * v4 Regulatory prose ruleset — 40 rules
 * (spec-v4.md §6.P, Step 59).
 *
 * Six new playbooks (P.1–P.6): Form D narrative, Form ADV Part 2A
 * brochure, S-1 / 10-K risk factors (shared ruleset), PPM narrative,
 * Reg A+ offering circular. Plus the always-fires `REG-040` filing-
 * schema disclaimer rule scoped to every P playbook (spec §6.P caveat).
 *
 * Rule ids are flat `REG-NNN` (001..040).
 */

import { makeFinding, type Finding, type Rule, type RuleContext } from "../../../finding.js";
import {
  buildV4PresenceRule,
  buildV4LanguageRule,
  docTop,
  type V4PresenceSpec,
  type V4LanguageSpec,
} from "../_helpers.js";
import {
  REG_PLAYBOOK_FORM_D,
  REG_PLAYBOOK_FORM_ADV,
  REG_PLAYBOOK_S1,
  REG_PLAYBOOK_10K,
  REG_PLAYBOOK_PPM,
  REG_PLAYBOOK_REG_A,
  REG_PLAYBOOK_IDS,
  regD,
  formDInstructions,
  formAdv,
  regSk105,
  plainEnglish,
  regA,
  blueSky,
  regPractice,
} from "./_helpers.js";

const CATEGORY = "regulatory-prose";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });
const language = (s: Omit<V4LanguageSpec, "category">): Rule =>
  buildV4LanguageRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// P.1 — Form D narrative. 7 rules: REG-001..REG-007.
// ────────────────────────────────────────────────────────────────────

const FORM_D_RULES: Rule[] = [
  presence({
    id: "REG-001",
    name: "Issuer identification",
    description:
      "Form D narrative must identify the issuer (name, jurisdiction of organization, CIK).",
    citation: formDInstructions(),
    playbooks: [REG_PLAYBOOK_FORM_D],
    missing_title: "Issuer identification clause missing",
    missing_description: "No clause was found identifying the issuer (name + jurisdiction + CIK).",
    explanation:
      "Form D Item 1 requires issuer identification — name, jurisdiction of organization, CIK / EDGAR file number.",
    recommendation:
      "Add 'Issuer' identifying name, jurisdiction of organization, and CIK / EDGAR file number.",
    present_patterns: [
      /(issuer|company|registrant)/i,
      /(jurisdiction\s+of\s+(organization|incorporation)|state\s+of\s+(organization|formation))/i,
    ],
  }),
  presence({
    id: "REG-002",
    name: "Exemption claimed — Rule 504 / 506(b) / 506(c)",
    description: "Form D narrative must identify the exemption claimed (Rule 504, 506(b), 506(c)).",
    citation: regD("506", "Rule 506(b) / 506(c) safe harbor"),
    playbooks: [REG_PLAYBOOK_FORM_D],
    missing_title: "Exemption identification clause missing",
    missing_description: "No clause was found identifying the Reg D exemption claimed.",
    explanation:
      "Form D Item 6 requires identification of the exemption(s) claimed. 506(c) permits general solicitation but requires verified accredited-investor status; 506(b) prohibits general solicitation.",
    recommendation: "Add 'Exemption' identifying Rule 504, 506(b), or 506(c) claimed.",
    present_patterns: [/(rule\s+50[46]|rule\s+506\(b\)|rule\s+506\(c\))/i, /(exempt|exemption)/i],
  }),
  presence({
    id: "REG-003",
    name: "Accredited-investor reps + verification (if 506(c))",
    description:
      "Form D narrative must address accredited-investor reps; under 506(c), must describe verification method.",
    citation: regD("501", "Accredited investor definition"),
    playbooks: [REG_PLAYBOOK_FORM_D],
    missing_title: "Accredited-investor reps / verification clause missing",
    missing_description: "No accredited-investor reps / verification clause was found.",
    explanation:
      "506(c) Rule 506(c) requires issuer to take 'reasonable steps to verify' accredited status; 506(b) accepts reasonable belief based on questionnaire.",
    recommendation:
      "Add 'Accredited Investor' covering reps and (for 506(c)) verification methods (income / net-worth / third-party letter).",
    present_patterns: [/(accredited\s+investor)/i, /(verif(y|ication|ied)|reasonable\s+steps)/i],
  }),
  presence({
    id: "REG-004",
    name: "General solicitation policy — 506(b) prohibition / 506(c) permission",
    description:
      "Narrative must address whether general solicitation is permitted (506(c)) or prohibited (506(b)).",
    citation: regD("502", "General solicitation"),
    playbooks: [REG_PLAYBOOK_FORM_D],
    missing_title: "General solicitation policy clause missing",
    missing_description: "No general-solicitation policy clause was found.",
    explanation:
      "Rule 502(c) prohibits general solicitation for Rule 506(b) offerings; Rule 506(c) permits with verification. Misalignment is the most common Reg D foot-fault.",
    recommendation:
      "Add 'General Solicitation' stating policy — prohibited (506(b)) or permitted with verification (506(c)).",
    present_patterns: [/general\s+solicit/i, /(prohibit|forbid|permit|advertising|web)/i],
  }),
  presence({
    id: "REG-005",
    name: "Bad-actor disqualification — Rule 506(d)",
    description: "Form D issuers must address Rule 506(d) bad-actor disqualification screening.",
    citation: regD("506", "Rule 506(d) bad-actor disqualification"),
    playbooks: [REG_PLAYBOOK_FORM_D],
    missing_title: "Bad-actor disqualification clause missing",
    missing_description: "No Rule 506(d) bad-actor disqualification clause was found.",
    explanation:
      "Rule 506(d) disqualifies covered persons (directors, officers, 20%+ owners, etc.) with disqualifying events from relying on Rule 506. Disclosure of pre-2013 events is required.",
    recommendation:
      "Add 'Bad-Actor Disqualification' confirming covered-persons screening + disclosure of pre-2013 events.",
    present_patterns: [
      /(bad.actor|rule\s+506\(d\)|disqualif)/i,
      /(covered\s+persons?|disqualifying\s+events?)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "REG-006",
    name: "Offering amount + minimum investment",
    description:
      "Form D narrative must state aggregate offering amount and any minimum investment.",
    citation: formDInstructions(),
    playbooks: [REG_PLAYBOOK_FORM_D],
    missing_title: "Offering amount / minimum investment clause missing",
    missing_description: "No offering-amount / minimum-investment clause was found.",
    explanation:
      "Form D Items 13–14 require aggregate offering amount and minimum-investment information.",
    recommendation:
      "Add 'Offering Size' specifying aggregate offering amount and minimum investment per investor.",
    present_patterns: [
      /(offering\s+(size|amount|aggregate))/i,
      /(minimum\s+(investment|subscription))/i,
      /\$\s*[\d,]+/,
    ],
  }),
  presence({
    id: "REG-007",
    name: "State blue-sky notice filings",
    description: "Form D narrative should address state blue-sky notice filings.",
    citation: blueSky(),
    playbooks: [REG_PLAYBOOK_FORM_D],
    missing_title: "State blue-sky notice clause missing",
    missing_description: "No state blue-sky notice clause was found.",
    explanation:
      "Most states require notice filings for Reg D offerings (NSMIA-preempted but most states require Form D copies + filing fees). Failure to file blocks resale.",
    recommendation:
      "Add 'State Blue-Sky' addressing notice filings in each state where investors reside.",
    present_patterns: [/(blue.sky|state\s+notice|nsmia)/i, /(notice\s+filing|state\s+securities)/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// P.2 — Form ADV Part 2A Brochure. 8 rules: REG-008..REG-015.
// ────────────────────────────────────────────────────────────────────

const FORM_ADV_RULES: Rule[] = [
  presence({
    id: "REG-008",
    name: "Cover page + material-changes summary",
    description:
      "Form ADV Part 2A brochure must include a cover page + Item 2 material-changes summary.",
    citation: formAdv("1", "Cover page"),
    playbooks: [REG_PLAYBOOK_FORM_ADV],
    missing_title: "Cover page / material-changes clause missing",
    missing_description: "No cover-page / material-changes clause was found.",
    explanation:
      "Form ADV Part 2A Items 1 + 2 require a cover page (firm name + contact + date) plus a summary of material changes since the prior annual update.",
    recommendation:
      "Add 'Cover Page' (firm + contact + date) and 'Item 2 — Material Changes' summary.",
    present_patterns: [/(cover\s+page|brochure|part\s+2a)/i, /(material\s+changes|item\s+2)/i],
  }),
  presence({
    id: "REG-009",
    name: "Advisory business + services description",
    description: "Brochure must describe advisory business + types of services (Item 4).",
    citation: formAdv("4", "Advisory business"),
    playbooks: [REG_PLAYBOOK_FORM_ADV],
    missing_title: "Advisory business / services clause missing",
    missing_description: "No advisory-business / services clause was found.",
    explanation:
      "Form ADV Part 2A Item 4 requires description of the advisory firm, its services, and assets under management.",
    recommendation: "Add 'Item 4 — Advisory Business' describing services, AUM, and tailoring.",
    present_patterns: [
      /(advisory\s+business|investment\s+advisory\s+services|item\s+4)/i,
      /(aum|assets\s+under\s+management)/i,
    ],
  }),
  presence({
    id: "REG-010",
    name: "Fees and compensation",
    description: "Brochure must describe fees and compensation (Item 5).",
    citation: formAdv("5", "Fees and compensation"),
    playbooks: [REG_PLAYBOOK_FORM_ADV],
    missing_title: "Fees and compensation clause missing",
    missing_description: "No fees-and-compensation clause was found.",
    explanation:
      "Form ADV Part 2A Item 5 requires description of fees, billing method, refund policy, and other compensation.",
    recommendation:
      "Add 'Item 5 — Fees and Compensation' describing fee schedule, billing, refunds, and other compensation.",
    present_patterns: [/(fees|compensation|fee\s+schedule)/i, /(billing|refund|item\s+5)/i],
  }),
  presence({
    id: "REG-011",
    name: "Methods of analysis + investment strategies + risk of loss",
    description:
      "Brochure must describe methods of analysis, investment strategies, and material risks (Item 8).",
    citation: formAdv("8", "Methods + strategies + risks"),
    playbooks: [REG_PLAYBOOK_FORM_ADV],
    missing_title: "Methods / strategies / risks clause missing",
    missing_description: "No methods / strategies / risks clause was found.",
    explanation:
      "Form ADV Part 2A Item 8 requires methods of analysis, investment strategies, and material risks of loss.",
    recommendation: "Add 'Item 8 — Methods of Analysis, Investment Strategies and Risk of Loss'.",
    present_patterns: [
      /(methods\s+of\s+analysis|investment\s+strateg)/i,
      /(risk\s+of\s+loss|material\s+risks?)/i,
    ],
  }),
  presence({
    id: "REG-012",
    name: "Disciplinary information (Item 9)",
    description: "Brochure must disclose disciplinary events (or state none).",
    citation: formAdv("9", "Disciplinary information"),
    playbooks: [REG_PLAYBOOK_FORM_ADV],
    missing_title: "Disciplinary information clause missing",
    missing_description: "No disciplinary-information clause was found.",
    explanation:
      "Form ADV Part 2A Item 9 requires disclosure of legal or disciplinary events material to evaluation of advisory business.",
    recommendation:
      "Add 'Item 9 — Disciplinary Information' disclosing any material disciplinary events (or stating none).",
    present_patterns: [
      /(disciplinary\s+(information|events?)|item\s+9)/i,
      /(legal\s+(events?|proceedings?)|sanctions?)/i,
    ],
  }),
  presence({
    id: "REG-013",
    name: "Code of ethics + personal trading (Item 11)",
    description: "Brochure must describe code of ethics and personal-trading policies (Item 11).",
    citation: formAdv("11", "Code of ethics"),
    playbooks: [REG_PLAYBOOK_FORM_ADV],
    missing_title: "Code of ethics / personal trading clause missing",
    missing_description: "No code-of-ethics / personal-trading clause was found.",
    explanation:
      "Form ADV Part 2A Item 11 requires description of the code of ethics, personal trading, and participation / interest in client transactions.",
    recommendation:
      "Add 'Item 11 — Code of Ethics, Participation in Client Transactions, Personal Trading'.",
    present_patterns: [
      /(code\s+of\s+ethics|personal\s+trading)/i,
      /(participation|client\s+transactions?|item\s+11)/i,
    ],
  }),
  presence({
    id: "REG-014",
    name: "Brokerage practices + soft dollars (Item 12)",
    description:
      "Brochure must describe brokerage selection and any soft-dollar arrangements (Item 12).",
    citation: formAdv("12", "Brokerage practices"),
    playbooks: [REG_PLAYBOOK_FORM_ADV],
    missing_title: "Brokerage practices clause missing",
    missing_description: "No brokerage-practices clause was found.",
    explanation:
      "Form ADV Part 2A Item 12 requires description of broker selection, soft-dollar arrangements, directed brokerage, and order aggregation.",
    recommendation:
      "Add 'Item 12 — Brokerage Practices' covering selection, soft dollars, directed brokerage, and aggregation.",
    present_patterns: [
      /(brokerage\s+practices?|broker.?dealer)/i,
      /(soft\s+dollars?|directed\s+brokerage|item\s+12)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "REG-015",
    name: "Custody (Item 15)",
    description:
      "Brochure must address custody (Item 15) — whether adviser has custody and qualified-custodian arrangements.",
    citation: formAdv("15", "Custody"),
    playbooks: [REG_PLAYBOOK_FORM_ADV],
    missing_title: "Custody clause missing",
    missing_description: "No custody clause was found.",
    explanation:
      "Form ADV Part 2A Item 15 requires disclosure of custody (Rule 206(4)-2 of the Advisers Act). Custody triggers qualified-custodian + surprise-examination requirements.",
    recommendation:
      "Add 'Item 15 — Custody' identifying whether adviser has custody and qualified-custodian / examination arrangements.",
    present_patterns: [
      /(custody|qualified\s+custodian)/i,
      /(item\s+15|rule\s+206\(4\)|surprise\s+examination)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// P.3 + P.4 — S-1 / 10-K Risk Factors (shared ruleset). 9 rules: REG-016..REG-024.
// ────────────────────────────────────────────────────────────────────

const RISK_FACTORS_RULES: Rule[] = [
  presence({
    id: "REG-016",
    name: "Risk-factor section heading + introduction",
    description:
      "Filing must include a clearly labeled 'Risk Factors' section with introduction (Item 105).",
    citation: regSk105(),
    playbooks: [REG_PLAYBOOK_S1, REG_PLAYBOOK_10K],
    missing_title: "Risk Factors section heading clause missing",
    missing_description: "No clearly labeled 'Risk Factors' section was found.",
    explanation: "Reg S-K Item 105 requires a separately captioned 'Risk Factors' section.",
    recommendation:
      "Add a 'Risk Factors' section with introductory paragraph framing the risks discussed.",
    present_patterns: [/risk\s+factors/i, /(material\s+risks?|principal\s+risks?)/i],
  }),
  presence({
    id: "REG-017",
    name: "Item 105 — material-risk-only standard + 15-page summary trigger",
    description:
      "Risk factors must address material risks only; > 15-page sections require a separate 2-page risk-factor summary.",
    citation: regSk105(),
    playbooks: [REG_PLAYBOOK_S1, REG_PLAYBOOK_10K],
    missing_title: "Item 105 materiality / summary clause missing",
    missing_description: "No Item 105 materiality / risk-factor-summary clause was found.",
    explanation:
      "Item 105 (revised 2020) requires materiality threshold + a separate 2-page summary when the Risk Factors section exceeds 15 pages.",
    recommendation:
      "Limit to material risks; if section > 15 pages, add a separately captioned 2-page summary of risk factors.",
    present_patterns: [/(material\s+risks?|item\s+105)/i, /(summary|2.?page|15.?page)/i],
    default_severity: "warning",
  }),
  language({
    id: "REG-018",
    version: "1.1.0",
    name: "Generic / boilerplate risk factor flagged",
    description: "Risk factors must not be generic boilerplate applicable to any company.",
    citation: regSk105(),
    playbooks: [REG_PLAYBOOK_S1, REG_PLAYBOOK_10K],
    bad_patterns: [
      /we\s+(may|might)\s+not\s+be\s+able\s+to\s+attract\s+and\s+retain\s+(qualified\s+)?(personnel|key\s+employees)/i,
      /general\s+economic\s+conditions\s+(may|could).{0,40}adversely\s+affect/is,
      /(our|the)\s+business\s+(may|could).{0,40}be\s+affected\s+by.{0,40}factors\s+beyond\s+our\s+control/is,
      // The canonical content-free boilerplate the SEC's Item 105 targets puts
      // the issuer first: "WE MAY BE ADVERSELY AFFECTED BY general economic
      // conditions … and other factors beyond our control" — the reverse of
      // the "economic conditions may affect us" order the patterns above knew,
      // so the most common generic risk factor slipped.
      /\bwe\s+(?:may|might|could)\s+be\s+(?:materially\s+and\s+)?adversely\s+affected\s+by\b[^.]{0,120}\b(?:general\s+economic\s+conditions|factors\s+beyond\s+our\s+control|numerous\s+factors|many\s+factors|various\s+factors)\b/is,
    ],
    bad_title: "Generic / boilerplate risk factor flagged",
    // The patterns match a boilerplate OPENING clause; they never read the rest
    // of the sentence, so the description must not assert the whole risk factor
    // lacks specificity — a highly specific, quantified risk factor can open
    // with this phrasing.
    bad_description:
      "Risk factor opens with boilerplate phrasing that could apply to any company; confirm the disclosure goes on to state issuer-specific detail.",
    explanation:
      "SEC staff have repeatedly cautioned against generic risk factors. Item 105 (2020 revision) emphasized the materiality threshold to drive out boilerplate.",
    recommendation:
      "Specify how the risk uniquely affects this issuer's operations, products, geographies, or capital structure.",
    default_severity: "warning",
  }),
  language({
    id: "REG-019",
    name: "Hypothetical / 'could' risk-factor language flagged for specificity",
    description:
      "Risk factors that hedge as merely hypothetical without specifying current exposures should be flagged.",
    citation: regSk105(),
    playbooks: [REG_PLAYBOOK_S1, REG_PLAYBOOK_10K],
    bad_patterns: [
      /(we\s+may|could|might)\s+(experience|face|be\s+subject\s+to)\s+(cyber|security|data\s+breach)/i,
      /(potential|hypothetical).{0,40}(risk|impact)/is,
    ],
    // The whole point of the Pearson / First American line is framing an
    // ALREADY-MATERIALIZED risk as hypothetical. A paragraph that narrates the
    // actual incident has done exactly what the rule asks for, so reporting it
    // as "merely hypothetical" is contradicted by the excerpt itself.
    exclude_if: [
      /\bwe\s+(?:have\s+)?(?:experienced|suffered|sustained|identified|discovered|disclosed|reported|been\s+subject\s+to)\b/i,
    ],
    bad_title: "Hypothetical / hedged risk factor flagged",
    bad_description:
      "Risk factor appears to discuss merely-hypothetical risks without disclosing whether the company has already experienced such an event.",
    explanation:
      "SEC enforcement (e.g., Pearson, First American) has charged issuers for framing as 'hypothetical' risks that had already materialized. Disclose actual incidents that have occurred.",
    recommendation:
      "If the risk has already materialized (cyber incident, breach, material adverse event), disclose factually — not as a hypothetical.",
    default_severity: "warning",
  }),
  presence({
    id: "REG-020",
    version: "1.1.0",
    name: "Risk-factor headlines / subheadings (plain English)",
    description:
      "Each risk factor should have a concise, plain-English headline (Item 105 + Rule 421).",
    citation: plainEnglish(),
    playbooks: [REG_PLAYBOOK_S1, REG_PLAYBOOK_10K],
    missing_title: "Risk-factor headlines clause missing",
    missing_description: "No risk-factor subheadings / headlines were found.",
    explanation:
      "Securities Act Rule 421(b) plain-English rule + Item 105 require risk-factor subheadings that adequately describe each risk.",
    recommendation:
      "Add concise subheadings (1-line) describing each risk factor; avoid generic captions.",
    present_patterns: [
      /(subheading|headline|caption)/i,
      /(plain\s+english|item\s+105)/i,
      // The presence of ACTUAL grouping subheadings — "Risks Related to Our
      // Lending Business" — satisfies the organization requirement; the
      // branches above only detected prose TALKING ABOUT headlines.
      /risks\s+relat(?:ed|ing)\s+to\s+/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "REG-021",
    name: "Forward-looking statement safe-harbor cross-reference (PSLRA)",
    description:
      "Risk factors should cross-reference the Private Securities Litigation Reform Act safe harbor where applicable.",
    citation: regPractice(
      "pslra",
      "Private Securities Litigation Reform Act safe harbor (15 U.S.C. § 77z-2 / § 78u-5)",
      "https://www.law.cornell.edu/uscode/text/15/78u-5",
    ),
    playbooks: [REG_PLAYBOOK_S1, REG_PLAYBOOK_10K],
    missing_title: "PSLRA safe-harbor cross-reference clause missing",
    missing_description: "No PSLRA safe-harbor cross-reference was found.",
    explanation:
      "PSLRA safe harbor (15 U.S.C. §§ 77z-2, 78u-5) protects forward-looking statements accompanied by meaningful cautionary statements identifying specific risk factors.",
    recommendation:
      "Add a forward-looking-statements section + cross-reference to risk factors to support the PSLRA safe harbor.",
    present_patterns: [
      /(forward.looking|safe\s+harbor)/i,
      /(pslra|meaningful\s+cautionary|securities\s+litigation\s+reform)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "REG-022",
    name: "Cybersecurity / data-breach risk factor",
    description:
      "Risk factors should address cybersecurity / data-breach risk (per 2023 cybersecurity disclosure rules).",
    citation: regPractice(
      "cyber-disclosure",
      "SEC Cybersecurity Disclosure Rule (Reg S-K Item 106 + Form 8-K Item 1.05)",
      "https://www.sec.gov/news/press-release/2023-139",
    ),
    playbooks: [REG_PLAYBOOK_S1, REG_PLAYBOOK_10K],
    missing_title: "Cybersecurity risk factor clause missing",
    missing_description: "No cybersecurity / data-breach risk factor was found.",
    explanation:
      "SEC's 2023 cybersecurity rule (Reg S-K Item 106 + Form 8-K Item 1.05) makes cyber disclosure compulsory for most issuers; risk factors should align.",
    recommendation:
      "Add a 'Cybersecurity' risk factor describing material cyber risks and incidents.",
    present_patterns: [
      /(cybersecurity|cyber\s+attack|data\s+breach|ransomware|item\s+106|item\s+1\.05)/i,
      /(risk|incident|exposure)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "REG-023",
    name: "Climate / environmental risk factor (where material)",
    description:
      "Risk factors should address material climate / environmental / ESG risks where applicable.",
    citation: regPractice(
      "climate-disclosure",
      "SEC Climate Disclosure proposal + state ESG rules + investor pressure (Reg S-K Item 105 materiality)",
      "https://www.sec.gov/news/press-release/2024-31",
    ),
    playbooks: [REG_PLAYBOOK_S1, REG_PLAYBOOK_10K],
    missing_title: "Climate / environmental risk factor clause missing",
    missing_description: "No climate / environmental risk factor was found.",
    explanation:
      "SEC climate disclosure rules (where stayed / litigated) + Reg S-K Item 105 materiality + investor expectations + EU CSRD increasingly require climate-related risk disclosure for material exposures.",
    recommendation:
      "Where material, add a 'Climate / Environmental' risk factor covering physical risks, transition risks, regulatory exposures, and supply-chain effects.",
    present_patterns: [
      /(climate|environmental|esg|sustainability)/i,
      /(risk|emissions?|transition|physical)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "REG-024",
    name: "Update vs prior periodic report (10-K only)",
    description:
      "10-K risk factors should update / cross-reference prior-period risk factors (S-K Item 105 + Form 10-K Instructions).",
    citation: regSk105(),
    playbooks: [REG_PLAYBOOK_10K],
    missing_title: "10-K update / cross-reference clause missing",
    missing_description: "No 10-K update / cross-reference clause was found.",
    explanation:
      "10-K filers should update risk factors to reflect material developments since the last periodic report.",
    recommendation:
      "Add 'Updates from Prior Period' or analogous to identify new / changed risk factors.",
    present_patterns: [
      /(update|new\s+(risk|risk\s+factor)|changes\s+since)/i,
      /(prior\s+(year|period)|10.?k|annual\s+report)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// P.5 — PPM narrative. 8 rules: REG-025..REG-032.
// ────────────────────────────────────────────────────────────────────

const PPM_RULES: Rule[] = [
  presence({
    id: "REG-025",
    name: "Issuer + offering overview",
    description:
      "PPM must include issuer description + offering overview (security type, amount, use of proceeds).",
    citation: regPractice(
      "ppm-overview",
      "PPM baseline (Reg D + state blue-sky offering memorandum standards)",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [REG_PLAYBOOK_PPM],
    missing_title: "Issuer / offering overview clause missing",
    missing_description: "No issuer-overview / offering-overview clause was found.",
    explanation:
      "PPMs combine Reg D Form D disclosures with offering-document detail. The overview is the central marketing-document framing.",
    recommendation:
      "Add 'Overview' covering issuer description, security type (equity / debt / SAFE), offering amount, and use of proceeds.",
    present_patterns: [
      /(overview|summary)/i,
      /(security|securities|equity|debt|saf)/i,
      /(use\s+of\s+proceeds|offering\s+amount)/i,
    ],
  }),
  presence({
    id: "REG-026",
    name: "Risk-factor section (material risks)",
    description:
      "PPM must include risk-factor section describing material risks specific to the offering.",
    citation: regSk105(),
    playbooks: [REG_PLAYBOOK_PPM],
    missing_title: "PPM risk-factor section clause missing",
    missing_description: "No risk-factor section was found in the PPM.",
    explanation:
      "Even though Reg D doesn't require specific PPM content, risk-factor disclosure protects against 10b-5 fraud claims.",
    recommendation:
      "Add 'Risk Factors' section with offering-specific material risks (liquidity, dilution, control, regulatory).",
    present_patterns: [/risk\s+factors/i, /(material\s+risks?|principal\s+risks?)/i],
  }),
  presence({
    id: "REG-027",
    name: "Suitability standards + investor qualifications",
    description:
      "PPM must state investor-qualification / suitability standards (accredited investor / sophistication).",
    citation: regD("501", "Accredited investor"),
    playbooks: [REG_PLAYBOOK_PPM],
    missing_title: "Suitability / qualification clause missing",
    missing_description: "No suitability / investor-qualification clause was found.",
    explanation:
      "Reg D 506(b)/(c) and state blue-sky require accredited-investor qualifications. PPM should articulate the standard.",
    recommendation:
      "Add 'Suitability' / 'Investor Qualifications' covering accredited-investor rules (and sophistication for 35-or-fewer non-accredited under 506(b)).",
    present_patterns: [
      /(suitability|investor\s+qualification|accredited\s+investor)/i,
      /(sophistication|knowledge\s+and\s+experience)/i,
    ],
  }),
  presence({
    id: "REG-028",
    name: "Subscription procedure + minimum / maximum",
    description: "PPM must describe subscription procedure and any minimum / maximum.",
    citation: regPractice(
      "ppm-subscription",
      "PPM subscription procedure baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [REG_PLAYBOOK_PPM],
    missing_title: "Subscription procedure clause missing",
    missing_description: "No subscription procedure / minimum / maximum clause was found.",
    explanation:
      "PPM should explain how investors subscribe — questionnaire, subscription agreement, funding mechanism, closing process.",
    recommendation:
      "Add 'Subscription Procedure' with questionnaire / subscription agreement / payment process / closing.",
    present_patterns: [
      /(subscription|subscribe|investor\s+questionnaire)/i,
      /(minimum|maximum|escrow|closing)/i,
    ],
  }),
  presence({
    id: "REG-029",
    name: "Transfer restrictions + securities-law legend",
    description:
      "PPM must address transfer restrictions + Rule 144 / restricted-securities legend.",
    citation: regPractice(
      "rule-144",
      "Rule 144 (17 C.F.R. § 230.144) — restricted securities legend",
      "https://www.law.cornell.edu/cfr/text/17/230.144",
    ),
    playbooks: [REG_PLAYBOOK_PPM],
    missing_title: "Transfer restrictions / legend clause missing",
    missing_description:
      "No transfer-restrictions / restricted-securities legend clause was found.",
    explanation:
      "Reg D securities are 'restricted securities' under Rule 144 — investors cannot resell freely. Standard legend warns of these limits.",
    recommendation:
      "Add 'Transfer Restrictions' with the standard Rule 144 restricted-securities legend + applicable resale conditions.",
    present_patterns: [
      /(transfer\s+restrictions?|restricted\s+securities)/i,
      /(rule\s+144|securities\s+act\s+legend)/i,
    ],
  }),
  presence({
    id: "REG-030",
    name: "Conflicts of interest disclosure",
    description: "PPM must disclose material conflicts of interest.",
    citation: regPractice(
      "ppm-coi",
      "PPM conflicts-of-interest disclosure baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [REG_PLAYBOOK_PPM],
    missing_title: "Conflicts of interest disclosure clause missing",
    missing_description: "No conflicts-of-interest disclosure was found.",
    explanation:
      "Material conflicts (sponsor / GP related-party transactions, fee-sharing) must be disclosed; failure is a leading 10b-5 fraud claim.",
    recommendation:
      "Add 'Conflicts of Interest' disclosing related-party transactions, sponsor / GP fees, and material conflicts.",
    present_patterns: [
      /(conflicts?\s+of\s+interest|related.?party)/i,
      /(disclos|related|sponsor|general\s+partner)/i,
    ],
  }),
  presence({
    id: "REG-031",
    name: "Tax considerations",
    description: "PPM should include material tax considerations.",
    citation: regPractice(
      "ppm-tax",
      "PPM tax-considerations baseline (Circular 230 + safe harbor disclaimers)",
      "https://www.americanbar.org/groups/taxation/",
    ),
    playbooks: [REG_PLAYBOOK_PPM],
    missing_title: "Tax considerations clause missing",
    missing_description: "No tax considerations / Circular 230 clause was found.",
    explanation:
      "Material tax considerations (passive activity, UBTI, K-1 vs 1099 reporting, basis, ECI) are typical PPM content; Circular 230 disclaimers may apply.",
    recommendation:
      "Add 'Tax Considerations' covering material federal income tax issues + appropriate Circular 230 disclaimer.",
    present_patterns: [
      /(tax\s+considerations?|tax\s+matters?)/i,
      /(circular\s+230|federal\s+income\s+tax|ubti|k.?1)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "REG-032",
    name: "State blue-sky notice + selling-agent compliance",
    description: "PPM must address state blue-sky notice filings + selling-agent registration.",
    citation: blueSky(),
    playbooks: [REG_PLAYBOOK_PPM],
    missing_title: "State blue-sky / selling-agent clause missing",
    missing_description: "No state blue-sky / selling-agent clause was found.",
    explanation:
      "State blue-sky laws + FINRA registration (where selling agents are involved) must be addressed in PPM marketing channels.",
    recommendation:
      "Add 'State Blue-Sky and Selling Agents' covering state notice-filings + selling-agent registration / FINRA compliance.",
    present_patterns: [
      /(blue.sky|state\s+(notice|securities))/i,
      /(selling\s+agent|placement\s+agent|finra)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// P.6 — Reg A+ offering circular. 7 rules: REG-033..REG-039.
// ────────────────────────────────────────────────────────────────────

const REG_A_RULES: Rule[] = [
  presence({
    id: "REG-033",
    name: "Tier 1 vs Tier 2 election + offering-size cap",
    description: "Offering circular must identify Tier 1 ($20M cap) or Tier 2 ($75M cap) election.",
    citation: regA("Tier 1 / Tier 2"),
    playbooks: [REG_PLAYBOOK_REG_A],
    missing_title: "Tier 1 / Tier 2 election clause missing",
    missing_description: "No Tier 1 / Tier 2 election clause was found.",
    explanation:
      "Reg A Tier 1 caps at $20M / 12 months; Tier 2 at $75M (after 2024 amendments). Tier 2 preempts state blue-sky but requires audited financials + ongoing reporting.",
    recommendation: "Add 'Tier' identifying Tier 1 or Tier 2 election and applicable offering cap.",
    present_patterns: [/(tier\s+1|tier\s+2|tier\s+i|tier\s+ii)/i, /\$\s*(20|75)\s*(million|m)/i],
  }),
  presence({
    id: "REG-034",
    name: "Form 1-A item structure followed",
    description: "Circular must follow Form 1-A item structure (Parts I / II / III).",
    citation: regA("Form 1-A"),
    playbooks: [REG_PLAYBOOK_REG_A],
    missing_title: "Form 1-A structure clause missing",
    missing_description: "No Form 1-A structure / item references found.",
    explanation:
      "Form 1-A Part I (notification), Part II (offering circular), Part III (exhibits) is the prescribed structure.",
    recommendation:
      "Follow Form 1-A structure with Part I notification + Part II offering circular + Part III exhibits.",
    present_patterns: [
      /(form\s+1.?a|part\s+i|part\s+ii)/i,
      /(notification|offering\s+circular|exhibits)/i,
    ],
  }),
  presence({
    id: "REG-035",
    name: "Risk factors specific to offering",
    description: "Reg A+ circular must include offering-specific risk factors.",
    citation: regSk105(),
    playbooks: [REG_PLAYBOOK_REG_A],
    missing_title: "Reg A+ risk factors clause missing",
    missing_description: "No risk-factors section was found in the offering circular.",
    explanation:
      "Form 1-A Item 1 (Part II) requires risk factors; standard practice mirrors Reg S-K Item 105.",
    recommendation:
      "Add 'Risk Factors' with offering-specific material risks (operating, financial, regulatory, investor-protection).",
    present_patterns: [/risk\s+factors/i, /(material\s+risks?|principal\s+risks?)/i],
  }),
  presence({
    id: "REG-036",
    name: "Use of proceeds + plan of distribution",
    description: "Circular must describe use of proceeds + plan of distribution.",
    citation: regA("Form 1-A"),
    playbooks: [REG_PLAYBOOK_REG_A],
    missing_title: "Use of proceeds / plan of distribution clause missing",
    missing_description: "No use-of-proceeds / plan-of-distribution clause was found.",
    explanation:
      "Form 1-A Items 3 + 4 require use of proceeds and plan of distribution. Use-of-proceeds drift drives investor protection scrutiny.",
    recommendation:
      "Add 'Use of Proceeds' and 'Plan of Distribution' with intended use of capital + distribution channels (self-distribution / broker-dealer / online).",
    present_patterns: [
      /(use\s+of\s+proceeds)/i,
      /(plan\s+of\s+distribution|distribution\s+channels?)/i,
    ],
  }),
  presence({
    id: "REG-037",
    name: "Investment limitation for non-accredited investors (Tier 2)",
    description:
      "Tier 2 circular must address the 10% income / net-worth investment limitation for non-accredited investors.",
    citation: regA("Tier 2"),
    playbooks: [REG_PLAYBOOK_REG_A],
    missing_title: "Non-accredited 10% investment-limitation clause missing",
    missing_description:
      "No clause was found addressing the Tier 2 non-accredited 10% investment cap.",
    explanation:
      "17 C.F.R. § 230.251(d)(2)(i)(C) limits non-accredited Tier 2 investors to 10% of greater of annual income or net worth per offering.",
    recommendation:
      "Add 'Investment Limitations' explaining the 10% cap on non-accredited Tier 2 investors.",
    present_patterns: [/(10\s?%|ten\s+percent)/i, /(annual\s+income|net\s+worth|non.accredited)/i],
    default_severity: "warning",
  }),
  presence({
    id: "REG-038",
    name: "Audited financials (Tier 2) — narrative reference",
    description:
      "Tier 2 circular must reference audited financials (2 years of audited statements required).",
    citation: regA("Tier 2"),
    playbooks: [REG_PLAYBOOK_REG_A],
    missing_title: "Audited financials clause missing (Tier 2)",
    missing_description:
      "No clause was found referencing the Tier 2 audited-financials requirement.",
    explanation:
      "Tier 2 requires 2 years of audited financial statements (Tier 1 requires reviewed). The narrative should reference where the financials appear.",
    recommendation:
      "Add 'Financial Statements' cross-reference to the audited financials (Tier 2) or reviewed financials (Tier 1).",
    present_patterns: [
      /(audited\s+financial(s|\s+statements?))/i,
      /(2\s+years?|two\s+years?|fiscal\s+year)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "REG-039",
    name: "Ongoing reporting (Tier 2) — Form 1-K / 1-SA / 1-U",
    description:
      "Tier 2 circular must address ongoing reporting (Form 1-K annual, Form 1-SA semi-annual, Form 1-U current).",
    citation: regA("Tier 2"),
    playbooks: [REG_PLAYBOOK_REG_A],
    missing_title: "Ongoing reporting clause missing (Tier 2)",
    missing_description: "No clause was found addressing Tier 2 ongoing reporting.",
    explanation:
      "Tier 2 issuers must file Form 1-K (annual), Form 1-SA (semi-annual), and Form 1-U (current). Tier 1 issuers have lighter reporting.",
    recommendation: "Add 'Ongoing Reporting' covering Form 1-K / 1-SA / 1-U deadlines and content.",
    present_patterns: [
      /(form\s+1.?k|form\s+1.?sa|form\s+1.?u)/i,
      /(annual\s+report|semi.?annual|current\s+report)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// REG-040 — Always-fires filing-schema-only disclaimer (spec §6.P caveat).
// ────────────────────────────────────────────────────────────────────

const FILING_SCHEMA_DISCLAIMER_RULE: Rule = {
  id: "REG-040",
  version: "1.0.0",
  name: "v4 lints prose only — financial statements + filing schemas are out of scope",
  category: CATEGORY,
  default_severity: "info",
  description:
    "Per spec-v4.md §6.P caveat, every output in the regulatory-prose sub-domain must say explicitly that v4 lints only the drafter's prose — not financial statements, numbers, or filing schemas. This rule emits that disclaimer on every analysis run in this sub-domain.",
  dkb_citations: ["reg-prose-disclaimer"],
  applies_to_playbooks: [...REG_PLAYBOOK_IDS],
  check(ctx: RuleContext): Finding | null {
    return makeFinding({
      rule: this as Rule,
      title: "v4 lints prose only — financial statements + filing schemas are out of scope",
      description:
        "Vaulytica lints the drafter's prose in regulatory filings — narrative risk factors, MD&A, plain-English disclosures. It does NOT opine on financial statements, accounting policies, EDGAR / Form D / Form ADV / Form 1-A filing schemas, financial calculations, or numerical disclosures. The regulator's review of the filing schema is the regulator's job, not the linter's.",
      excerptText: "(disclaimer applies to every regulatory-prose analysis run)",
      explanation:
        "Regulatory filings (Form D, Form ADV, S-1, 10-K, PPM, Reg A+) combine drafter's prose with financial statements + filing schemas. v4 lints the drafter's text against published authority. The numerical disclosures live in the auditor's report; the filing schema lives in the EDGAR / SEC / FINRA validators. Both are outside Vaulytica's scope.",
      recommendation:
        "Confirm financial-statement accuracy with auditors; confirm filing-schema compliance with EDGAR / SEC / FINRA validators; rely on Vaulytica's findings for prose / disclosure only.",
      position: docTop(ctx),
      source_citations: [
        {
          id: "reg-prose-disclaimer",
          source:
            "Vaulytica spec-v4.md §6.P caveat — prose-only / filing-schema disclaimer required on every output in regulatory-prose sub-domain",
          source_url: "https://vaulytica.com/#spec-v4-6p-regulatory-prose-filing-schema-disclaimer",
          retrieved_at: "2026-05-16T00:00:00Z",
          license: "MIT",
          license_url: "https://opensource.org/licenses/MIT",
        },
      ],
    });
  },
};

// ────────────────────────────────────────────────────────────────────
// Aggregate. 40 rules total.
// ────────────────────────────────────────────────────────────────────

export const REGULATORY_PROSE_RULES: Rule[] = [
  ...FORM_D_RULES,
  ...FORM_ADV_RULES,
  ...RISK_FACTORS_RULES,
  ...PPM_RULES,
  ...REG_A_RULES,
  FILING_SCHEMA_DISCLAIMER_RULE,
];

export {
  FORM_D_RULES,
  FORM_ADV_RULES,
  RISK_FACTORS_RULES,
  PPM_RULES,
  REG_A_RULES,
  FILING_SCHEMA_DISCLAIMER_RULE,
};
