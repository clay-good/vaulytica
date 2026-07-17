/**
 * v4 Compliance policies ruleset — 50 rules
 * (spec-v4.md §6.O, Step 58).
 *
 * Ten new playbooks (O.1–O.10). Rule ids are flat `POL-NNN` (001..050).
 */

import type { Rule } from "../../../finding.js";
import {
  buildV4PresenceRule,
  buildV4LanguageRule,
  type V4PresenceSpec,
  type V4LanguageSpec,
} from "../_helpers.js";
import {
  POL_PLAYBOOK_CODE_OF_CONDUCT,
  POL_PLAYBOOK_FCPA,
  POL_PLAYBOOK_AML,
  POL_PLAYBOOK_INSIDER,
  POL_PLAYBOOK_WHISTLEBLOWER,
  POL_PLAYBOOK_RETENTION,
  POL_PLAYBOOK_COI,
  POL_PLAYBOOK_AI_AUP,
  POL_PLAYBOOK_SOCIAL_MEDIA,
  POL_PLAYBOOK_LOBBYING,
  nyse303A,
  nasdaq5610,
  soxSection,
  fcpa,
  ukba,
  bsa,
  ofac,
  rule10b5,
  whistleblowerLaw,
  sedona,
  form990,
  nistAiRmf,
  euAiAct,
  nlraSec7,
  ftcEndorsement,
  lda,
  polPractice,
} from "./_helpers.js";

const CATEGORY = "compliance-policy";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });
const language = (s: Omit<V4LanguageSpec, "category">): Rule =>
  buildV4LanguageRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// O.1 — Code of Conduct / Ethics. 5 rules: POL-001..POL-005.
// ────────────────────────────────────────────────────────────────────

const CODE_OF_CONDUCT_RULES: Rule[] = [
  presence({
    id: "POL-001",
    name: "Scope — applies to directors, officers, employees",
    description: "Code must state it applies to directors, officers, and employees.",
    citation: nyse303A(),
    playbooks: [POL_PLAYBOOK_CODE_OF_CONDUCT],
    missing_title: "Scope clause missing",
    missing_description:
      "No clause was found stating the Code applies to directors, officers, and employees.",
    explanation:
      "NYSE § 303A.10 / Nasdaq 5610 require listed-issuer codes to cover all directors, officers, and employees.",
    recommendation:
      "Add 'Scope' applying the Code to directors, officers, employees (and contractors / agents where appropriate).",
    present_patterns: [/(directors?|officers?|employees?)/i, /(apply|applies|applicable|cover)/i],
  }),
  presence({
    id: "POL-002",
    name: "SOX § 406 financial-officer ethics elements",
    description:
      "Code must address SOX § 406 elements for senior financial officers — honest / ethical conduct, accurate disclosures, compliance with law.",
    citation: soxSection("406", "Code of Ethics for Senior Financial Officers"),
    playbooks: [POL_PLAYBOOK_CODE_OF_CONDUCT],
    missing_title: "SOX § 406 elements clause missing",
    missing_description:
      "No clause was found covering SOX § 406 elements for senior financial officers.",
    explanation:
      "SOX § 406 (15 U.S.C. § 7264) requires public-company codes for senior financial officers to address honest / ethical conduct, full / fair / accurate disclosures in SEC filings, compliance with laws, prompt reporting of violations, and accountability.",
    recommendation:
      "Add 'Senior Financial Officers' covering honest / ethical conduct, accurate SEC disclosures, compliance with applicable law, prompt reporting, and accountability.",
    present_patterns: [
      /(honest|ethical\s+conduct|integrity)/i,
      /(full|fair|accurate).{0,40}disclos/is,
      /(compliance\s+with\s+law|laws,?\s+rules)/i,
    ],
  }),
  presence({
    id: "POL-003",
    name: "Waiver disclosure mechanism",
    description: "Code must address how waivers are granted and disclosed (NYSE / Nasdaq + SOX).",
    citation: nasdaq5610(),
    playbooks: [POL_PLAYBOOK_CODE_OF_CONDUCT],
    missing_title: "Waiver disclosure clause missing",
    missing_description: "No clause was found addressing waiver grants and disclosure.",
    explanation:
      "Both NYSE 303A.10 and Nasdaq 5610 require disclosure of waivers granted to directors / executive officers within 4 business days (Form 8-K Item 5.05).",
    recommendation:
      "Add 'Waivers' clause permitting waivers only by the board (or designated committee) and requiring 8-K disclosure within 4 business days for executive officers / directors.",
    present_patterns: [
      /waiver/i,
      /(board|audit\s+committee|nominating)/i,
      /(disclos|8.?k|form\s+8.?k|4\s+business\s+days?)/i,
    ],
  }),
  presence({
    id: "POL-004",
    name: "Reporting violations + non-retaliation",
    description: "Code must establish a confidential reporting channel and prohibit retaliation.",
    citation: whistleblowerLaw(),
    playbooks: [POL_PLAYBOOK_CODE_OF_CONDUCT],
    missing_title: "Reporting / non-retaliation clause missing",
    missing_description: "No clause was found establishing reporting channel and non-retaliation.",
    explanation:
      "SOX § 806 (18 U.S.C. § 1514A) + Dodd-Frank § 922 + SOX § 301 audit-committee complaint procedures require confidential / anonymous reporting and non-retaliation.",
    recommendation:
      "Add 'Reporting and Non-Retaliation' clause establishing hotline / ombudsperson, anonymous reporting option, and explicit no-retaliation rule.",
    present_patterns: [
      /(report\s+violations|hotline|helpline|ombudsperson|anonymous(ly)?)/i,
      /(no\s+retaliation|non.?retaliation|whistleblower)/i,
    ],
  }),
  presence({
    id: "POL-005",
    name: "Compliance with laws + regulations",
    description: "Code must require compliance with applicable laws and regulations.",
    citation: nyse303A(),
    playbooks: [POL_PLAYBOOK_CODE_OF_CONDUCT],
    missing_title: "Compliance with laws clause missing",
    missing_description:
      "No clause was found requiring compliance with applicable laws and regulations.",
    explanation:
      "The compliance-with-law obligation is the baseline. Listed-issuer codes always include this; private-company codes routinely do.",
    recommendation:
      "Add 'Compliance with Laws' requiring conformance with all applicable laws, rules, and regulations.",
    present_patterns: [/(compliance\s+with|comply\s+with)/i, /(laws|regulations|rules|statutes)/i],
  }),
];

// ────────────────────────────────────────────────────────────────────
// O.2 — FCPA / Anti-bribery. 6 rules: POL-006..POL-011.
// ────────────────────────────────────────────────────────────────────

const FCPA_RULES: Rule[] = [
  presence({
    id: "POL-006",
    name: "FCPA anti-bribery prohibition",
    description: "Policy must prohibit corrupt payments to foreign officials (FCPA § 30A / § 30B).",
    citation: fcpa("78dd-1"),
    playbooks: [POL_PLAYBOOK_FCPA],
    missing_title: "FCPA anti-bribery clause missing",
    missing_description: "No clause was found prohibiting corrupt payments to foreign officials.",
    explanation:
      "15 U.S.C. §§ 78dd-1 / -2 / -3 prohibit corrupt payments to foreign officials to obtain or retain business. Policy must affirmatively prohibit.",
    recommendation:
      "Add 'Prohibited Payments' enumerating the FCPA prohibitions on corrupt payments to foreign officials.",
    present_patterns: [
      /(fcpa|foreign\s+corrupt\s+practices\s+act)/i,
      /(prohibit|forbid|may\s+not)/i,
      /(foreign\s+official|government\s+official|bribe)/i,
    ],
  }),
  presence({
    id: "POL-007",
    name: "Third-party / agent / intermediary due diligence",
    description: "Policy must require due diligence on third parties / agents / intermediaries.",
    citation: polPractice(
      "dojfcpa-third-party",
      "DOJ-SEC FCPA Resource Guide — third-party due diligence",
      "https://www.justice.gov/criminal/criminal-fraud/foreign-corrupt-practices-act",
    ),
    playbooks: [POL_PLAYBOOK_FCPA],
    missing_title: "Third-party due-diligence clause missing",
    missing_description:
      "No clause was found requiring third-party / agent / intermediary due diligence.",
    explanation:
      "DOJ-SEC FCPA Resource Guide emphasizes that third-party intermediaries are the most common channel for FCPA violations. Risk-based due diligence is the standard.",
    recommendation:
      "Add 'Third-Party Due Diligence' requiring risk-based screening, anti-corruption reps and warranties, and audit rights for high-risk intermediaries.",
    present_patterns: [
      /(third.?part(y|ies)|agents?|intermediar(y|ies)|distributor)/i,
      /(due\s+diligence|screening|background)/i,
    ],
  }),
  presence({
    id: "POL-008",
    name: "Books-and-records + internal-controls (FCPA accounting)",
    description:
      "Policy must address FCPA accounting provisions — accurate books and records + adequate internal controls.",
    citation: fcpa("78m"),
    playbooks: [POL_PLAYBOOK_FCPA],
    missing_title: "Books-and-records / internal-controls clause missing",
    missing_description:
      "No clause was found addressing FCPA books-and-records or internal-controls provisions.",
    explanation:
      "15 U.S.C. § 78m(b)(2) requires issuers to maintain accurate books and records and adequate internal accounting controls. Violations can be charged without underlying bribery.",
    recommendation:
      "Add 'Books and Records / Internal Controls' requiring accurate recording of transactions and adequate internal accounting controls.",
    present_patterns: [
      /(books\s+and\s+records|accounting\s+(records|controls))/i,
      /(internal\s+(accounting\s+)?controls?|78m)/i,
      /(accurate|accuracy)/i,
    ],
  }),
  presence({
    id: "POL-009",
    name: "Facilitating payments — narrowness / prohibition recital",
    description:
      "Policy must address facilitating payments (typically prohibited despite the narrow FCPA exception).",
    citation: fcpa("78dd-1(b)"),
    playbooks: [POL_PLAYBOOK_FCPA],
    missing_title: "Facilitating-payments clause missing",
    missing_description: "No facilitating-payments clause was found.",
    explanation:
      "The narrow FCPA facilitating-payments exception (§ 78dd-1(b)) does not exist under the UK Bribery Act and most other regimes. Best practice: prohibit them entirely.",
    recommendation:
      "Add 'Facilitating Payments' prohibiting facilitating / grease payments (regardless of any narrow FCPA exception).",
    present_patterns: [
      /(facilitating\s+payments?|grease\s+payments?|expedite)/i,
      /(prohibit|forbid|not\s+permit)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "POL-010",
    name: "UK Bribery Act / cross-border applicability",
    description:
      "Policy should address UK Bribery Act 2010 + other non-US anti-corruption regimes.",
    citation: ukba(),
    playbooks: [POL_PLAYBOOK_FCPA],
    missing_title: "UKBA / cross-border clause missing",
    missing_description: "No UKBA / cross-border clause was found.",
    explanation:
      "UK Bribery Act 2010 is broader than FCPA — extends to commercial bribery, has 'failure to prevent bribery' offense, no facilitating-payments exception, broad jurisdictional reach. Most multinationals follow the stricter regime.",
    recommendation:
      "Add 'Cross-Border' clause acknowledging UKBA + other applicable non-US anti-corruption regimes and applying the stricter standard.",
    present_patterns: [
      /(uk\s+bribery\s+act|ukba|bribery\s+act\s+2010)/i,
      /(failure\s+to\s+prevent|cross.border|adequate\s+procedures)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "POL-011",
    name: "Gifts, hospitality, charitable contributions thresholds",
    description:
      "Policy must address gifts / hospitality / charitable contributions / political contributions (US + non-US).",
    citation: polPractice(
      "gifts-hospitality",
      "Gifts / hospitality / charitable contributions baseline (DOJ-SEC FCPA Resource Guide ch. 2)",
      "https://www.justice.gov/criminal/criminal-fraud/foreign-corrupt-practices-act",
    ),
    playbooks: [POL_PLAYBOOK_FCPA],
    missing_title: "Gifts / hospitality / charitable contributions clause missing",
    missing_description:
      "No gifts / hospitality / charitable / political contributions clause was found.",
    explanation:
      "Gifts and hospitality to foreign officials are the most common FCPA risk area. Policy should set monetary thresholds, pre-approval workflow, and recordkeeping.",
    recommendation:
      "Add 'Gifts, Hospitality, Charitable and Political Contributions' setting thresholds, pre-approval workflow, and recordkeeping requirements.",
    present_patterns: [
      /(gifts?|hospitality|entertainment|meals)/i,
      /(charitable|political\s+contribution)/i,
      /(threshold|pre.?approval|recordkeeping)/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// O.3 — AML policy. 6 rules: POL-012..POL-017.
// ────────────────────────────────────────────────────────────────────

const AML_RULES: Rule[] = [
  presence({
    id: "POL-012",
    name: "AML program — BSA five pillars",
    description:
      "AML policy must establish the five-pillar AML program (BSA + FinCEN final rule 2018).",
    citation: bsa(),
    playbooks: [POL_PLAYBOOK_AML],
    missing_title: "BSA five-pillar AML program clause missing",
    missing_description: "No AML five-pillar program clause was found.",
    explanation:
      "FinCEN's 2018 final rule requires (1) internal policies / procedures / controls, (2) compliance officer designation, (3) ongoing employee training, (4) independent testing / audit, and (5) customer due diligence including beneficial-ownership identification.",
    recommendation:
      "Add 'AML Program' establishing the five pillars: policies / procedures, AML officer, training, independent testing, CDD + beneficial ownership.",
    present_patterns: [
      /(aml\s+program|anti.?money.?laundering)/i,
      /(compliance\s+officer|aml\s+officer)/i,
      /(training|testing|cdd|customer\s+due\s+diligence)/i,
    ],
  }),
  presence({
    id: "POL-013",
    name: "OFAC sanctions screening",
    description: "Policy must require OFAC sanctions screening (SDN + sectoral lists).",
    citation: ofac(),
    playbooks: [POL_PLAYBOOK_AML],
    missing_title: "OFAC sanctions screening clause missing",
    missing_description: "No OFAC sanctions screening clause was found.",
    explanation:
      "31 C.F.R. Chapter V (OFAC) prohibits transactions with SDNs and entities on sectoral / sanctions lists. Strict liability — even unintentional dealings can trigger penalties.",
    recommendation:
      "Add 'OFAC Sanctions Screening' requiring customer / transaction screening against SDN + sectoral / sanctions lists and blocking / reporting procedures.",
    present_patterns: [
      /(ofac|office\s+of\s+foreign\s+assets\s+control)/i,
      /(sdn|specially\s+designated\s+nationals|sanctions\s+list)/i,
      /(screen(ing)?|block(ing)?|report)/i,
    ],
  }),
  presence({
    id: "POL-014",
    name: "Suspicious activity reporting (SAR) procedures",
    description:
      "Policy must establish SAR procedures (FinCEN 31 C.F.R. § 1010.320 thresholds + 30-day deadline).",
    citation: bsa(),
    playbooks: [POL_PLAYBOOK_AML],
    missing_title: "SAR procedure clause missing",
    missing_description: "No SAR procedure clause was found.",
    explanation:
      "FinCEN requires SAR filing within 30 days of detection (with 30-day extension); the policy must define triggers, escalation, filing channels, and confidentiality.",
    recommendation:
      "Add 'Suspicious Activity Reports' specifying detection / escalation / filing within 30 days + SAR confidentiality.",
    present_patterns: [
      /(suspicious\s+activity\s+report|sar)/i,
      /(30\s+days?|thirty\s+days?|fincen)/i,
      /(confidential|tipping.?off)/i,
    ],
  }),
  presence({
    id: "POL-015",
    name: "Customer identification program (CIP) + beneficial ownership",
    description: "Policy must establish CIP and FinCEN beneficial-ownership identification rule.",
    citation: polPractice(
      "fincen-cdd",
      "FinCEN CDD final rule — beneficial ownership (31 C.F.R. § 1010.230)",
      "https://www.fincen.gov/resources/statutes-regulations/cdd-final-rule",
    ),
    playbooks: [POL_PLAYBOOK_AML],
    missing_title: "CIP / beneficial-ownership clause missing",
    missing_description: "No CIP / beneficial-ownership clause was found.",
    explanation:
      "FinCEN CDD rule + Corporate Transparency Act (CTA, 2024) require identification of beneficial owners (25%+ ownership / control). CIP requires name, DOB, address, ID number for natural-person customers.",
    recommendation:
      "Add 'Customer Identification Program' + 'Beneficial Ownership' covering CIP elements (name / DOB / address / ID), 25% ownership threshold, and CTA reporting where applicable.",
    present_patterns: [
      /(cip|customer\s+identification\s+program)/i,
      /(beneficial\s+ownership|beneficial\s+owners?)/i,
      /(25%|twenty.five\s+percent|cta|corporate\s+transparency)/i,
    ],
  }),
  presence({
    id: "POL-016",
    name: "Currency Transaction Reports (CTR) ≥ $10,000",
    description:
      "Covered businesses must file CTRs for currency transactions exceeding $10,000 (31 C.F.R. § 1010.311).",
    citation: bsa(),
    playbooks: [POL_PLAYBOOK_AML],
    missing_title: "CTR / $10,000 currency-reporting clause missing",
    missing_description: "No CTR / $10,000 currency-reporting clause was found.",
    explanation:
      "FinCEN requires CTRs for currency transactions over $10,000 (aggregating same-day transactions by the same person). Structuring to evade is a separate criminal offense (31 U.S.C. § 5324).",
    recommendation:
      "Add 'Currency Transaction Reports' covering $10,000 aggregation rule, structuring prohibition, and CTR filing procedure.",
    present_patterns: [
      /(ctr|currency\s+transaction\s+report)/i,
      /(\$10,?000|ten\s+thousand)/i,
      /(structuring|aggregation|aggregate)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "POL-017",
    name: "Recordkeeping + retention",
    description: "AML records must be retained for at least 5 years (31 C.F.R. § 1010.430).",
    citation: bsa(),
    playbooks: [POL_PLAYBOOK_AML],
    missing_title: "AML recordkeeping / retention clause missing",
    missing_description: "No AML recordkeeping / retention clause was found.",
    explanation:
      "FinCEN requires AML records (SARs, CTRs, CIP records, BSA records) to be retained for 5 years.",
    recommendation:
      "Add 'Recordkeeping' specifying 5-year retention for SARs, CTRs, CIP records, and other BSA documentation.",
    present_patterns: [
      /(recordkeeping|records?\s+retention|retain)/i,
      /(5\s+years?|five\s+years?)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// O.4 — Insider Trading. 5 rules: POL-018..POL-022.
// ────────────────────────────────────────────────────────────────────

const INSIDER_TRADING_RULES: Rule[] = [
  presence({
    id: "POL-018",
    name: "Material non-public information (MNPI) prohibition",
    description: "Policy must prohibit trading on material non-public information (Rule 10b-5).",
    citation: rule10b5(false),
    playbooks: [POL_PLAYBOOK_INSIDER],
    missing_title: "MNPI / insider-trading prohibition clause missing",
    missing_description:
      "No clause was found prohibiting trading on material non-public information.",
    explanation:
      "Rule 10b-5 prohibits trading on MNPI; tipping liability extends to third parties under *Dirks v. SEC* + *Salman v. United States*.",
    recommendation:
      "Add 'Prohibited Trading' clause prohibiting any transaction in company securities while in possession of MNPI and prohibiting tipping.",
    present_patterns: [
      /(material\s+non.?public\s+information|mnpi)/i,
      /(insider\s+trading|trad(e|ing)\s+(while|on)\s+the\s+basis)/i,
      /(prohibit|forbid|may\s+not)/i,
    ],
  }),
  presence({
    id: "POL-019",
    name: "Blackout periods + pre-clearance for insiders",
    description:
      "Policy must establish blackout periods around earnings + pre-clearance for Section 16 insiders.",
    citation: polPractice(
      "blackout",
      "Insider-trading policy — blackout period + pre-clearance baseline",
      "https://www.sec.gov/about/laws/sea34.pdf",
    ),
    playbooks: [POL_PLAYBOOK_INSIDER],
    missing_title: "Blackout / pre-clearance clause missing",
    missing_description: "No blackout / pre-clearance clause was found.",
    explanation:
      "Blackout periods (quarterly windows before earnings) + pre-clearance for directors / officers / designated insiders are standard prophylactic controls.",
    recommendation:
      "Add 'Blackout Periods and Pre-Clearance' establishing quarterly blackouts around earnings + pre-clearance for Section 16 insiders.",
    present_patterns: [
      /(blackout\s+period|trading\s+window|window\s+period)/i,
      /(pre.?clearance|pre.?approval|trading\s+window)/i,
      /(section\s+16|insider|director|officer)/i,
    ],
  }),
  presence({
    id: "POL-020",
    name: "Rule 10b5-1 trading-plan provisions",
    description:
      "Policy should address Rule 10b5-1 trading plans (December 2022 amendments — cooling-off + good faith).",
    citation: rule10b5(true),
    playbooks: [POL_PLAYBOOK_INSIDER],
    missing_title: "Rule 10b5-1 plan clause missing",
    missing_description: "No Rule 10b5-1 trading-plan clause was found.",
    explanation:
      "December 2022 amendments require cooling-off periods (90 days for officers / directors), good-faith certification, single-plan limit, and quarterly Form 10-Q disclosure. Plans entered in bad faith / overlapping invalidate the affirmative defense.",
    recommendation:
      "Add 'Rule 10b5-1 Plans' addressing cooling-off (90 days / 30 days), good-faith certification, single-plan limit, modification restrictions, and disclosure.",
    present_patterns: [
      /(10b5.?1|rule\s+10b5.?1)/i,
      /(cooling.?off|good\s+faith\s+certif|trading\s+plan)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "POL-021",
    name: "Tipper / tippee liability + family members + 'spreading the love' prohibition",
    description:
      "Policy must address tipping liability (covers family members / friends / brokers).",
    citation: rule10b5(false),
    playbooks: [POL_PLAYBOOK_INSIDER],
    missing_title: "Tipping liability clause missing",
    missing_description: "No tipping-liability clause was found.",
    explanation:
      "Under *Dirks* + *Salman*, tippers and tippees can be liable; family / friend tips create reasonable inference of personal benefit.",
    recommendation:
      "Add 'Tipping' prohibiting disclosure of MNPI to anyone, including family / friends / brokers.",
    present_patterns: [
      /(tipping|tippee|tipper)/i,
      /(family|friends?|relatives?)/i,
      /(disclos|disclos)/i,
    ],
  }),
  presence({
    id: "POL-022",
    name: "Short sales / derivatives / hedging restrictions",
    description:
      "Policy should restrict short sales, hedging, and derivative transactions by insiders.",
    citation: polPractice(
      "hedging",
      "Dodd-Frank § 955 hedging disclosure + Item 407(i) of Regulation S-K",
      "https://www.law.cornell.edu/cfr/text/17/229.407",
    ),
    playbooks: [POL_PLAYBOOK_INSIDER],
    missing_title: "Short sales / hedging restrictions clause missing",
    missing_description: "No clause was found restricting short sales / hedging / derivatives.",
    explanation:
      "Item 407(i) of Reg S-K (Dodd-Frank § 955) requires disclosure of hedging policies. Most issuers prohibit insiders from hedging / pledging / short-selling company stock.",
    recommendation:
      "Add 'Hedging and Short Sales' prohibiting insider hedging, short sales, pledging, and trading in derivatives.",
    present_patterns: [
      /(short\s+sales?|hedge|hedging|derivative)/i,
      /(prohibit|forbid|may\s+not)/i,
      /(pledg(e|ing)|margin)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// O.5 — Whistleblower Policy. 5 rules: POL-023..POL-027.
// ────────────────────────────────────────────────────────────────────

const WHISTLEBLOWER_RULES: Rule[] = [
  presence({
    id: "POL-023",
    name: "Reporting channels — internal + external",
    description:
      "Policy must establish internal reporting channels and acknowledge external (SEC / CFTC / DOL) options.",
    citation: whistleblowerLaw(),
    playbooks: [POL_PLAYBOOK_WHISTLEBLOWER],
    missing_title: "Reporting channels clause missing",
    missing_description: "No clause was found establishing reporting channels.",
    explanation:
      "SOX § 301 audit-committee complaints + Dodd-Frank § 922 SEC bounty + agency-specific programs (CFTC, DOL OSHA) create overlapping options. Policy should support internal reporting without restricting external rights.",
    recommendation:
      "Add 'Reporting Channels' establishing hotline / ombudsperson / supervisor + audit-committee channel + acknowledging right to report to SEC / CFTC / DOL.",
    present_patterns: [
      /(hotline|helpline|ombudsperson|audit\s+committee|reporting\s+channels?)/i,
      /(sec|cftc|dol|nlrb|government\s+agency)/i,
    ],
  }),
  presence({
    id: "POL-024",
    name: "Non-retaliation prohibition + SOX / Dodd-Frank protections",
    description:
      "Policy must prohibit retaliation and reference SOX § 806 + Dodd-Frank § 922 protections.",
    citation: whistleblowerLaw(),
    playbooks: [POL_PLAYBOOK_WHISTLEBLOWER, POL_PLAYBOOK_CODE_OF_CONDUCT],
    missing_title: "Non-retaliation / statutory-protection clause missing",
    missing_description: "No non-retaliation / statutory-protection clause was found.",
    explanation:
      "SOX § 806 (18 U.S.C. § 1514A) + Dodd-Frank § 922 (15 U.S.C. § 78u-6(h)) prohibit retaliation against whistleblowers; remedies include reinstatement, back pay, and special damages.",
    recommendation:
      "Add 'Non-Retaliation' clause prohibiting retaliation and reciting SOX / Dodd-Frank protections.",
    present_patterns: [
      /(non.?retaliation|no\s+retaliation|will\s+not\s+retaliate)/i,
      /(sox\s+§\s*806|dodd.?frank|§\s*922|protected)/i,
    ],
  }),
  presence({
    id: "POL-025",
    name: "SEC Rule 21F-17 — no impeding whistleblower communications",
    description:
      "Policy must comply with SEC Rule 21F-17 (17 C.F.R. § 240.21F-17) — no provision shall impede whistleblower communications.",
    citation: polPractice(
      "sec-21f17",
      "SEC Rule 21F-17 — anti-impeding-whistleblower rule",
      "https://www.law.cornell.edu/cfr/text/17/240.21F-17",
    ),
    playbooks: [POL_PLAYBOOK_WHISTLEBLOWER],
    missing_title: "Rule 21F-17 carve-out clause missing",
    missing_description: "No Rule 21F-17 carve-out clause was found.",
    explanation:
      "SEC Rule 21F-17 prohibits any agreement / policy provision that impedes whistleblower communications with the SEC. SEC enforcement actions have repeatedly fined employers for non-compliant NDAs / severance / handbook provisions.",
    recommendation:
      "Add 'No Impediment to Government Reporting' clause stating nothing in this policy or any company agreement restricts employee's ability to communicate with government agencies or receive any bounty.",
    present_patterns: [
      /(21f.?17|21f17|nothing\s+(in\s+)?this\s+(policy|agreement))/i,
      /(government\s+(agency|investigation)|communicat\s+with|sec)/i,
      /(impede|prevent|restrict|interfere)/i,
    ],
  }),
  presence({
    id: "POL-026",
    name: "Confidentiality + anonymous reporting",
    description: "Policy must offer confidentiality and an anonymous reporting option.",
    citation: soxSection("301", "Audit-committee complaint procedures"),
    playbooks: [POL_PLAYBOOK_WHISTLEBLOWER],
    missing_title: "Confidentiality / anonymous reporting clause missing",
    missing_description: "No confidentiality / anonymous reporting clause was found.",
    explanation:
      "SOX § 301 requires audit-committee complaint procedures with confidentiality and anonymity. Anonymous channels (third-party hotline) drive higher reporting rates.",
    recommendation:
      "Add 'Confidentiality and Anonymity' establishing confidential handling and anonymous reporting (typically via third-party hotline).",
    present_patterns: [/(confidential(ity)?|anonymous(ly)?|anonymity)/i, /(hotline|third.?party)/i],
  }),
  presence({
    id: "POL-027",
    name: "Investigation procedure + corrective action",
    description: "Policy must describe investigation procedure and corrective action.",
    citation: polPractice(
      "investigation",
      "Whistleblower investigation procedure baseline",
      "https://www.dol.gov/agencies/oalj/topics/libraries/LIBRARY_SARBOX",
    ),
    playbooks: [POL_PLAYBOOK_WHISTLEBLOWER],
    missing_title: "Investigation procedure clause missing",
    missing_description: "No investigation procedure / corrective-action clause was found.",
    explanation:
      "Without described procedure, complainants do not trust the channel and may go directly external — defeating the policy's purpose.",
    recommendation:
      "Add 'Investigation' describing timeline, independent investigator, status updates, and corrective action where warranted.",
    present_patterns: [
      /(investigation|investigate|inquiry)/i,
      /(corrective\s+action|remedy|outcome|status\s+update)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// O.6 — Document Retention. 5 rules: POL-028..POL-032.
// ────────────────────────────────────────────────────────────────────

const DOC_RETENTION_RULES: Rule[] = [
  presence({
    id: "POL-028",
    name: "Retention schedule — record types + periods",
    description: "Policy must include a retention schedule (record types + retention periods).",
    citation: polPractice(
      "retention-schedule",
      "Records retention schedule baseline (IRS / SEC / DOL + state)",
      "https://www.irs.gov/businesses/small-businesses-self-employed/how-long-should-i-keep-records",
    ),
    playbooks: [POL_PLAYBOOK_RETENTION],
    missing_title: "Retention schedule clause missing",
    missing_description: "No retention-schedule clause was found.",
    explanation:
      "Retention schedules drive both compliance (statutory minimums) and litigation defense (consistent destruction). Schedule should enumerate record categories and retention periods.",
    recommendation:
      "Add 'Retention Schedule' enumerating tax / HR / contracts / corporate / financial / regulatory record categories and retention periods.",
    present_patterns: [
      /(retention\s+schedule|retention\s+period)/i,
      /(years?|months?)/i,
      /(tax|hr|contracts?|corporate|financial)/i,
    ],
  }),
  presence({
    id: "POL-029",
    name: "Legal hold + e-discovery suspension override",
    description: "Policy must provide for legal-hold override that suspends routine destruction.",
    citation: sedona(),
    playbooks: [POL_PLAYBOOK_RETENTION],
    missing_title: "Legal-hold override clause missing",
    missing_description: "No legal-hold / suspension clause was found.",
    explanation:
      "Sedona Principles + FRCP 37(e) require suspension of routine destruction once litigation is reasonably anticipated. Without an override the policy can backfire as spoliation.",
    recommendation:
      "Add 'Legal Hold' clause suspending routine destruction on issuance of a litigation hold + cooperation with custodians + counsel.",
    present_patterns: [
      /(legal\s+hold|litigation\s+hold|preservation)/i,
      /(suspend|override|stop\s+destruction)/i,
    ],
  }),
  presence({
    id: "POL-030",
    name: "ESI / electronic records treatment",
    description:
      "Policy must address ESI (email, IM, cloud, mobile) and how it is retained / destroyed.",
    citation: sedona(),
    playbooks: [POL_PLAYBOOK_RETENTION],
    missing_title: "ESI / electronic records clause missing",
    missing_description: "No ESI / electronic records clause was found.",
    explanation:
      "ESI is the dominant record category. Policy must address email, IM (Slack / Teams), cloud storage, mobile, voicemail, and ephemeral / disappearing messaging.",
    recommendation:
      "Add 'ESI' covering email, IM, cloud, mobile, voicemail, and treatment of ephemeral messaging.",
    present_patterns: [
      /(esi|electronically\s+stored\s+information|email|cloud|mobile)/i,
      /(retention|destruction|deletion)/i,
    ],
  }),
  presence({
    id: "POL-031",
    name: "SEC / IRS / regulatory minimums",
    description:
      "Policy must align with SEC / IRS / DOL / regulatory minimum retention requirements.",
    citation: polPractice(
      "sec-irs-mins",
      "SEC + IRS + DOL retention minimum baselines (SEC Rule 17a-4; IRC § 6501; ERISA § 107)",
      "https://www.law.cornell.edu/cfr/text/17/240.17a-4",
    ),
    playbooks: [POL_PLAYBOOK_RETENTION],
    missing_title: "Regulatory minimum retention clause missing",
    missing_description: "No regulatory-minimum retention clause was found.",
    explanation:
      "SEC Rule 17a-4 (broker-dealers), IRC § 6501 (tax assessment 3-year minimum + 7-year fraud), ERISA § 107 (6 years), HIPAA § 164.530(j) (6 years) — policy must align with the longest applicable.",
    recommendation:
      "Add 'Regulatory Minimums' aligning retention with SEC / IRS / DOL / HIPAA / state minimums (the longer applicable period controls).",
    present_patterns: [
      /(sec|irs|dol|erisa|hipaa)/i,
      /(rule\s+17a.?4|6501|107|164\.530|6\s+years?|7\s+years?)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "POL-032",
    name: "Final disposition — secure destruction",
    description:
      "Policy must require secure destruction at end of retention period (shredding / certificate of destruction).",
    citation: polPractice(
      "secure-destruction",
      "Records destruction baseline (NAID AAA / shred / e-waste)",
      "https://naidonline.org/",
    ),
    playbooks: [POL_PLAYBOOK_RETENTION],
    missing_title: "Secure-destruction clause missing",
    missing_description: "No secure-destruction clause was found.",
    explanation:
      "Without secure destruction, retained records risk identity theft / breach (e.g., PHI / PII). Standard practice: NAID-AAA shred + certificate of destruction.",
    recommendation:
      "Add 'Destruction' specifying secure destruction (paper: NAID-AAA shred; electronic: NIST 800-88 sanitization) + certificate of destruction.",
    present_patterns: [
      /(secure\s+destruction|shred|naid|sanitization)/i,
      /(certificate\s+of\s+destruction)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// O.7 — Conflict of Interest. 4 rules: POL-033..POL-036.
// ────────────────────────────────────────────────────────────────────

const COI_POLICY_RULES: Rule[] = [
  presence({
    id: "POL-033",
    name: "Definition of conflict of interest",
    description: "Policy must define what constitutes a conflict of interest.",
    citation: form990(),
    playbooks: [POL_PLAYBOOK_COI],
    missing_title: "COI definition clause missing",
    missing_description: "No COI-definition clause was found.",
    explanation:
      "IRS Form 990 Part VI requires conflict-of-interest policy. ABA model nonprofit code + most state nonprofit acts require disclosure procedures.",
    recommendation:
      "Add 'Definition' covering direct / indirect financial interests, family / spouse / business / related-party transactions, and dual-board service.",
    present_patterns: [
      /(conflict\s+of\s+interest|coi)/i,
      /(financial\s+interest|related\s+party|family\s+member|business\s+(interest|relationship))/i,
    ],
  }),
  presence({
    id: "POL-034",
    name: "Annual disclosure / certification + ongoing duty",
    description: "Policy must require annual disclosure + ongoing duty to disclose new conflicts.",
    citation: form990(),
    playbooks: [POL_PLAYBOOK_COI],
    missing_title: "Annual disclosure clause missing",
    missing_description: "No annual disclosure / ongoing-duty clause was found.",
    explanation:
      "IRS Form 990 governance questions ask whether annual disclosure is required and reviewed.",
    recommendation:
      "Add 'Disclosure' requiring annual written disclosure + ongoing duty as conflicts arise.",
    present_patterns: [
      /(annual\s+disclosure|annual\s+certification)/i,
      /(ongoing|continuing\s+duty|update)/i,
    ],
  }),
  presence({
    id: "POL-035",
    name: "Recusal + review procedure for related-party transactions",
    description:
      "Policy must require recusal of conflicted board member + review / approval by disinterested directors.",
    citation: polPractice(
      "related-party",
      "Related-party transaction approval baseline (IRC § 4958 + state law)",
      "https://www.law.cornell.edu/uscode/text/26/4958",
    ),
    playbooks: [POL_PLAYBOOK_COI],
    missing_title: "Recusal / review procedure clause missing",
    missing_description: "No recusal / review-procedure clause was found.",
    explanation:
      "IRC § 4958 (intermediate sanctions) creates rebuttable presumption of reasonableness when independent body approves + relies on comparable data + documents the basis.",
    recommendation:
      "Add 'Recusal and Review' requiring conflicted member to recuse, disinterested directors to approve, and § 4958 documentation where applicable.",
    present_patterns: [
      /(recus(e|al|ed))/i,
      /(disinterested|independent\s+directors?)/i,
      /(approval|review)/i,
    ],
  }),
  presence({
    id: "POL-036",
    name: "Sanctions for violations",
    description: "Policy must address sanctions for violations (board removal, employment action).",
    citation: polPractice(
      "coi-sanctions",
      "COI policy — sanctions baseline",
      "https://www.americanbar.org/groups/nonprofit_organizations/",
    ),
    playbooks: [POL_PLAYBOOK_COI],
    missing_title: "Sanctions for violations clause missing",
    missing_description: "No sanctions-for-violations clause was found.",
    explanation:
      "Without articulated sanctions, the policy is toothless. Standard: board removal for directors, discipline up to termination for employees.",
    recommendation:
      "Add 'Sanctions' specifying consequences for non-disclosure / violation (board removal, discipline up to termination).",
    present_patterns: [
      /(sanctions?|discipline|consequences|violation)/i,
      /(remove|termination|disciplinary)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// O.8 — AI Acceptable Use Policy. 5 rules: POL-037..POL-041.
// ────────────────────────────────────────────────────────────────────

const AI_AUP_RULES: Rule[] = [
  presence({
    id: "POL-037",
    name: "Approved AI tools list + procurement gate",
    description:
      "AI AUP must specify approved AI tools and procurement / approval gate for new tools.",
    citation: nistAiRmf(),
    playbooks: [POL_PLAYBOOK_AI_AUP],
    missing_title: "Approved AI tools clause missing",
    missing_description: "No approved-AI-tools / procurement-gate clause was found.",
    explanation:
      "Shadow AI (employees using unapproved tools) is the leading AI-governance risk; an approved-tools list with procurement gate is the first line of defense.",
    recommendation:
      "Add 'Approved Tools' listing approved AI tools + 'Procurement Gate' for new tools (security + privacy + IP review).",
    present_patterns: [
      /(approved\s+(ai\s+)?tools?|allowlist|authorized\s+tools?)/i,
      /(procurement|approval|review|security\s+review)/i,
    ],
  }),
  presence({
    id: "POL-038",
    name: "Prohibited inputs — PHI / PII / trade-secret / privileged",
    description:
      "AI AUP must prohibit inputting sensitive data (PHI / PII / trade secrets / privileged material) into unapproved AI tools.",
    citation: polPractice(
      "ai-input-prohibitions",
      "AI policy — prohibited inputs baseline (HIPAA / trade secrets / privilege)",
      "https://www.nist.gov/itl/ai-risk-management-framework",
    ),
    playbooks: [POL_PLAYBOOK_AI_AUP],
    missing_title: "Prohibited inputs clause missing",
    missing_description: "No prohibited-inputs clause was found.",
    explanation:
      "Public AI tools often retain or train on prompts. Inputting PHI / PII / trade secrets / privileged material can breach HIPAA, GDPR, DTSA, and waive privilege.",
    recommendation:
      "Add 'Prohibited Inputs' enumerating PHI, PII, trade secrets, privileged communications, source code (where applicable), and confidential client data.",
    present_patterns: [
      /(phi|protected\s+health|pii|personally\s+identifiable|trade\s+secret|privileged|confidential)/i,
      /(prohibit|do\s+not\s+(input|submit|paste)|may\s+not)/i,
    ],
  }),
  presence({
    id: "POL-039",
    name: "Human-in-the-loop review for high-impact outputs",
    description:
      "AI AUP must require human review of AI outputs in high-impact contexts (hiring, lending, legal, medical).",
    citation: euAiAct(),
    playbooks: [POL_PLAYBOOK_AI_AUP],
    missing_title: "Human-in-the-loop review clause missing",
    missing_description: "No human-in-the-loop / output-review clause was found.",
    explanation:
      "EU AI Act Art. 14 requires human oversight for high-risk systems. NIST AI RMF Govern function emphasizes accountable human review. Standard practice: AI assists, humans decide for high-impact outputs.",
    recommendation:
      "Add 'Human Review' requiring meaningful human review of AI outputs in high-impact contexts (hiring, credit, legal, medical, customer-facing).",
    present_patterns: [
      /(human.?in.?the.?loop|human\s+review|human\s+oversight)/i,
      /(high.?(risk|impact)|hiring|lending|legal|medical|adverse)/i,
    ],
  }),
  presence({
    id: "POL-040",
    name: "IP / attribution / hallucination disclaimer",
    description:
      "AI AUP must address IP ownership of AI outputs, attribution, and hallucination / accuracy review.",
    citation: polPractice(
      "ai-output-quality",
      "Generative AI output baseline — IP / hallucination / attribution",
      "https://www.uspto.gov/initiatives/artificial-intelligence",
    ),
    playbooks: [POL_PLAYBOOK_AI_AUP],
    missing_title: "IP / hallucination disclaimer clause missing",
    missing_description: "No IP / hallucination / attribution clause was found.",
    explanation:
      "USPTO guidance + Thaler v. Vidal: AI-generated outputs raise copyright / patent ownership questions. Hallucinations require verification before reliance.",
    recommendation:
      "Add 'Output Quality and IP' addressing IP ownership ambiguity, attribution / disclosure expectations, and verification of AI outputs.",
    present_patterns: [
      /(hallucinat|accuracy|verif|fact.?check)/i,
      /(intellectual\s+property|copyright|attribution|disclos)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "POL-041",
    name: "Training + incident reporting",
    description:
      "AI AUP must require training and establish AI-incident reporting (data leak, hallucination harm, bias finding).",
    citation: nistAiRmf(),
    playbooks: [POL_PLAYBOOK_AI_AUP],
    missing_title: "Training / incident-reporting clause missing",
    missing_description: "No training / incident-reporting clause was found.",
    explanation:
      "NIST AI RMF Govern function emphasizes training + incident reporting as the operational backbone of AI governance.",
    recommendation:
      "Add 'Training and Incident Reporting' requiring annual AI training + procedures for reporting AI-related incidents.",
    present_patterns: [
      /(training|trained)/i,
      /(incident\s+reporting|report\s+(an\s+)?incident|hotline)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// O.9 — Social Media / External Communications. 4 rules: POL-042..POL-045.
// ────────────────────────────────────────────────────────────────────

const SOCIAL_MEDIA_POLICY_RULES: Rule[] = [
  language({
    id: "POL-042",
    name: "NLRA § 7 — overbroad social-media restriction flagged",
    description:
      "Social-media policy must not broadly restrict employee discussion of wages / working conditions (NLRA § 7).",
    citation: nlraSec7(),
    playbooks: [POL_PLAYBOOK_SOCIAL_MEDIA, POL_PLAYBOOK_CODE_OF_CONDUCT],
    bad_patterns: [
      /employees?\s+(shall|may)\s+not\s+(discuss|post|comment).{0,80}(wages?|salary|compensation|working\s+conditions)/is,
      /(social\s+media|online).{0,80}(prohibit(s|ed)?|may\s+not).{0,80}(company|employer|business)/is,
    ],
    exclude_if: [
      /(?:does|do|shall|will)\s+not\s+(?:prohibit|restrict|prevent|preclude|bar|limit)/i,
    ],
    bad_title: "Overbroad social-media restriction flagged (NLRA § 7)",
    bad_description:
      "Policy appears to broadly restrict discussion of wages / working conditions or company-related online activity.",
    explanation:
      "NLRA § 7 protects concerted activity including online discussion of wages and working conditions. NLRB *Stericycle* (2023) tightened scrutiny of rules that could chill § 7 activity.",
    recommendation:
      "Narrow the policy with explicit carve-outs for § 7 protected concerted activity and wage / working-condition discussions.",
    default_severity: "warning",
  }),
  presence({
    id: "POL-043",
    name: "FTC endorsement disclosure (employee + influencer)",
    description:
      "Policy must require FTC-compliant material-connection disclosure for endorsements / testimonials.",
    citation: ftcEndorsement(),
    playbooks: [POL_PLAYBOOK_SOCIAL_MEDIA],
    missing_title: "FTC endorsement disclosure clause missing",
    missing_description: "No FTC endorsement / material-connection disclosure clause was found.",
    explanation:
      "FTC Endorsement Guides (16 C.F.R. Part 255, 2023 revision) require clear and conspicuous disclosure of material connections (employment / payment / free product) for any endorsement.",
    recommendation:
      "Add 'Endorsements and Testimonials' requiring clear-and-conspicuous material-connection disclosure for any employee or influencer endorsement.",
    present_patterns: [
      /(endorsement|testimonial|influencer|material\s+connection)/i,
      /(disclos|disclaim|#ad|#sponsored)/i,
    ],
  }),
  presence({
    id: "POL-044",
    name: "Reg FD / SEC compliance for material disclosures",
    description: "Policy must address Reg FD compliance for public-company communications.",
    citation: polPractice(
      "reg-fd",
      "SEC Regulation FD (17 C.F.R. §§ 243.100–.103)",
      "https://www.law.cornell.edu/cfr/text/17/part-243",
    ),
    playbooks: [POL_PLAYBOOK_SOCIAL_MEDIA],
    missing_title: "Reg FD compliance clause missing",
    missing_description: "No Reg FD compliance clause was found.",
    explanation:
      "Reg FD requires public companies to disseminate material information broadly + simultaneously. SEC has confirmed that social-media may satisfy Reg FD if the channel is recognized as a means of communication.",
    recommendation:
      "Add 'Reg FD' clause restricting disclosure of material non-public information by social media + requiring use of approved disclosure channels.",
    present_patterns: [
      /(reg\s+fd|regulation\s+fd|fair\s+disclosure)/i,
      /(material\s+(information|non.?public))/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "POL-045",
    name: "Brand voice / disclaimer requirement for personal accounts",
    description:
      "Policy should require employees to use 'views are my own' disclaimer when speaking on industry / company topics.",
    citation: polPractice(
      "brand-voice",
      "Social-media brand-voice baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [POL_PLAYBOOK_SOCIAL_MEDIA],
    missing_title: "Brand-voice / personal-disclaimer clause missing",
    missing_description: "No brand-voice / personal-disclaimer clause was found.",
    explanation:
      "Distinguishing personal speech from company speech avoids attribution risk + minimizes endorsement-disclosure exposure for casual employee posts.",
    recommendation:
      "Add 'Personal Speech' requiring 'views are my own' disclaimer when employees post about industry / company topics from personal accounts.",
    present_patterns: [
      /(views?\s+are\s+my\s+own|personal\s+opinion|opinions\s+(are\s+)?my\s+own)/i,
      /(personal\s+account|individual\s+capacity)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// O.10 — Lobbying / Political Contribution. 5 rules: POL-046..POL-050.
// ────────────────────────────────────────────────────────────────────

const LOBBYING_POLICY_RULES: Rule[] = [
  presence({
    id: "POL-046",
    name: "LDA registration + quarterly reporting",
    description: "Policy must address LDA registration thresholds + quarterly LD-2 reporting.",
    citation: lda(),
    playbooks: [POL_PLAYBOOK_LOBBYING],
    missing_title: "LDA registration / quarterly reporting clause missing",
    missing_description: "No LDA registration / quarterly reporting clause was found.",
    explanation:
      "Lobbying Disclosure Act of 1995 (2 U.S.C. §§ 1601–1614) requires registration when income ≥ $14,000/quarter (in-house) and quarterly LD-2 reports. Honest Leadership and Open Government Act of 2007 adds semiannual LD-203 reports.",
    recommendation:
      "Add 'LDA Compliance' addressing registration thresholds, lobbyist designation, LD-2 quarterly reports, and LD-203 semiannual reports.",
    present_patterns: [
      /(lda|lobbying\s+disclosure\s+act)/i,
      /(ld.?2|quarterly\s+(report|filing))/i,
      /(registration|registered\s+lobbyist)/i,
    ],
  }),
  presence({
    id: "POL-047",
    name: "Pre-approval of lobbying expenditures",
    description:
      "Policy must require pre-approval of lobbying expenditures and contacts with covered officials.",
    citation: polPractice(
      "lobbying-preapproval",
      "Pre-approval baseline for lobbying activities",
      "https://lobbyingdisclosure.house.gov/",
    ),
    playbooks: [POL_PLAYBOOK_LOBBYING],
    missing_title: "Lobbying pre-approval clause missing",
    missing_description: "No pre-approval clause was found.",
    explanation:
      "Pre-approval workflow ensures activities are captured for LDA reporting and conform to policy / budget.",
    recommendation:
      "Add 'Pre-Approval' requiring written approval for lobbying activities, contacts with covered officials, and related expenditures.",
    present_patterns: [
      /(pre.?approval|pre.?approve|prior\s+approval)/i,
      /(lobby|lobbying|covered\s+official)/i,
    ],
  }),
  presence({
    id: "POL-048",
    name: "Political contributions — corporate + individual + PAC",
    description:
      "Policy must address corporate political contributions (banned federally per FECA) + individual contributions + PAC procedures.",
    citation: polPractice(
      "feca",
      "Federal Election Campaign Act (52 U.S.C. § 30118) — corporate contribution ban + state contribution limits",
      "https://www.law.cornell.edu/uscode/text/52/30118",
    ),
    playbooks: [POL_PLAYBOOK_LOBBYING],
    missing_title: "Political contributions clause missing",
    missing_description: "No political-contributions clause was found.",
    explanation:
      "FECA prohibits direct corporate contributions to federal candidates (52 U.S.C. § 30118); states vary. Many companies operate PACs subject to FEC rules.",
    recommendation:
      "Add 'Political Contributions' addressing the FECA corporate ban, state-by-state limits, PAC procedures, and individual contributions (not reimbursable).",
    present_patterns: [
      /(political\s+contributions?|campaign\s+contributions?)/i,
      /(corporate|pac|individual)/i,
      /(feca|federal\s+election\s+campaign\s+act)/i,
    ],
  }),
  presence({
    id: "POL-049",
    name: "State / local lobbying compliance",
    description:
      "Policy must address state / local lobbying registration and reporting (varies by jurisdiction).",
    citation: polPractice(
      "state-lobbying",
      "State lobbying registration / reporting baselines (NCSL clearinghouse)",
      "https://www.ncsl.org/about-state-legislatures/state-lobbying-registration-laws-and-information",
    ),
    playbooks: [POL_PLAYBOOK_LOBBYING],
    missing_title: "State / local lobbying compliance clause missing",
    missing_description: "No state / local lobbying compliance clause was found.",
    explanation:
      "State lobbying laws vary widely (NY, CA, IL have aggressive registration / contribution-reporting + revolving-door rules). Multi-state lobbyists need a 50-state matrix.",
    recommendation:
      "Add 'State and Local Lobbying' requiring registration and reporting in each applicable state / locality.",
    present_patterns: [
      /(state\s+(lobbying|registration)|local\s+(lobbying|registration))/i,
      /(register|reporting|jepi)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "POL-050",
    name: "Gifts to government officials — strict prohibitions",
    description:
      "Policy must prohibit / strictly limit gifts to government officials (federal + state ethics codes).",
    citation: polPractice(
      "gov-gifts",
      "Federal gift rules (5 C.F.R. § 2635) + state ethics-code gift bans",
      "https://www.law.cornell.edu/cfr/text/5/2635",
    ),
    playbooks: [POL_PLAYBOOK_LOBBYING],
    missing_title: "Gifts to government officials clause missing",
    missing_description:
      "No clause was found prohibiting / limiting gifts to government officials.",
    explanation:
      "Federal employees: 5 C.F.R. § 2635 limits gifts to $20 / occasion + $50 / source / year (with many exceptions). Many states are stricter; some bar all gifts.",
    recommendation:
      "Add 'Gifts to Government Officials' specifying strict limits and pre-approval requirement; default to the stricter of federal / state / local rules.",
    present_patterns: [
      /(gifts?\s+to\s+(government\s+)?officials?|gift\s+rules?)/i,
      /(\$20|\$50|federal\s+gift\s+rules|5\s+c\.?f\.?r\.?\s+§?\s*2635|state\s+ethics)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate. 50 rules total.
// ────────────────────────────────────────────────────────────────────

export const COMPLIANCE_POLICY_RULES: Rule[] = [
  ...CODE_OF_CONDUCT_RULES,
  ...FCPA_RULES,
  ...AML_RULES,
  ...INSIDER_TRADING_RULES,
  ...WHISTLEBLOWER_RULES,
  ...DOC_RETENTION_RULES,
  ...COI_POLICY_RULES,
  ...AI_AUP_RULES,
  ...SOCIAL_MEDIA_POLICY_RULES,
  ...LOBBYING_POLICY_RULES,
];

export {
  CODE_OF_CONDUCT_RULES,
  FCPA_RULES,
  AML_RULES,
  INSIDER_TRADING_RULES,
  WHISTLEBLOWER_RULES,
  DOC_RETENTION_RULES,
  COI_POLICY_RULES,
  AI_AUP_RULES,
  SOCIAL_MEDIA_POLICY_RULES,
  LOBBYING_POLICY_RULES,
};
