/**
 * v4 IP and licensing (expanded) ruleset — 40 rules
 * (spec-v4.md §6.H, Step 51).
 *
 * Seven new playbooks: IP assignment, patent license, trademark license,
 * copyright license, OSS contributor license agreement (CLA), OSS
 * compliance audit document, and work-for-hire agreement. H.5 (software
 * EULA) continues under v3 `eula` and is not duplicated here.
 *
 * Citations anchor to 35 U.S.C. (patent), 17 U.S.C. (copyright), the
 * Lanham Act (trademark), 18 U.S.C. § 1833(b) (DTSA notice), the
 * *Brulotte / Kimble* line, the Developer Certificate of Origin,
 * Apache ICLA, and OSI-approved license families.
 *
 * Rule ids are flat `IPL-NNN` (001..040); each rule's
 * `applies_to_playbooks` restricts execution.
 */

import type { Rule } from "../../../finding.js";
import {
  buildV4PresenceRule,
  buildV4LanguageRule,
  type V4PresenceSpec,
  type V4LanguageSpec,
} from "../_helpers.js";
import {
  IPL_PLAYBOOK_ASSIGNMENT,
  IPL_PLAYBOOK_PATENT,
  IPL_PLAYBOOK_TRADEMARK,
  IPL_PLAYBOOK_COPYRIGHT,
  IPL_PLAYBOOK_CLA,
  IPL_PLAYBOOK_OSS_COMPLIANCE,
  IPL_PLAYBOOK_WFH,
  patentAct,
  copyrightAct,
  lanham,
  dtsa,
  brulotteKimble,
  osiLicense,
  dco,
  apacheCla,
  gpl,
  permissiveOss,
  iplPractice,
} from "./_helpers.js";

const CATEGORY = "ip-licensing";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });
const language = (s: Omit<V4LanguageSpec, "category">): Rule =>
  buildV4LanguageRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// H.1 — IP Assignment Agreement. 6 rules: IPL-001..IPL-006.
// ────────────────────────────────────────────────────────────────────

const IP_ASSIGNMENT_RULES: Rule[] = [
  presence({
    id: "IPL-001",
    name: "Assignor / assignee identified",
    description: "IP assignment must identify assignor and assignee with full legal names.",
    citation: iplPractice(
      "assignment-parties",
      "IP assignment — parties baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [IPL_PLAYBOOK_ASSIGNMENT],
    missing_title: "Assignor / assignee identification missing",
    missing_description: "No clause identifying the assignor and assignee was found.",
    explanation:
      "An assignment is only effective as to identified parties. Recordation at the USPTO / Copyright Office requires identification.",
    recommendation:
      "Identify the assignor and assignee with full legal names, jurisdictions of formation, and addresses.",
    present_patterns: [/(assignor|assignee)/i, /(party|parties)/i],
  }),
  presence({
    id: "IPL-002",
    name: "Assigned IP described with specificity",
    description:
      "IP assignment must describe the assigned IP with sufficient specificity (patent / app numbers, registration numbers, work titles).",
    citation: iplPractice(
      "assignment-scope",
      "IP assignment — scope of assigned IP baseline",
      "https://www.uspto.gov/learning-and-resources/general-faqs/general-information-concerning-patents",
    ),
    playbooks: [IPL_PLAYBOOK_ASSIGNMENT],
    missing_title: "Assigned-IP scope clause missing",
    missing_description:
      "No clause was found describing the assigned IP with sufficient specificity.",
    explanation:
      "Vague assignments ('all intellectual property') invite later disputes about which assets transferred and are difficult to record.",
    recommendation:
      "Add 'Assigned IP' enumerating patent / application numbers, registration numbers, copyrighted work titles, and any common-law rights.",
    present_patterns: [
      /(patent\s+no|application\s+no|reg\.?\s*no|registration\s+number|schedule\s+a)/i,
      /(patent|trademark|copyright|trade\s+secret)/i,
    ],
  }),
  presence({
    id: "IPL-003",
    name: "Assignment of right to sue for past infringement",
    description:
      "Assignment should expressly include the right to sue for past, present, and future infringement.",
    citation: patentAct("261", "Patent assignment"),
    playbooks: [IPL_PLAYBOOK_ASSIGNMENT],
    missing_title: "Right-to-sue-for-past-infringement clause missing",
    missing_description:
      "No clause was found expressly assigning the right to sue for past infringement.",
    explanation:
      "Under *Crown Die & Tool* and *Arachnid v. Merit Industries*, the right to sue for past infringement does not automatically pass with an assignment unless expressly conveyed.",
    recommendation:
      "Add 'Right to Sue' assigning all causes of action for past, present, and future infringement, plus the right to all damages and remedies.",
    present_patterns: [
      /(right\s+to\s+sue|causes?\s+of\s+action)/i,
      /(past|present|future)\s+infring/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "IPL-004",
    name: "Recordation cooperation — 35 U.S.C. § 261 / 17 U.S.C. § 205",
    description:
      "Assignment should require assignor to cooperate with recordation at the USPTO / Copyright Office.",
    citation: patentAct("261", "Assignment recordation"),
    playbooks: [IPL_PLAYBOOK_ASSIGNMENT],
    missing_title: "Recordation-cooperation clause missing",
    missing_description: "No clause requiring cooperation with recordation was found.",
    explanation:
      "35 U.S.C. § 261 voids an unrecorded assignment as against a subsequent bona-fide purchaser without notice within 3 months; 17 U.S.C. § 205 provides priority on recordation. Cooperation language ensures recordation can be perfected.",
    recommendation:
      "Add 'Further Assurances' / 'Recordation' requiring assignor to execute documents and provide reasonable cooperation to record the assignment.",
    present_patterns: [
      /(further\s+assurances?|cooperat)/i,
      /(record(ation|ing)?|uspto|copyright\s+office)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "IPL-005",
    name: "Power of attorney for IP-office filings",
    description:
      "Assignment should grant a power of attorney to enable the assignee to file in the IP offices.",
    citation: iplPractice(
      "assignment-poa",
      "IP assignment — POA baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [IPL_PLAYBOOK_ASSIGNMENT],
    missing_title: "POA clause missing",
    missing_description: "No power-of-attorney clause was found in the assignment.",
    explanation:
      "Without a POA the assignee cannot independently file recordation, prosecute, or maintain transferred IP — every action requires reaching assignor for execution.",
    recommendation:
      "Add 'Power of Attorney' authorizing assignee (and its counsel) to execute and file documents necessary to record, maintain, prosecute, or enforce the assigned IP.",
    present_patterns: [
      /power\s+of\s+attorney/i,
      /(authoriz(e|es|ed)|appoint(s|ed)?).{0,40}(assignee|attorney.in.fact)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "IPL-006",
    name: "Assignor reps — ownership, no encumbrances, no prior conveyance",
    description:
      "Assignment must include assignor reps as to ownership and absence of encumbrances.",
    citation: iplPractice(
      "assignment-reps",
      "IP assignment — assignor reps baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [IPL_PLAYBOOK_ASSIGNMENT],
    missing_title: "Assignor representations clause missing",
    missing_description:
      "No clause was found stating assignor's representations as to ownership / encumbrances.",
    explanation:
      "Assignee needs (at minimum) reps that assignor owns the IP, has not previously conveyed it, and that no liens / encumbrances exist.",
    recommendation:
      "Add 'Representations and Warranties' covering ownership, no prior conveyance, and absence of liens / security interests / licenses.",
    present_patterns: [
      /(representations?\s+(and|&)\s+warranties|reps?\s+and\s+warranties)/i,
      /(own(s|ership)|no\s+prior\s+(conveyance|assignment))/i,
      /(encumbrance|lien|security\s+interest)/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// H.2 — Patent License Agreement. 6 rules: IPL-007..IPL-012.
// ────────────────────────────────────────────────────────────────────

const PATENT_LICENSE_RULES: Rule[] = [
  presence({
    id: "IPL-007",
    name: "Licensed patents identified by number",
    description: "Patent license must identify Licensed Patents by patent / application number.",
    citation: patentAct("261", "Patent license"),
    playbooks: [IPL_PLAYBOOK_PATENT],
    missing_title: "Licensed Patents identification clause missing",
    missing_description:
      "No clause was found identifying Licensed Patents by patent / application number.",
    explanation:
      "Patent licenses must identify the licensed claims with sufficient specificity for both enforcement and royalty accounting.",
    recommendation:
      "Add 'Licensed Patents' (or Schedule A) listing patent / application numbers, jurisdictions, and any continuations / divisionals.",
    present_patterns: [
      /(licensed\s+patents?|schedule\s+a)/i,
      /(patent\s+no|u\.?s\.?\s+pat|application\s+no)/i,
    ],
  }),
  presence({
    id: "IPL-008",
    name: "License grant scope — exclusivity, field, territory, sublicensing",
    description:
      "Patent license grant must specify exclusivity, field of use, territory, and sublicensing rights.",
    citation: patentAct("271", "Patent infringement / scope"),
    playbooks: [IPL_PLAYBOOK_PATENT],
    missing_title: "License-grant scope clause missing",
    missing_description:
      "No clause was found specifying exclusivity, field of use, territory, and sublicensing rights.",
    explanation:
      "These four parameters define the scope of the license; ambiguity invites *Brulotte* / *Kimble*-style misuse arguments or licensor / licensee scope disputes.",
    recommendation:
      "Add 'License Grant' specifying exclusive vs non-exclusive, field of use, territory (e.g., worldwide / US), and sublicensing right (with or without consent).",
    present_patterns: [
      /(exclusive|non.?exclusive|sole)/i,
      /(field\s+of\s+use|territor)/i,
      /sub.?licens/i,
    ],
  }),
  language({
    id: "IPL-009",
    name: "Brulotte / Kimble — royalties beyond patent expiration",
    description:
      "Royalty obligations that extend beyond patent expiration violate the *Brulotte / Kimble* rule absent a step-down or unbundling.",
    citation: brulotteKimble(),
    playbooks: [IPL_PLAYBOOK_PATENT],
    bad_patterns: [
      /royalt(y|ies).{0,200}(after|beyond|notwithstanding).{0,80}(expiration|expir|term\s+of\s+the\s+patent)/is,
      /(perpetual|indefinite|in\s+perpetuity).{0,80}royalt/is,
    ],
    bad_title: "Royalty obligation potentially extends beyond patent expiration",
    bad_description:
      "Royalty language appears to require payment past patent expiration without a Brulotte-compliant step-down or unbundled consideration.",
    explanation:
      "*Brulotte v. Thys* (379 U.S. 29) prohibits royalties accruing after patent expiration; *Kimble v. Marvel* (576 U.S. 446) reaffirmed. Workarounds: step-down at expiration, hybrid know-how / trade-secret royalty, or amortized lump-sum.",
    recommendation:
      "Add a step-down at patent expiration, allocate a portion of royalty to know-how / trade-secret rights with separate accrual, or structure as a lump-sum amortized payment.",
    default_severity: "warning",
  }),
  presence({
    id: "IPL-010",
    name: "Royalty rate, base, audit",
    description: "Patent license must state royalty rate, base, payment timing, and audit right.",
    citation: iplPractice(
      "patent-royalty",
      "Patent license — royalty mechanics baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [IPL_PLAYBOOK_PATENT],
    missing_title: "Royalty / payment / audit clause missing",
    missing_description: "No royalty / payment / audit clause was found.",
    explanation:
      "Royalty disputes are the most common source of patent-license litigation; the rate, base ('Net Sales'), reporting, and audit right are universal in modern agreements.",
    recommendation:
      "Add 'Royalties' specifying rate (e.g., X% of Net Sales), Net Sales definition, payment schedule (quarterly), reporting (royalty statement), and audit right (annual, kept-records retention).",
    present_patterns: [
      /(royalt(y|ies)|payment)/i,
      /(net\s+sales|gross\s+sales|revenue)/i,
      /audit/i,
    ],
  }),
  presence({
    id: "IPL-011",
    name: "Patent marking obligation — 35 U.S.C. § 287",
    description:
      "Licensee should be required to mark licensed products with patent number(s) per 35 U.S.C. § 287 to preserve damages.",
    citation: patentAct("287", "Patent marking"),
    playbooks: [IPL_PLAYBOOK_PATENT],
    missing_title: "Patent-marking clause missing",
    missing_description: "No clause was found requiring patent marking.",
    explanation:
      "35 U.S.C. § 287 limits patentee's pre-notice damages unless products are marked. Licensor needs marking compliance from licensee to preserve damages against third-party infringers.",
    recommendation:
      "Add 'Patent Marking' requiring licensee to mark Licensed Products with applicable patent numbers (or 'Patent Pending' / virtual marking per § 287(a)).",
    present_patterns: [
      /(patent\s+marking|mark.{0,40}with\s+(the\s+)?patent\s+number)/i,
      /(35\s+u\.?s\.?c\.?\s+§?\s*287|section\s+287)/i,
      /virtual\s+marking/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "IPL-012",
    name: "Improvements / grant-back",
    description:
      "Patent license should address whether improvements made by licensee are licensed back.",
    citation: iplPractice(
      "patent-improvements",
      "Patent license — improvements / grant-back baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [IPL_PLAYBOOK_PATENT],
    missing_title: "Improvements / grant-back clause missing",
    missing_description: "No clause addressing improvements / grant-back was found.",
    explanation:
      "Improvements made by licensee can be a valuable side-channel. Antitrust concerns require careful drafting: non-exclusive royalty-free grant-back is generally permissible; exclusive grant-back raises misuse concerns under DOJ / FTC IP guidelines.",
    recommendation:
      "Add 'Improvements' addressing ownership of improvements and grant-back (non-exclusive, royalty-free is the common safe-harbor).",
    present_patterns: [/(improvements?|enhancements?|derivative\s+works?)/i, /grant.?back/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// H.3 — Trademark License Agreement. 6 rules: IPL-013..IPL-018.
// ────────────────────────────────────────────────────────────────────

const TM_LICENSE_RULES: Rule[] = [
  presence({
    id: "IPL-013",
    name: "Licensed marks identified",
    description: "Trademark license must identify Licensed Marks (with registration numbers).",
    citation: lanham("5", "Trademark license"),
    playbooks: [IPL_PLAYBOOK_TRADEMARK],
    missing_title: "Licensed Marks identification clause missing",
    missing_description: "No clause identifying the Licensed Marks (with reg. numbers) was found.",
    explanation:
      "Trademark licenses must identify the Licensed Marks by name and (where registered) by registration number; common-law marks should specify the goods / services and territory of use.",
    recommendation:
      "Add 'Licensed Marks' or Schedule A listing each mark, its registration number (or pending application), and the goods / services covered.",
    present_patterns: [
      /(licensed\s+marks?|schedule\s+a|the\s+marks?)/i,
      /(reg\.?\s*no|registration\s+number|u\.?s\.?\s+ser\.?\s+no)/i,
    ],
  }),
  presence({
    id: "IPL-014",
    name: "Quality control — naked-license avoidance",
    description:
      "Trademark license must impose quality-control obligations on licensee to avoid 'naked license' abandonment.",
    citation: lanham("5", "Quality control / naked license"),
    playbooks: [IPL_PLAYBOOK_TRADEMARK],
    missing_title: "Quality-control clause missing",
    missing_description: "No quality-control clause was found.",
    explanation:
      "A trademark license without meaningful quality control is a 'naked license' that can result in abandonment (*Stanfield v. Osborne Industries*; *Eva's Bridal Ltd. v. Halanick Enterprises*). Licensor must reserve and exercise quality control.",
    recommendation:
      "Add 'Quality Control' requiring compliance with Quality Standards (attached or referenced), inspection / sample-submission rights, and remedies for non-compliance.",
    present_patterns: [
      /quality\s+(control|standards?)/i,
      /(inspect|sample|approval)/i,
      /(specifications?|guidelines?)/i,
    ],
  }),
  presence({
    id: "IPL-015",
    name: "Goodwill assignment to licensor / no challenge",
    description:
      "Trademark license should provide that all use inures to licensor's benefit and licensee will not challenge the marks.",
    citation: lanham("32", "Goodwill / no-challenge"),
    playbooks: [IPL_PLAYBOOK_TRADEMARK],
    missing_title: "Goodwill / no-challenge clause missing",
    missing_description:
      "No clause stating use inures to licensor's benefit and barring licensee challenge was found.",
    explanation:
      "Without an inures-to-benefit clause and a no-challenge clause, licensee can build independent rights or later challenge the mark. Note: some jurisdictions limit enforceability of no-challenge clauses; pair with covenants to assist registration.",
    recommendation:
      "Add 'Goodwill' clause stating all use inures to licensor and 'No Challenge' clause barring licensee from challenging validity / ownership.",
    present_patterns: [
      /(inures?|inuring).{0,40}(licensor|owner)/i,
      /(no.?challenge|will\s+not\s+challenge)/i,
      /goodwill/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "IPL-016",
    name: "Proper use guidelines (® / ™ / SM)",
    description:
      "Trademark license must specify proper-use rules (capitalization, ® / ™ markers, adjective use, no genericization).",
    citation: lanham("45", "Proper use / genericization"),
    playbooks: [IPL_PLAYBOOK_TRADEMARK],
    missing_title: "Proper-use guidelines clause missing",
    missing_description: "No proper-use / marking guidelines clause was found.",
    explanation:
      "Misuse (verb / generic use, missing ® / ™) hastens genericization (e.g., aspirin, escalator). Licensor must require proper use to preserve the mark.",
    recommendation:
      "Add 'Proper Use' specifying use as an adjective, prohibition on verb / pluralized / possessive use, mandatory ® or ™ markers, and capitalization rules.",
    present_patterns: [
      /(proper\s+use|use\s+guidelines)/i,
      /(®|™|\(R\)|\(TM\)|registered\s+trademark)/i,
      /(adjective|capitaliz|generic)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "IPL-017",
    name: "Territory / channels / field of use",
    description: "Trademark license must define territory, channels, and field of use.",
    citation: iplPractice(
      "tm-scope",
      "Trademark license — scope baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [IPL_PLAYBOOK_TRADEMARK],
    missing_title: "Territory / channels / field clause missing",
    missing_description:
      "No clause was found defining territory, channels of trade, or field of use.",
    explanation:
      "Scope ambiguity is the most common trademark-license dispute. Define geographic territory, channels of trade (retail, wholesale, e-commerce), and field of use (goods / services).",
    recommendation:
      "Add 'License Scope' specifying Territory, Channels of Trade, and Field of Use; identify any reserved channels / fields.",
    present_patterns: [
      /(territor|channels?\s+of\s+trade|field\s+of\s+use)/i,
      /(licensed\s+goods?|licensed\s+services?)/i,
    ],
  }),
  presence({
    id: "IPL-018",
    name: "Termination — quality / non-payment / change-of-control",
    description:
      "Trademark license must include termination rights tied to quality breach / non-payment / CoC.",
    citation: iplPractice(
      "tm-termination",
      "Trademark license — termination baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [IPL_PLAYBOOK_TRADEMARK],
    missing_title: "Termination clause missing",
    missing_description: "No termination clause was found in the trademark license.",
    explanation:
      "Quality-breach and non-payment termination protect the mark; change-of-control / insolvency termination protect licensor against an unwanted licensee. Sell-off / phase-out periods address remaining inventory.",
    recommendation:
      "Add 'Termination' covering quality breach (after cure), non-payment, change of control, and insolvency; include a 90-day sell-off period for existing inventory.",
    present_patterns: [
      /termination/i,
      /(non.?payment|change\s+of\s+control|insolvenc|sell.?off|phase.?out)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// H.4 — Copyright License Agreement. 6 rules: IPL-019..IPL-024.
// ────────────────────────────────────────────────────────────────────

const COPYRIGHT_LICENSE_RULES: Rule[] = [
  presence({
    id: "IPL-019",
    name: "Licensed Works identified",
    description:
      "Copyright license must identify Licensed Works (titles, registration numbers, deposit info).",
    citation: copyrightAct("201", "Copyright ownership / transfers"),
    playbooks: [IPL_PLAYBOOK_COPYRIGHT],
    missing_title: "Licensed Works clause missing",
    missing_description: "No clause was found identifying the Licensed Works.",
    explanation:
      "Copyright licenses must identify the licensed works with sufficient specificity. Registration numbers (where available) support recordation and statutory-damages availability.",
    recommendation:
      "Add 'Licensed Works' (or Schedule A) listing each work, its registration number (if any), and the medium / format covered.",
    present_patterns: [
      /(licensed\s+works?|copyrighted\s+works?|schedule\s+a)/i,
      /(reg\.?\s*no|registration\s+number|tx|va|pa|sr)\s*\d/i,
    ],
  }),
  presence({
    id: "IPL-020",
    name: "Exclusive vs non-exclusive + signed writing for exclusive grants",
    description:
      "Copyright license must state exclusivity; exclusive grants must satisfy 17 U.S.C. § 204(a) (signed writing).",
    citation: copyrightAct("204", "Execution of transfers"),
    playbooks: [IPL_PLAYBOOK_COPYRIGHT],
    missing_title: "Exclusivity / § 204 writing clause missing",
    missing_description: "No clause stating exclusivity or satisfying § 204(a) was found.",
    explanation:
      "Under 17 U.S.C. § 204(a), exclusive copyright transfers must be in writing signed by the owner; non-exclusive licenses can be oral or implied. Clarity prevents *Effects Associates v. Cohen*-style disputes.",
    recommendation:
      "Add 'Grant of Rights' stating exclusive vs non-exclusive; for exclusive grants, ensure a signed writing per § 204(a).",
    present_patterns: [/(exclusive|non.?exclusive|sole)/i, /(in\s+writing|signed|executed)/i],
  }),
  presence({
    id: "IPL-021",
    name: "Rights granted — reproduction / distribution / display / performance / derivative",
    description: "Copyright license must specify which 17 U.S.C. § 106 rights are granted.",
    citation: copyrightAct("106", "Exclusive rights"),
    playbooks: [IPL_PLAYBOOK_COPYRIGHT],
    missing_title: "§ 106 rights grant clause missing",
    missing_description:
      "No clause specifying which § 106 rights are granted (reproduction / distribution / display / performance / derivative) was found.",
    explanation:
      "17 U.S.C. § 106 enumerates six exclusive rights. A license should explicitly state which are granted; silence creates ambiguity (e.g., does a license to reproduce include a derivative-work right?).",
    recommendation:
      "Add 'Rights Granted' enumerating which of reproduction, distribution, public display, public performance, and preparation of derivative works are licensed.",
    present_patterns: [
      /(reproduc|copy|distribut|display|perform|derivative\s+works?)/i,
      /(section\s+106|17\s+u\.?s\.?c\.?\s+§?\s*106)/i,
    ],
  }),
  presence({
    id: "IPL-022",
    name: "Term, territory, media / channels",
    description: "Copyright license must specify term, territory, and media / channels of use.",
    citation: iplPractice(
      "copyright-scope",
      "Copyright license — scope baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [IPL_PLAYBOOK_COPYRIGHT],
    missing_title: "Term / territory / media clause missing",
    missing_description: "No clause was found specifying term, territory, and media of use.",
    explanation:
      "These three parameters define the boundary of the license. Open-ended grants in unfamiliar media invite *Bourne v. Walt Disney*-style disputes when new media emerge.",
    recommendation:
      "Add 'License Scope' specifying Term, Territory, and Media (with explicit treatment of 'now known or hereafter developed').",
    present_patterns: [
      /(term|territor)/i,
      /(media|channels?|format)/i,
      /(now\s+known|hereafter\s+developed)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "IPL-023",
    name: "Attribution / credit / moral rights",
    description: "Copyright license should address attribution and moral-rights treatment.",
    citation: copyrightAct("106A", "VARA moral rights"),
    playbooks: [IPL_PLAYBOOK_COPYRIGHT],
    missing_title: "Attribution / moral-rights clause missing",
    missing_description: "No attribution or moral-rights clause was found.",
    explanation:
      "17 U.S.C. § 106A (VARA) grants moral rights for visual works; many foreign jurisdictions recognize broader moral rights. Attribution requirements and moral-rights waivers (where waivable) should be addressed explicitly.",
    recommendation:
      "Add 'Attribution' specifying credit / byline conventions and addressing moral rights (waiver / non-assertion where waivable).",
    present_patterns: [/(attribution|credit|byline)/i, /(moral\s+rights?|droit\s+moral|vara)/i],
    default_severity: "warning",
  }),
  presence({
    id: "IPL-024",
    name: "Termination of transfers — 17 U.S.C. § 203 caveat",
    description:
      "Copyright license should acknowledge the § 203 termination-of-transfers right (35–40 year window).",
    citation: copyrightAct("203", "Termination of transfers"),
    playbooks: [IPL_PLAYBOOK_COPYRIGHT],
    missing_title: "§ 203 termination-of-transfers caveat missing",
    missing_description: "No clause acknowledging the § 203 termination right was found.",
    explanation:
      "17 U.S.C. § 203 permits authors (or heirs) to terminate post-1977 transfers / licenses 35–40 years after grant, regardless of contrary contract terms. Sophisticated agreements acknowledge this and address pre-termination consequences.",
    recommendation:
      "Add 'Statutory Termination' acknowledging § 203 and addressing notice / pre-termination consequences (e.g., derivative works prepared before termination may continue under the original grant per § 203(b)(1)).",
    present_patterns: [
      /(section\s+203|17\s+u\.?s\.?c\.?\s+§?\s*203)/i,
      /termination\s+of\s+(transfers?|grants?)/i,
      /(35|thirty.five|forty)\s+years?/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// H.6 — OSS Contributor License Agreement (CLA). 5 rules: IPL-025..IPL-029.
// ────────────────────────────────────────────────────────────────────

const CLA_RULES: Rule[] = [
  presence({
    id: "IPL-025",
    name: "Contributor identification + entity / individual disambiguation",
    description:
      "CLA must identify the contributor and disambiguate individual vs entity contribution.",
    citation: apacheCla(),
    playbooks: [IPL_PLAYBOOK_CLA],
    missing_title: "Contributor identification clause missing",
    missing_description:
      "No clause was found identifying the contributor or distinguishing individual / entity contributions.",
    explanation:
      "ASF ICLA / corporate CLA distinguish individuals from corporate contributors because corporations need authority recitals and employer carve-outs.",
    recommendation:
      "Add 'Contributor' / 'You' definition with disambiguation between individual ICLA and corporate CCLA.",
    present_patterns: [/(contributor|you|i\b)/i, /(individual|corporat(e|ion)|entity|employer)/i],
  }),
  presence({
    id: "IPL-026",
    name: "Copyright license grant to project",
    description:
      "CLA must grant a copyright license sufficient for the project to use, modify, and redistribute.",
    citation: apacheCla(),
    playbooks: [IPL_PLAYBOOK_CLA],
    missing_title: "Copyright license grant clause missing",
    missing_description: "No clause was found granting the copyright license to the project.",
    explanation:
      "Without a copyright license grant, the project lacks the rights to redistribute the contribution under the project's outbound license (e.g., Apache 2 / MIT).",
    recommendation:
      "Add 'Copyright License Grant' (ASF ICLA § 2) — perpetual, worldwide, non-exclusive, royalty-free copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute.",
    present_patterns: [
      /(copyright\s+license|grant.{0,40}copyright)/i,
      /(perpetual|worldwide|royalty.?free|irrevocable)/i,
    ],
  }),
  presence({
    id: "IPL-027",
    name: "Patent license grant + defensive termination",
    description: "CLA must grant a patent license and include defensive termination.",
    citation: apacheCla(),
    playbooks: [IPL_PLAYBOOK_CLA],
    missing_title: "Patent license / defensive termination clause missing",
    missing_description:
      "No clause was found granting a patent license or providing defensive termination.",
    explanation:
      "ASF ICLA § 3 grants a patent license; defensive termination terminates the patent license if recipient sues for patent infringement. This is the OSS counterpart to MAD / patent peace.",
    recommendation:
      "Add 'Patent License Grant' (ASF ICLA § 3) — perpetual, worldwide, non-exclusive, royalty-free patent license; include defensive termination terminating the patent grant upon patent-litigation initiation.",
    present_patterns: [
      /patent\s+(license|grant)/i,
      /(defensive\s+termination|patent\s+litigation|countersuit)/i,
    ],
  }),
  presence({
    id: "IPL-028",
    name: "Original-work representation",
    description:
      "Contributor must represent that the contribution is their original work or properly licensed.",
    citation: apacheCla(),
    playbooks: [IPL_PLAYBOOK_CLA],
    missing_title: "Original-work representation clause missing",
    missing_description: "No representation that the contribution is original was found.",
    explanation:
      "ASF ICLA § 5 requires that each contribution be the contributor's original creation; otherwise the contributor must specify third-party rights and submit the contribution properly.",
    recommendation:
      "Add a 'Representations' clause stating the contribution is original (or properly licensed third-party material with appropriate notices).",
    present_patterns: [
      /(original\s+(creation|work)|created.{0,40}by\s+(you|the\s+contributor))/i,
      /(third.?party|right\s+(to|to\s+grant))/i,
    ],
  }),
  presence({
    id: "IPL-029",
    name: "DCO alternative path (sign-off)",
    description:
      "Projects following the DCO model should accept signed-off-by per the Developer Certificate of Origin 1.1.",
    citation: dco(),
    playbooks: [IPL_PLAYBOOK_CLA],
    missing_title: "DCO sign-off acknowledgment clause missing",
    missing_description: "No clause was found addressing the DCO 1.1 sign-off alternative.",
    explanation:
      "Many OSS projects use DCO sign-off (e.g., Linux kernel) instead of a per-contributor CLA. Documents that intermix CLA and DCO should specify which path applies.",
    recommendation:
      "Add 'DCO Alternative' (if applicable) referencing the Developer Certificate of Origin 1.1 sign-off mechanism, or clarify that only the CLA applies.",
    present_patterns: [
      /(dco|developer\s+certificate\s+of\s+origin)/i,
      /(signed.?off.?by|sign.?off)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// H.7 — OSS Compliance Audit Document. 6 rules: IPL-030..IPL-035.
// ────────────────────────────────────────────────────────────────────

const OSS_COMPLIANCE_RULES: Rule[] = [
  presence({
    id: "IPL-030",
    name: "Third-party / open-source software inventory",
    description: "OSS compliance document must inventory third-party / open-source components.",
    citation: permissiveOss(),
    playbooks: [IPL_PLAYBOOK_OSS_COMPLIANCE],
    missing_title: "OSS inventory clause missing",
    missing_description: "No third-party / OSS inventory was found.",
    explanation:
      "OSS compliance starts with knowing what is in the product. A bill of materials (SBOM, SPDX, CycloneDX) lists components, versions, and licenses.",
    recommendation:
      "Add a 'Third-Party Software' / SBOM section listing each component, its version, and its license; reference SPDX / CycloneDX format.",
    present_patterns: [
      /(third.?party\s+(software|components?)|open.?source|sbom|spdx|cyclonedx)/i,
      /(component|library|dependency)/i,
    ],
  }),
  presence({
    id: "IPL-031",
    name: "License enumeration per component",
    description:
      "Each component must have its license enumerated (e.g., MIT, Apache-2.0, GPL-3.0).",
    citation: osiLicense("license-list", "OSI-approved license list (SPDX identifiers)"),
    playbooks: [IPL_PLAYBOOK_OSS_COMPLIANCE],
    missing_title: "Per-component license enumeration missing",
    missing_description: "No per-component license enumeration was found.",
    explanation:
      "Compliance obligations differ per license family. Without per-component license identification, downstream notices and source-availability obligations cannot be determined.",
    recommendation:
      "Add a 'Licenses' column / sub-section using SPDX identifiers (e.g., MIT, Apache-2.0, GPL-3.0-only, AGPL-3.0-only, BSD-3-Clause).",
    present_patterns: [/(mit|apache.?2|bsd|gpl|agpl|lgpl|mpl|isc|cc.?by)/i, /(license|spdx)/i],
  }),
  presence({
    id: "IPL-032",
    name: "Copyleft (GPL / AGPL) obligations addressed",
    description:
      "If GPL / AGPL components are used, source-availability and notice obligations must be addressed.",
    citation: gpl(),
    playbooks: [IPL_PLAYBOOK_OSS_COMPLIANCE],
    missing_title: "Copyleft obligation handling missing",
    missing_description:
      "No clause was found addressing GPL / AGPL source-availability or notice obligations.",
    explanation:
      "GPL / LGPL / AGPL require that recipients of distributed binaries receive (or be offered) the corresponding source. AGPL extends this to network use. Failure to comply can result in license termination and copyright-infringement liability.",
    recommendation:
      "Add 'Copyleft Compliance' identifying GPL / LGPL / AGPL components, the source-availability mechanism (e.g., URL, written offer, accompanying source), and AGPL network-use treatment.",
    present_patterns: [
      /(source\s+(availability|disclosure)|corresponding\s+source)/i,
      /(written\s+offer|accompanying\s+source|gpl|agpl)/i,
      /(network\s+use|remote\s+interaction)/i,
    ],
  }),
  presence({
    id: "IPL-033",
    name: "Notice / attribution file generation",
    description:
      "Compliance document must address how attribution notices are generated and distributed.",
    citation: permissiveOss(),
    playbooks: [IPL_PLAYBOOK_OSS_COMPLIANCE],
    missing_title: "Notice / attribution generation clause missing",
    missing_description: "No clause was found addressing notice / attribution generation.",
    explanation:
      "MIT, Apache-2.0, and BSD all require notice / attribution preservation. Apache-2.0 § 4(d) requires a NOTICE file. Notice files are typically generated automatically from the SBOM.",
    recommendation:
      "Add 'Notices' describing how NOTICE / THIRD-PARTY-NOTICES files are generated and made available (in-product, in documentation, or at a URL).",
    present_patterns: [
      /(notices?\s+file|third.?party.?notices?|attribution\s+file)/i,
      /(notice|attribution)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "IPL-034",
    name: "Forbidden / discouraged-license list",
    description:
      "OSS compliance document should specify forbidden licenses (e.g., SSPL, BUSL non-OSI) or discouraged ones.",
    citation: osiLicense("license-policy", "Practitioner OSS-license policy baseline"),
    playbooks: [IPL_PLAYBOOK_OSS_COMPLIANCE],
    missing_title: "Forbidden / discouraged-license policy missing",
    missing_description: "No policy on forbidden / discouraged licenses was found.",
    explanation:
      "Source-available-but-not-OSI licenses (SSPL, BUSL, Commons Clause, ELv2) impose use restrictions that may not be compatible with downstream commercial use. A stated policy keeps the inventory clean.",
    recommendation:
      "Add 'Forbidden Licenses' listing licenses that may not be used (e.g., SSPL for hosted offering, Commons Clause, ELv2) and the approval path for exceptions.",
    present_patterns: [
      /(forbidden|prohibited|approved|discouraged).{0,40}(license|licenses)/is,
      /(sspl|busl|commons\s+clause|elastic\s+license|polyform)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "IPL-035",
    name: "Vulnerability / CVE tracking obligation",
    description:
      "OSS compliance documents should require CVE / vulnerability monitoring of inventoried components.",
    citation: iplPractice(
      "oss-vuln",
      "OSS compliance — vulnerability tracking baseline (CISA SBOM guidance)",
      "https://www.cisa.gov/sbom",
    ),
    playbooks: [IPL_PLAYBOOK_OSS_COMPLIANCE],
    missing_title: "Vulnerability / CVE tracking clause missing",
    missing_description:
      "No clause was found requiring CVE / vulnerability tracking of inventoried components.",
    explanation:
      "Modern OSS-compliance programs (NIST SSDF, EO 14028, CISA SBOM) require continuous monitoring for vulnerabilities in third-party components.",
    recommendation:
      "Add 'Vulnerability Monitoring' requiring continuous CVE / advisory tracking against the SBOM, with severity thresholds and patch-window SLAs.",
    present_patterns: [/(cve|vulnerability|advisor(y|ies))/i, /(monitor|track|patch)/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// H.8 — Work-for-Hire Agreement. 5 rules: IPL-036..IPL-040.
// ────────────────────────────────────────────────────────────────────

const WFH_RULES: Rule[] = [
  presence({
    id: "IPL-036",
    name: "§ 101 specially-commissioned-category recital",
    description:
      "Work-for-hire agreement must fall within one of the nine 17 U.S.C. § 101 categories for specially commissioned works.",
    citation: copyrightAct("101", "Work made for hire definition"),
    playbooks: [IPL_PLAYBOOK_WFH],
    missing_title: "§ 101 specially-commissioned recital missing",
    missing_description: "No clause was found reciting the § 101 work-for-hire category.",
    explanation:
      "Under 17 U.S.C. § 101, a non-employee work is 'made for hire' only if (a) the parties expressly agree in writing AND (b) the work falls into one of nine categories (contribution to a collective work, part of a motion picture or audiovisual work, translation, supplementary work, compilation, instructional text, test, answer material, atlas). Outside those categories, an assignment is required instead.",
    recommendation:
      "Recite the § 101 category (or, if none applies, restructure as an assignment) and include both a work-for-hire recital and a backup assignment.",
    present_patterns: [
      /(work\s+made\s+for\s+hire|work.?for.?hire|17\s+u\.?s\.?c\.?\s+§?\s*101|section\s+101)/i,
      /(motion\s+picture|audiovisual|collective\s+work|translation|supplementary|compilation|instructional\s+text|test|atlas)/i,
    ],
  }),
  presence({
    id: "IPL-037",
    name: "Backup assignment clause",
    description:
      "Work-for-hire agreement must include a backup assignment in case the work-for-hire designation fails.",
    citation: copyrightAct("204", "Backup assignment"),
    playbooks: [IPL_PLAYBOOK_WFH],
    missing_title: "Backup-assignment clause missing",
    missing_description: "No backup-assignment clause was found.",
    explanation:
      "Universal practice: include a 'to the extent any portion is not a work for hire, contractor hereby assigns' clause. Without it, a court that disagrees with the § 101 categorization leaves the work with the contractor.",
    recommendation:
      "Add 'Backup Assignment' assigning all right, title, and interest to client in the event any portion is not a work for hire.",
    present_patterns: [
      /(to\s+the\s+extent|in\s+the\s+event).{0,40}(not\s+a\s+work\s+for\s+hire|fails\s+to\s+qualify)/is,
      /(hereby\s+assigns?|assignment)/i,
    ],
  }),
  presence({
    id: "IPL-038",
    name: "DTSA / 18 U.S.C. § 1833(b) notice",
    description:
      "Work-for-hire agreements with confidentiality obligations must include the DTSA whistleblower notice.",
    citation: dtsa(),
    playbooks: [IPL_PLAYBOOK_WFH],
    missing_title: "DTSA whistleblower notice missing",
    missing_description:
      "No 18 U.S.C. § 1833(b) DTSA notice was found in the work-for-hire agreement.",
    explanation:
      "18 U.S.C. § 1833(b)(3) requires that, to preserve exemplary damages / attorney's fees under DTSA, employers and contractors include the immunity / whistleblower notice in any agreement governing the use of trade-secret information.",
    recommendation:
      "Add 'DTSA Notice' / 'Immunity' reciting that an individual will not be held criminally / civilly liable for disclosure of a trade secret made in confidence to a government official solely for the purpose of reporting or investigating a violation of law.",
    present_patterns: [
      /(18\s+u\.?s\.?c\.?\s+§?\s*1833|section\s+1833|defend\s+trade\s+secrets\s+act|dtsa)/i,
      /(immunity|whistleblower|reporting\s+a\s+violation)/i,
    ],
  }),
  presence({
    id: "IPL-039",
    name: "Moral-rights waiver (where waivable)",
    description:
      "Work-for-hire agreement should address moral rights for works subject to VARA / foreign moral-rights regimes.",
    citation: copyrightAct("106A", "VARA moral rights"),
    playbooks: [IPL_PLAYBOOK_WFH],
    missing_title: "Moral-rights waiver clause missing",
    missing_description: "No moral-rights waiver / non-assertion clause was found.",
    explanation:
      "VARA (17 U.S.C. § 106A) protects works of visual art; many foreign jurisdictions recognize broader moral rights (some non-waivable). Where waivable, an express waiver protects downstream modification / attribution decisions.",
    recommendation:
      "Add 'Moral Rights' waiving (where waivable) any moral / droit moral rights or covenant-not-to-assert.",
    present_patterns: [
      /(moral\s+rights?|droit\s+moral|vara)/i,
      /(waiv(e|er|ing|ed)|covenant\s+not\s+to\s+(assert|sue))/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "IPL-040",
    name: "Independent-contractor status + tax / benefits disclaimer",
    description:
      "Work-for-hire agreement (with non-employees) must recite independent-contractor status.",
    citation: iplPractice(
      "wfh-ic-status",
      "Work-for-hire — independent-contractor status baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [IPL_PLAYBOOK_WFH],
    missing_title: "Independent-contractor status clause missing",
    missing_description:
      "No clause was found reciting independent-contractor status / no-employee-benefits.",
    explanation:
      "Misclassification is the central risk of contractor engagements (IRS 20-factor / ABC test). A status recital + tax / benefits disclaimer documents the parties' intent.",
    recommendation:
      "Add 'Independent Contractor' stating contractor is not an employee, is responsible for taxes, and is not entitled to employee benefits.",
    present_patterns: [
      /(independent\s+contractor|not\s+an\s+employee)/i,
      /(taxes?|self.?employment)/i,
      /(benefits|employer)/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate. 40 rules total.
// ────────────────────────────────────────────────────────────────────

export const IP_LICENSING_RULES: Rule[] = [
  ...IP_ASSIGNMENT_RULES,
  ...PATENT_LICENSE_RULES,
  ...TM_LICENSE_RULES,
  ...COPYRIGHT_LICENSE_RULES,
  ...CLA_RULES,
  ...OSS_COMPLIANCE_RULES,
  ...WFH_RULES,
];

export {
  IP_ASSIGNMENT_RULES,
  PATENT_LICENSE_RULES,
  TM_LICENSE_RULES,
  COPYRIGHT_LICENSE_RULES,
  CLA_RULES,
  OSS_COMPLIANCE_RULES,
  WFH_RULES,
};
