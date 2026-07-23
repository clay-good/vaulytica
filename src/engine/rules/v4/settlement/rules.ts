/**
 * v4 Settlement / release / demand ruleset — 30 rules
 * (spec-v4.md §6.G, Step 50).
 *
 * Six new playbooks: mutual / general release, confidential settlement
 * agreement, demand letter, cease-and-desist letter, tolling agreement,
 * and litigation hold notice. Citations anchor to Cal. Civ. § 1542,
 * NLRB *McLaren Macomb*, SEC Rule 21F-17, FRE 408, FDCPA, Lanham Act
 * § 43(a), state statutes of limitations, PAGA notice, and FRCP 37(e) /
 * *Zubulake*.
 *
 * Rule ids are flat `SET-NNN` (001..030); each rule's
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
  SETTLE_PLAYBOOK_RELEASE,
  SETTLE_PLAYBOOK_SETTLEMENT,
  SETTLE_PLAYBOOK_DEMAND,
  SETTLE_PLAYBOOK_CD,
  SETTLE_PLAYBOOK_TOLLING,
  SETTLE_PLAYBOOK_LITHOLD,
  caCiv1542,
  mclarenMacomb,
  secRule21F17,
  frcp37e,
  zubulake,
  fdcpa,
  lanham43,
  stateLimitations,
  pagaNotice,
  fre408,
  settlePractice,
} from "./_helpers.js";

const CATEGORY = "settlement";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });
const language = (s: Omit<V4LanguageSpec, "category">): Rule =>
  buildV4LanguageRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// G.1 — Mutual / general release. 5 rules: SET-001..SET-005.
// ────────────────────────────────────────────────────────────────────

const RELEASE_RULES: Rule[] = [
  presence({
    id: "SET-001",
    name: "Releasing parties identified",
    description:
      "Release must identify the releasing parties (Releasor) and the released parties (Releasee), including affiliates / officers / agents.",
    citation: settlePractice(
      "release-parties",
      "General release — parties identification baseline",
      "https://www.americanbar.org/groups/litigation/",
    ),
    playbooks: [SETTLE_PLAYBOOK_RELEASE],
    missing_title: "Releasing / released parties clause missing",
    missing_description:
      "No clause was found identifying the releasing and released parties (with affiliates).",
    explanation:
      "An effective release must bind every entity intended to benefit. Failure to enumerate affiliates, officers, directors, agents, and assigns leaves residual claims against unnamed parties.",
    recommendation:
      "Add 'Parties' or 'Releasor / Releasee' clause enumerating each side plus 'and their respective parents, subsidiaries, affiliates, officers, directors, employees, agents, successors, and assigns'.",
    present_patterns: [
      /releas(or|ee|ing\s+part(y|ies)|ed\s+part(y|ies))/i,
      /(affiliates?|subsidiaries|officers|directors|agents)/i,
    ],
  }),
  presence({
    id: "SET-002",
    name: "Scope of released claims — broad release language",
    description:
      "Release must state the scope of claims released (known / unknown, past / present).",
    citation: settlePractice(
      "release-scope",
      "General release — scope of claims baseline",
      "https://www.americanbar.org/groups/litigation/",
    ),
    playbooks: [SETTLE_PLAYBOOK_RELEASE],
    missing_title: "Scope-of-release clause missing",
    missing_description:
      "No clause was found stating the scope of claims released (known / unknown / past).",
    explanation:
      "Without explicit scope language ('any and all claims, known or unknown, that have accrued or may accrue'), a court may construe the release narrowly.",
    recommendation:
      "Add 'Release of Claims' covering any and all claims, demands, causes of action, known or unknown, arising out of the dispute.",
    present_patterns: [
      /(any\s+and\s+all|each\s+and\s+every)\s+claims?/i,
      /(known\s+(or|and)\s+unknown|known\s+or\s+unknown)\s+claims?/i,
    ],
  }),
  presence({
    id: "SET-003",
    name: "California § 1542 waiver (if applicable)",
    description:
      "California releases of unknown claims require a specific § 1542 waiver with the statutory text.",
    citation: caCiv1542(),
    playbooks: [SETTLE_PLAYBOOK_RELEASE, SETTLE_PLAYBOOK_SETTLEMENT],
    missing_title: "California § 1542 waiver missing (if applicable)",
    missing_description: "No California Civil Code § 1542 waiver was found.",
    explanation:
      "Under Cal. Civ. § 1542, a general release does NOT extend to claims the releasor does not know or suspect to exist at the time, unless that protection is specifically waived.",
    recommendation:
      "If California law applies, add a § 1542 waiver quoting the statutory text and an express waiver.",
    present_patterns: [
      /section\s+1542/i,
      /(unknown\s+claims|do\s+not\s+know\s+or\s+suspect)/i,
      /(waiv(es?|e|ed|ing)).{0,40}(1542|known\s+or\s+unknown)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "SET-004",
    name: "No admission of liability",
    description:
      "Release should state that settlement is not an admission of liability or wrongdoing.",
    citation: fre408(),
    playbooks: [SETTLE_PLAYBOOK_RELEASE, SETTLE_PLAYBOOK_SETTLEMENT],
    missing_title: "No-admission clause missing",
    missing_description: "No clause stating settlement is not an admission of liability was found.",
    explanation:
      "FRE 408 makes settlement offers inadmissible to prove liability, but an explicit 'no-admission' recital reinforces the principle and helps with collateral disputes.",
    recommendation:
      "Add 'No Admission of Liability' recital — the settlement is a compromise of disputed claims, not an admission of fault.",
    present_patterns: [
      /no\s+admission\s+of\s+(liability|wrongdoing|fault)/i,
      /(compromise|disputed\s+claim)/i,
    ],
    default_severity: "warning",
  }),
  language({
    id: "SET-005",
    name: "Overbroad future-claims release flagged",
    description:
      "Releases that purport to cover future, post-execution claims may be unenforceable or limited by public policy (e.g., CA Civ. Code § 1668).",
    citation: settlePractice(
      "future-claims-policy",
      "Cal. Civ. Code § 1668 (release of future claims policy)",
      "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1668",
    ),
    playbooks: [SETTLE_PLAYBOOK_RELEASE],
    bad_patterns: [
      /releases?.{0,80}(future|hereafter\s+arising|may\s+arise).{0,80}claims?/is,
      /(future|prospective)\s+claims?.{0,80}(of\s+any\s+kind|whatsoever)/is,
    ],
    exclude_if: [
      /releases?\s+(?:does|do|shall|will)\s+not\s+(?:extend|apply|cover|include|reach)\b/i,
    ],
    bad_title: "Overbroad future-claims release flagged",
    bad_description:
      "The release appears to cover unaccrued / future claims; courts (including CA under § 1668) limit prospective releases.",
    explanation:
      "California § 1668 voids contracts that exempt a party from responsibility for their own fraud, willful injury, or violation of law. Many jurisdictions are skeptical of releases of unaccrued claims.",
    recommendation:
      "Limit the release to claims that have accrued through the Effective Date; remove blanket future-claims language.",
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// G.2 — Confidential settlement agreement. 5 rules: SET-006..SET-010.
// ────────────────────────────────────────────────────────────────────

const SETTLEMENT_AGREEMENT_RULES: Rule[] = [
  presence({
    id: "SET-006",
    name: "Settlement consideration stated",
    description: "Settlement agreement must state the consideration (payment amount, performance).",
    citation: settlePractice(
      "settlement-consideration",
      "Settlement agreement consideration baseline",
      "https://www.americanbar.org/groups/litigation/",
    ),
    playbooks: [SETTLE_PLAYBOOK_SETTLEMENT],
    missing_title: "Settlement consideration clause missing",
    missing_description: "No clause was found stating the consideration paid for the settlement.",
    explanation:
      "Without recited consideration, the agreement is vulnerable to a failure-of-consideration defense.",
    recommendation:
      "Add 'Consideration' or 'Settlement Payment' specifying the amount, currency, payee, and timing.",
    present_patterns: [
      /(settlement\s+payment|settlement\s+amount|settlement\s+sum)/i,
      /(consideration|in\s+consideration)/i,
      /\$\s*[\d,]+/,
    ],
  }),
  language({
    id: "SET-007",
    name: "Overbroad confidentiality / non-disparagement (NLRB scrutiny)",
    description:
      "NLRB *McLaren Macomb* found that overbroad confidentiality / non-disparagement provisions in settlements with non-supervisory employees violate NLRA § 7.",
    citation: mclarenMacomb(),
    playbooks: [SETTLE_PLAYBOOK_SETTLEMENT],
    bad_patterns: [
      /(employee|claimant|you)\s+shall\s+not\s+(disclose|disparage).{0,80}(any|all)\s+(person|individual|terms)/is,
      /confidentiality.{0,80}(terms\s+of\s+this\s+agreement|existence\s+of\s+this\s+settlement|any\s+aspect)/is,
      /non.?disparag.{0,200}(any|all)\s+(person|individual|entity)/is,
    ],
    exclude_if: [
      /(?:does|do|shall|will)\s+not\s+(?:restrict|prohibit|prevent|preclude|limit|bar|apply\s+to)\b/i,
      /\bnothing\b[^.]{0,60}(?:restrict|prohibit|prevent|preclude|limit|bar|interfere)/i,
    ],
    bad_title: "Overbroad confidentiality / non-disparagement flagged",
    bad_description:
      "Settlement appears to contain confidentiality or non-disparagement language broad enough to chill protected concerted activity (NLRA § 7).",
    explanation:
      "Under *McLaren Macomb*, settlement clauses that broadly restrict employees from discussing terms, disparaging the employer, or communicating about the dispute are unlawful as to covered employees.",
    recommendation:
      "Narrow with carve-outs for protected concerted activity, § 7 rights, agency communications (SEC / EEOC / NLRB / DOL), and disclosure of unlawful conduct.",
    default_severity: "warning",
  }),
  presence({
    id: "SET-008",
    name: "Whistleblower / agency-communication carve-out",
    description:
      "Confidential settlements must preserve the parties' right to communicate with regulators (SEC Rule 21F-17, EEOC, NLRB, DOL).",
    citation: secRule21F17(),
    playbooks: [SETTLE_PLAYBOOK_SETTLEMENT],
    missing_title: "Whistleblower / agency carve-out missing",
    missing_description: "No protected-rights / agency-communication carve-out was found.",
    explanation:
      "SEC Rule 21F-17 prohibits impeding whistleblower communications; EEOC / NLRB / DOL impose similar limits. Confidentiality must yield to these rights.",
    recommendation:
      "Add 'Protected Rights' carve-out preserving rights to communicate with the SEC, EEOC, NLRB, DOL, or any government agency and to retain any whistleblower bounty.",
    present_patterns: [
      /(protected\s+rights?|government\s+agency)/i,
      /(sec|eeoc|nlrb|dol)/i,
      /(whistleblower|whistle.?blower)/i,
    ],
  }),
  presence({
    id: "SET-009",
    name: "Tax allocation / IRS Form 1099 / W-2 treatment",
    description:
      "Settlement of employment / personal-injury / contract claims should allocate payment among taxable categories.",
    citation: settlePractice(
      "settlement-tax",
      "IRS Pub. 4345 — settlement and judgment tax treatment",
      "https://www.irs.gov/pub/irs-pdf/p4345.pdf",
    ),
    playbooks: [SETTLE_PLAYBOOK_SETTLEMENT],
    missing_title: "Tax allocation clause missing",
    missing_description: "No clause allocating the payment among taxable categories was found.",
    explanation:
      "IRC § 104(a)(2) excludes physical-injury damages from income; back wages are W-2; emotional-distress, attorney fees, and interest are typically 1099. Failure to allocate triggers IRS scrutiny and unfavorable default treatment.",
    recommendation:
      "Add 'Tax Treatment' allocating among physical-injury (§ 104), wages (W-2), non-wage (1099), attorney fees (1099-MISC / 1099-NEC), and interest.",
    present_patterns: [
      /(1099|w.?2|w2|form\s+1099|tax\s+(allocation|treatment))/i,
      /(internal\s+revenue\s+code|irc\s+§|section\s+104)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "SET-010",
    name: "Section 162(q) — Harvey Weinstein tax limitation (sexual harassment claims)",
    description:
      "IRC § 162(q) disallows deduction of settlements subject to nondisclosure for sexual harassment / abuse.",
    citation: settlePractice(
      "irc-162q",
      "IRC § 162(q) — no deduction for nondisclosure settlements (sexual harassment / abuse)",
      "https://www.law.cornell.edu/uscode/text/26/162",
    ),
    playbooks: [SETTLE_PLAYBOOK_SETTLEMENT],
    missing_title: "§ 162(q) recital missing (if applicable)",
    missing_description:
      "No IRC § 162(q) recital was found for a settlement that may involve sexual-harassment / abuse claims.",
    explanation:
      "If the settlement covers a sexual-harassment / abuse claim AND is subject to a nondisclosure, § 162(q) disallows the deduction for settlement payments + related attorney's fees.",
    recommendation:
      "If applicable, add a § 162(q) recital acknowledging that the payor will not deduct amounts covered by nondisclosure for sexual-harassment / abuse claims.",
    present_patterns: [
      /section\s+162.?q/i,
      /(harvey\s+weinstein|tcja|tax\s+cuts\s+and\s+jobs\s+act).{0,80}(harassment|abuse)/is,
      /no\s+deduction.{0,80}(harassment|abuse)/is,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// G.3 — Demand letter. 5 rules: SET-011..SET-015.
// ────────────────────────────────────────────────────────────────────

const DEMAND_LETTER_RULES: Rule[] = [
  presence({
    id: "SET-011",
    name: "Statement of facts and legal basis",
    description: "Demand letter must state the factual basis and the legal theory of the claim.",
    citation: settlePractice(
      "demand-letter-baseline",
      "Demand letter baseline content",
      "https://www.americanbar.org/groups/litigation/",
    ),
    playbooks: [SETTLE_PLAYBOOK_DEMAND],
    missing_title: "Statement-of-facts clause missing",
    missing_description:
      "No clause was found stating the factual basis and legal theory of the claim.",
    explanation:
      "Without specific facts and a legal theory, the recipient cannot meaningfully respond and the letter does not preserve the claim for pre-suit purposes.",
    recommendation:
      "Add a numbered statement of facts and a statement of the legal theory (e.g., breach of contract, fraud, statutory violation).",
    present_patterns: [
      /(facts?|background)/i,
      /(claim|cause\s+of\s+action|legal\s+theory|breach|fraud|statutor)/i,
    ],
  }),
  presence({
    id: "SET-012",
    name: "Specific demand and response deadline",
    description:
      "Demand letter must state the specific demand (amount / action) and a response deadline.",
    citation: settlePractice(
      "demand-deadline",
      "Demand letter — response-deadline baseline",
      "https://www.americanbar.org/groups/litigation/",
    ),
    playbooks: [SETTLE_PLAYBOOK_DEMAND],
    missing_title: "Specific demand / deadline clause missing",
    missing_description: "No specific demand or response-deadline clause was found.",
    explanation:
      "A demand letter without a specific demand or deadline is non-actionable. Many statutes (PAGA, CC&Rs, anti-SLAPP) impose minimum response windows.",
    recommendation:
      "State the specific relief sought (dollar amount, cure action) and a response deadline (typically 14–30 days).",
    present_patterns: [
      /(respond|reply|cure).{0,40}within\s+\d{1,3}\s+(days?|business\s+days?)/i,
      /(\d{1,3})\s+(days?|business\s+days?).{0,40}(respond|cure|comply)/i,
      /\$\s*[\d,]+/,
    ],
  }),
  language({
    id: "SET-013",
    name: "FDCPA — abusive / threatening language flagged (debt collection)",
    description:
      "Demand letters in debt-collection contexts must comply with FDCPA (15 U.S.C. § 1692e) — no false / abusive / threatening representations.",
    citation: fdcpa(),
    playbooks: [SETTLE_PLAYBOOK_DEMAND],
    bad_patterns: [
      /(arrest|criminal\s+prosecut|jail|imprison).{0,60}(if|unless|fail)/is,
      /(if\s+you\s+(fail|do\s+not|don.?t)).{0,60}(arrest|criminal\s+prosecut|jail|imprison)/is,
      /(we\s+will\s+(arrange|have)).{0,40}(arrest|criminal\s+prosecut|jail|imprison)/is,
      /(seize\s+(your|the)\s+(home|property|wages)|garnish.{0,40}without\s+(court|judgment))/is,
      /threat.{0,40}(violence|harm)/is,
    ],
    exclude_if: [
      /(?:does|do|shall|will)\s+not\s+(?:threaten|seek|pursue|constitute|contain\s+(?:any\s+)?threat|make\s+any\s+threat)/i,
      /\bnothing\b[^.]{0,60}(?:threat|constitute|arrest|prosecut)/i,
    ],
    bad_title: "Potentially FDCPA-violative threatening language flagged",
    bad_description:
      "Demand letter appears to contain threats of arrest, criminal prosecution, or non-judicial seizure that may violate FDCPA § 1692e.",
    explanation:
      "15 U.S.C. § 1692e prohibits false, deceptive, or misleading representations in connection with the collection of a debt — including threats of action that cannot legally be taken.",
    recommendation:
      "Remove threats of arrest, criminal prosecution, or non-judicial seizure. Use FDCPA-compliant language.",
    default_severity: "warning",
  }),
  presence({
    id: "SET-014",
    name: "Reservation of rights",
    description: "Demand letter should expressly reserve all rights and remedies.",
    citation: settlePractice(
      "demand-reservation",
      "Demand letter — reservation of rights baseline",
      "https://www.americanbar.org/groups/litigation/",
    ),
    playbooks: [SETTLE_PLAYBOOK_DEMAND],
    missing_title: "Reservation-of-rights clause missing",
    missing_description: "No reservation-of-rights clause was found.",
    explanation:
      "Without an express reservation, a recipient may argue waiver / estoppel based on the demand letter's tone or omissions.",
    recommendation:
      "Add 'Reservation of Rights' stating that nothing in the letter waives any rights or remedies available at law or in equity.",
    present_patterns: [
      /reservation\s+of\s+rights/i,
      /(without\s+prejudice|expressly\s+reserve)/i,
      /(no\s+waiver|nothing\s+(herein|in\s+this\s+letter)\s+(shall|constitutes)\s+a\s+waiver)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "SET-015",
    name: "PAGA pre-suit notice — required elements (if applicable)",
    description:
      "California PAGA demand letters must satisfy Cal. Lab. § 2699.3 (LWDA notice, specific Labor Code sections, supporting facts).",
    citation: pagaNotice(),
    playbooks: [SETTLE_PLAYBOOK_DEMAND],
    missing_title: "PAGA notice elements clause missing (if applicable)",
    missing_description:
      "No PAGA-compliant notice elements were found in a letter that may be a PAGA pre-suit notice.",
    explanation:
      "Cal. Lab. § 2699.3 requires PAGA notices to identify the specific Labor Code sections allegedly violated and the facts and theories supporting each alleged violation, delivered to the LWDA online.",
    recommendation:
      "If this is a PAGA notice, list the specific Labor Code sections allegedly violated, the supporting facts, and confirm LWDA filing.",
    present_patterns: [
      /\bpaga\b/i,
      /(private\s+attorneys?\s+general\s+act|labor\s+code\s+§\s*2699)/i,
      /(lwda|labor\s+(and\s+)?workforce\s+development\s+agency)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// G.4 — Cease-and-desist letter. 5 rules: SET-016..SET-020.
// ────────────────────────────────────────────────────────────────────

const CEASE_DESIST_RULES: Rule[] = [
  presence({
    id: "SET-016",
    name: "Identification of protected IP / right",
    description:
      "Cease-and-desist must identify the specific IP, mark, copyrighted work, or right alleged to be infringed.",
    citation: lanham43(),
    playbooks: [SETTLE_PLAYBOOK_CD],
    missing_title: "Protected IP / right identification missing",
    missing_description:
      "No specific identification of the trademark, copyright, patent, or other right was found.",
    explanation:
      "A C&D that does not specify the asserted right is unhelpful and may not preserve willfulness arguments. For Lanham Act claims, the mark (registration number / common-law rights) must be identified.",
    recommendation:
      "Identify the specific trademark (with reg. no.), copyright (with cert. no.), patent (with patent no.), or right alleged to be infringed.",
    present_patterns: [
      /(trademark|service\s+mark|mark)/i,
      /(copyright|registration|reg\.?\s*no\.?|patent\s+no\.?)/i,
      /(®|™|©|u\.?s\.?\s+pat)/i,
    ],
  }),
  presence({
    id: "SET-017",
    name: "Description of allegedly infringing conduct",
    description: "C&D must describe the allegedly infringing conduct with specificity.",
    citation: lanham43(),
    playbooks: [SETTLE_PLAYBOOK_CD],
    missing_title: "Infringing-conduct description missing",
    missing_description:
      "No description of the allegedly infringing conduct was found in the letter.",
    explanation:
      "Specificity allows the recipient to evaluate and (where appropriate) cure. Vague allegations weaken any later willfulness or laches argument.",
    recommendation:
      "Identify the URL, product, packaging, or content allegedly infringing and describe how it infringes.",
    present_patterns: [
      /(infring|us(ing|e)\s+(of\s+)?the\s+(mark|work|patent))/i,
      /(your\s+(product|website|advertisement|use))/i,
    ],
  }),
  presence({
    id: "SET-018",
    name: "Demand to cease and specific remedial actions",
    description:
      "C&D must demand cessation and specify the remedial actions (recall, transfer, accounting).",
    citation: settlePractice(
      "cd-demand",
      "Cease-and-desist letter — demand baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [SETTLE_PLAYBOOK_CD],
    missing_title: "Cease / remedial demand clause missing",
    missing_description: "No clause demanding cessation and specifying remedial actions was found.",
    explanation:
      "Cease-only demands are common, but a well-drafted C&D demands cessation plus remedial action (recall, destruction, domain transfer, accounting).",
    recommendation:
      "Add a numbered demand: cease, recall / destroy, transfer (e.g., domain), provide accounting, and confirm compliance.",
    present_patterns: [
      /(cease\s+and\s+desist|immediately\s+cease)/i,
      /(recall|destroy|transfer|accounting|written\s+confirmation)/i,
    ],
  }),
  presence({
    id: "SET-019",
    name: "Response deadline",
    description: "C&D must state a response deadline.",
    citation: settlePractice(
      "cd-deadline",
      "Cease-and-desist letter — response deadline baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [SETTLE_PLAYBOOK_CD],
    missing_title: "Response-deadline clause missing",
    missing_description: "No response deadline was specified in the letter.",
    explanation:
      "Without a deadline the letter is open-ended and the recipient may delay; deadlines also support a willfulness argument if ignored.",
    recommendation: "Add 'Response Required by [date]' — typically 7–14 days for IP C&Ds.",
    present_patterns: [
      /(respond|reply|confirm).{0,40}within\s+\d{1,3}\s+(days?|business\s+days?)/i,
      /(by|no\s+later\s+than)\s+\d/i,
    ],
  }),
  language({
    id: "SET-020",
    name: "Anti-SLAPP / extortion risk — overreaching threats flagged",
    description:
      "C&D should avoid threats of unrelated criminal prosecution or other overreach that may give rise to abuse-of-process / extortion / anti-SLAPP exposure.",
    citation: settlePractice(
      "cd-extortion",
      "Cease-and-desist letter — anti-SLAPP / extortion risk baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [SETTLE_PLAYBOOK_CD],
    bad_patterns: [
      /threat.{0,80}(criminal\s+prosecution|report\s+to.{0,40}authorities)/is,
      /(extortion|blackmail|expose)/is,
      /if\s+you\s+do\s+not.{0,60}we\s+will\s+(contact|notify).{0,40}(employer|family|customers)/is,
    ],
    exclude_if: [
      /\bnothing\b[^.]{0,60}(?:constitutes?|amounts?\s+to|is\s+(?:intended|a\s+threat))/i,
      /(?:does|do|shall|will)\s+not\s+(?:constitute|amount\s+to|threaten|contain\s+(?:any\s+)?threat)/i,
    ],
    bad_title: "Potentially overreaching threats flagged",
    bad_description:
      "Letter contains threats of unrelated criminal prosecution, employer contact, or other coercive language that risks anti-SLAPP / extortion exposure.",
    explanation:
      "Threats of unrelated criminal prosecution, employer / family contact, or public exposure may constitute extortion (Flatley v. Mauro, 39 Cal. 4th 299) and expose the sender to abuse-of-process claims.",
    recommendation:
      "Confine the letter to the asserted civil claim and remedies; remove threats of unrelated criminal action, employer contact, or public exposure.",
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// G.5 — Tolling agreement. 4 rules: SET-021..SET-024.
// ────────────────────────────────────────────────────────────────────

const TOLLING_RULES: Rule[] = [
  presence({
    id: "SET-021",
    name: "Identification of tolled claims",
    description:
      "Tolling agreement must identify the claims and statutes of limitations being tolled.",
    citation: stateLimitations(),
    playbooks: [SETTLE_PLAYBOOK_TOLLING],
    missing_title: "Identification of tolled claims missing",
    missing_description:
      "No identification of the claims / limitations periods being tolled was found.",
    explanation:
      "A tolling agreement that does not identify the claims tolled may be construed narrowly or as covering only the specifically-named cause of action.",
    recommendation:
      "Identify each cause of action being tolled and the applicable statute of limitations (with citation).",
    present_patterns: [
      /toll(s|ing|ed)?/i,
      /(claims?|causes?\s+of\s+action)/i,
      /(statute\s+of\s+limitations?|limitations?\s+period)/i,
    ],
  }),
  presence({
    id: "SET-022",
    name: "Tolling period — start and end dates / triggering events",
    description:
      "Tolling agreement must state the tolling period (start date / end date / triggers).",
    citation: stateLimitations(),
    playbooks: [SETTLE_PLAYBOOK_TOLLING],
    missing_title: "Tolling-period clause missing",
    missing_description:
      "No clause specifying the tolling period (start / end / triggers) was found.",
    explanation:
      "Without explicit start / end dates or events, the tolling period is ambiguous and the limitations defense may not be effectively waived.",
    recommendation:
      "Add 'Tolling Period' specifying the start date, end date or terminating event, and any notice requirements.",
    present_patterns: [
      /(tolling\s+period|effective\s+date)/i,
      /(commences?|begin|start)/i,
      /(terminates?|ends?|expires?|expir)/i,
    ],
  }),
  presence({
    id: "SET-023",
    name: "No revival of claims already barred",
    description:
      "Tolling agreement should clarify whether claims already time-barred at execution are revived (default: no).",
    citation: stateLimitations(),
    playbooks: [SETTLE_PLAYBOOK_TOLLING],
    missing_title: "No-revival clause missing",
    missing_description: "No clause addressing revival of already-barred claims was found.",
    explanation:
      "Tolling does not retroactively revive claims that are already time-barred unless the agreement explicitly so provides. Ambiguity invites later disputes.",
    recommendation:
      "Add 'No Revival' clause clarifying that claims already barred at execution are not revived (or expressly revive them with consideration).",
    present_patterns: [
      /(no\s+revival|not\s+revive|already\s+barred)/i,
      /(time.?barred|expired\s+claims?)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "SET-024",
    name: "Termination on notice",
    description: "Tolling agreement should be terminable on stated notice by either party.",
    citation: settlePractice(
      "tolling-termination",
      "Tolling agreement — termination baseline",
      "https://www.americanbar.org/groups/litigation/",
    ),
    playbooks: [SETTLE_PLAYBOOK_TOLLING],
    missing_title: "Termination-on-notice clause missing",
    missing_description: "No clause permitting termination on notice was found.",
    explanation:
      "Open-ended tolling is rarely desirable; either side should be able to terminate on notice (e.g., 30 days), at which point the limitations period resumes running.",
    recommendation:
      "Add 'Termination' permitting either party to terminate on 30 days' written notice; specify that the limitations period resumes on termination.",
    present_patterns: [
      /(terminat(e|ion)|cancel).{0,60}(notice|days?)/is,
      /(30|thirty|10|ten|14|fourteen)\s+days?\s+(notice|written\s+notice)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// G.6 — Litigation hold notice. 6 rules: SET-025..SET-030.
// ────────────────────────────────────────────────────────────────────

const LIT_HOLD_RULES: Rule[] = [
  presence({
    id: "SET-025",
    name: "Triggering event / pending or anticipated litigation",
    description:
      "Litigation hold must describe the triggering event (filed or anticipated litigation / investigation).",
    citation: zubulake(),
    playbooks: [SETTLE_PLAYBOOK_LITHOLD],
    missing_title: "Triggering-event description missing",
    missing_description:
      "No description of the litigation / investigation triggering the hold was found.",
    explanation:
      "Under *Zubulake* and FRCP 37(e), the duty to preserve attaches when litigation is reasonably anticipated. The hold notice should describe the trigger so recipients understand scope.",
    recommendation:
      "Identify the matter (case caption / investigation), the parties, and the date the duty to preserve attached.",
    present_patterns: [
      /(litigation|investigation|claim|dispute|matter)/i,
      /(anticipated|pending|reasonably\s+(expected|anticipated))/i,
    ],
  }),
  presence({
    id: "SET-026",
    name: "Scope of preservation — categories of materials",
    description:
      "Hold notice must identify categories of materials to preserve (documents, emails, ESI, mobile, IM, voicemail).",
    citation: frcp37e(),
    playbooks: [SETTLE_PLAYBOOK_LITHOLD],
    missing_title: "Preservation-scope clause missing",
    missing_description: "No clause identifying the categories of materials to preserve was found.",
    explanation:
      "FRCP 37(e) requires preservation of ESI that should reasonably have been preserved. The hold must enumerate categories (email, chat, mobile, cloud, shared drives, third-party platforms).",
    recommendation:
      "List categories: email, instant messaging (Slack / Teams), text / SMS / mobile, voicemail, paper, shared drives, cloud storage, third-party platforms (e.g., Dropbox, Box, GitHub).",
    present_patterns: [
      /(email|e-mail)/i,
      /(text|sms|slack|teams|chat|instant\s+messag)/i,
      /(electronically\s+stored\s+information|esi|cloud|shared\s+drive)/i,
    ],
  }),
  presence({
    id: "SET-027",
    name: "Suspension of routine deletion / retention policies",
    description:
      "Hold notice must suspend routine deletion / records-retention policies on covered materials.",
    citation: frcp37e(),
    playbooks: [SETTLE_PLAYBOOK_LITHOLD],
    missing_title: "Suspension-of-deletion clause missing",
    missing_description: "No clause suspending routine deletion / retention policies was found.",
    explanation:
      "Routine email purge / auto-delete / DLP retention sweeps must be suspended for covered custodians; FRCP 37(e) sanctions follow when routine deletion destroys ESI subject to a duty to preserve.",
    recommendation:
      "Add 'Suspension of Routine Deletion' instructing recipients (and IT) to suspend auto-delete, mailbox quotas, and routine retention destruction for covered custodians.",
    present_patterns: [
      /(suspend|hold|stop).{0,40}(deletion|destruction|auto.?delete|retention)/is,
      /(do\s+not\s+delete|preserve\s+all)/i,
    ],
  }),
  presence({
    id: "SET-028",
    name: "Custodian list and acknowledgment requirement",
    description: "Hold should identify covered custodians and require written acknowledgment.",
    citation: zubulake(),
    playbooks: [SETTLE_PLAYBOOK_LITHOLD],
    missing_title: "Custodian list / acknowledgment clause missing",
    missing_description:
      "No custodian list or acknowledgment requirement was found in the hold notice.",
    explanation:
      "*Zubulake V* requires counsel to oversee preservation. Acknowledgment establishes that custodians received and understood the hold; the custodian list scopes preservation.",
    recommendation:
      "Identify covered custodians and require each to return a signed acknowledgment within a stated period (typically 5–7 business days).",
    present_patterns: [/(custodian|recipient)/i, /(acknowledg(e|ment)|confirm\s+receipt)/i],
    default_severity: "warning",
  }),
  presence({
    id: "SET-029",
    name: "Point of contact for questions",
    description:
      "Hold notice should designate a point of contact (in-house or outside counsel) for questions.",
    citation: settlePractice(
      "lit-hold-poc",
      "Litigation hold — point-of-contact baseline",
      "https://www.americanbar.org/groups/litigation/",
    ),
    playbooks: [SETTLE_PLAYBOOK_LITHOLD],
    missing_title: "Point-of-contact clause missing",
    missing_description: "No designated point of contact for hold questions was found.",
    explanation:
      "Custodians often have questions about scope, format, and what to do with specific items. A designated POC ensures consistent answers and helps document the preservation effort.",
    recommendation:
      "Add 'Questions' identifying the in-house or outside counsel POC and contact information.",
    present_patterns: [/(questions?|contact|point\s+of\s+contact)/i, /(@|telephone|phone|email)/i],
    default_severity: "warning",
  }),
  presence({
    id: "SET-030",
    name: "Privilege and confidentiality reminder",
    description:
      "Hold notice itself is typically privileged work-product; the notice should remind recipients not to share it externally.",
    citation: settlePractice(
      "lit-hold-privilege",
      "Litigation hold — privilege / work-product baseline",
      "https://www.americanbar.org/groups/litigation/",
    ),
    playbooks: [SETTLE_PLAYBOOK_LITHOLD],
    missing_title: "Privilege / confidentiality reminder missing",
    missing_description:
      "No privilege / confidentiality reminder regarding the hold notice itself was found.",
    explanation:
      "The hold notice and communications regarding it are typically protected as attorney work product. A reminder helps preserve privilege and limits inadvertent waiver.",
    recommendation:
      "Add 'Confidential — Attorney Work Product / Privileged' header and a reminder not to forward externally.",
    present_patterns: [
      /(attorney\s+work\s+product|work.?product|privileged)/i,
      /(confidential|do\s+not\s+forward|do\s+not\s+share)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate. 30 rules total.
// ────────────────────────────────────────────────────────────────────

export const SETTLEMENT_RULES: Rule[] = [
  ...RELEASE_RULES,
  ...SETTLEMENT_AGREEMENT_RULES,
  ...DEMAND_LETTER_RULES,
  ...CEASE_DESIST_RULES,
  ...TOLLING_RULES,
  ...LIT_HOLD_RULES,
];

export {
  RELEASE_RULES,
  SETTLEMENT_AGREEMENT_RULES,
  DEMAND_LETTER_RULES,
  CEASE_DESIST_RULES,
  TOLLING_RULES,
  LIT_HOLD_RULES,
};
