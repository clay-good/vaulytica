/**
 * v4 M&A and investment ruleset — 80 rules (spec-v4.md §6.D, Step 47).
 *
 * Nine playbooks (LOI / term sheet, SPA, APA, merger agreement,
 * disclosure schedules, escrow agreement, TSA, earnout, M&A
 * restrictive covenant). Citations anchor to DGCL §§ 251–271, UCC Art.
 * 9 / state bulk-sales law, the Delaware *Lazard / Aveta* earnout
 * line, the FTC Non-Compete Rule (sale-of-business exception), and
 * the ABA private-target deal-points studies.
 *
 * Rule ids are flat `MNA-NNN` (001..080); each rule's
 * `applies_to_playbooks` restricts execution.
 */

import type { Rule } from "../../../finding.js";
import {
  buildV4PresenceRule,
  buildV4LanguageRule,
  buildV4CompoundRule,
  type V4PresenceSpec,
  type V4LanguageSpec,
  type V4CompoundSpec,
} from "../_helpers.js";
import {
  MA_PLAYBOOK_LOI,
  MA_PLAYBOOK_SPA,
  MA_PLAYBOOK_APA,
  MA_PLAYBOOK_MERGER,
  MA_PLAYBOOK_DISCLOSURE,
  MA_PLAYBOOK_ESCROW,
  MA_PLAYBOOK_TSA,
  MA_PLAYBOOK_EARNOUT,
  MA_PLAYBOOK_MA_RC,
  dgcl,
  ucc9,
  bulkSales,
  delawareEarnoutCases,
  dealPoints,
  ftcNcr,
  sigaPennzoil,
  abaMapa,
  maPractice,
} from "./_helpers.js";

const CATEGORY = "m-and-a";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });
const language = (s: Omit<V4LanguageSpec, "category">): Rule =>
  buildV4LanguageRule({ ...s, category: CATEGORY });
const compound = (s: Omit<V4CompoundSpec, "category">): Rule =>
  buildV4CompoundRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// D.1 — LOI / Term Sheet. 9 rules: MNA-001..MNA-009.
// ────────────────────────────────────────────────────────────────────

const LOI_TERM_SHEET_RULES: Rule[] = [
  compound({
    id: "MNA-001",
    name: "Binding vs non-binding clause clearly demarcated",
    description:
      "LOIs must clearly demarcate binding (confidentiality, exclusivity, expenses, governing law) from non-binding (price, structure) provisions.",
    citation: sigaPennzoil(),
    playbooks: [MA_PLAYBOOK_LOI],
    required_patterns: [
      /(non.?binding|not\s+binding|except\s+(as|for))/i,
      /(binding|legally\s+binding)/i,
      /(confidentiality|exclusivity|expenses)/i,
    ],
    min_match: 3,
    missing_title: "Binding / non-binding demarcation incomplete",
    missing_description:
      "The LOI does not clearly state which provisions are binding and which are non-binding.",
    explanation:
      "The *SIGA / Pennzoil* line shows that LOIs can be enforced as binding contracts if the parties do not clearly disclaim intent to be bound on commercial terms. Standard pattern: confidentiality / exclusivity / expenses / governing law / forum are binding; price / structure / definitive-agreement terms are non-binding.",
    recommendation:
      "Add an explicit 'Binding / Non-Binding Effect' section that enumerates the binding clauses and disclaims binding effect on commercial terms.",
    default_severity: "critical",
  }),
  presence({
    id: "MNA-002",
    name: "Exclusivity / no-shop period stated",
    description:
      "LOI should include an exclusivity period during which the seller may not solicit competing offers.",
    citation: dealPoints("loi-exclusivity", "LOI exclusivity practice"),
    playbooks: [MA_PLAYBOOK_LOI],
    missing_title: "Exclusivity / no-shop period clause missing",
    missing_description: "No exclusivity period was found in the LOI.",
    explanation:
      "Buyers expend diligence cost in reliance on exclusivity. Practice baseline: 30–60 days exclusive negotiation.",
    recommendation: "Add 'Exclusivity' with a defined period and a non-solicitation undertaking.",
    present_patterns: [
      /exclusivity/i,
      /no.shop/i,
      /go.shop/i,
      /not\s+solicit.{0,40}(alternative|competing)/is,
    ],
  }),
  presence({
    id: "MNA-003",
    name: "Confidentiality obligation",
    description: "Binding confidentiality clause is the universal binding LOI provision.",
    citation: dealPoints("loi-confidentiality", "LOI confidentiality"),
    playbooks: [MA_PLAYBOOK_LOI],
    missing_title: "Confidentiality clause missing",
    missing_description: "No binding confidentiality clause was found.",
    explanation:
      "Even when commercial terms are non-binding, the confidentiality obligation should be binding.",
    recommendation: "Either incorporate the existing NDA or add a binding confidentiality clause.",
    present_patterns: [/confidential(ity)?/i, /(non.disclosure|nda)/i],
  }),
  presence({
    id: "MNA-004",
    name: "Purchase price / consideration outline",
    description: "LOI should outline purchase price and consideration mix.",
    citation: dealPoints("loi-price", "LOI price outline"),
    playbooks: [MA_PLAYBOOK_LOI],
    missing_title: "Purchase price / consideration clause missing",
    missing_description: "No purchase price or consideration outline was found.",
    explanation:
      "Even non-binding, the price outline anchors the deal — silence creates downstream disputes about whether the parties agreed on essential terms.",
    recommendation:
      "Add 'Purchase Price' specifying total consideration and consideration mix (cash, stock, rollover, earnout).",
    present_patterns: [
      /purchase\s+price/i,
      /aggregate\s+consideration/i,
      /enterprise\s+value/i,
      /\beva?\b/i,
    ],
  }),
  presence({
    id: "MNA-005",
    name: "Transaction structure outline",
    description: "LOI should outline the transaction structure (stock vs asset vs merger).",
    citation: dealPoints("loi-structure", "LOI structure outline"),
    playbooks: [MA_PLAYBOOK_LOI],
    missing_title: "Transaction structure outline missing",
    missing_description: "No transaction-structure outline was found.",
    explanation:
      "Stock / asset / merger structure has dramatic tax and successor-liability implications that should be flagged early.",
    recommendation:
      "Add 'Structure' specifying the contemplated structure and any required tax-treatment elections.",
    present_patterns: [
      /(stock|asset|merger|share)\s+(purchase|acquisition|transaction)/i,
      /reverse\s+(triangular\s+)?merger/i,
    ],
  }),
  presence({
    id: "MNA-006",
    name: "Conditions to closing — outline",
    description: "LOI should outline conditions to closing (due diligence, financing, regulatory).",
    citation: dealPoints("loi-conditions", "LOI conditions outline"),
    playbooks: [MA_PLAYBOOK_LOI],
    missing_title: "Conditions-to-closing outline missing",
    missing_description: "No conditions-to-closing outline was found.",
    explanation:
      "Buyers and sellers should both know whether the deal is conditioned on financing or regulatory approval.",
    recommendation:
      "Add 'Conditions' outlining due diligence, financing, HSR / regulatory, board / stockholder approvals.",
    present_patterns: [
      /conditions?\s+to\s+closing/i,
      /due\s+diligence/i,
      /financing\s+contingency/i,
      /hsr/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-007",
    name: "Expenses / break fee treatment",
    description:
      "LOI should address whose expenses (party-pays vs reimbursement) and any break fee.",
    citation: dealPoints("loi-expenses", "LOI expense treatment"),
    playbooks: [MA_PLAYBOOK_LOI],
    missing_title: "Expenses / break fee clause missing",
    missing_description: "No expense or break-fee clause was found.",
    explanation:
      "Practice baseline: each side pays its own expenses until signing; certain conduct (e.g., breach of exclusivity) triggers an expense-reimbursement obligation.",
    recommendation:
      "Add 'Expenses' specifying who pays and any reimbursement / break-fee triggers.",
    present_patterns: [
      /expenses\s+(shall|will)\s+be\s+borne/i,
      /(each|own)\s+party.{0,40}expenses/i,
      /break(.up|.fee)?/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-008",
    name: "Termination / expiration date",
    description: "LOI should have an expiration date (drop-dead date).",
    citation: dealPoints("loi-termination", "LOI termination date"),
    playbooks: [MA_PLAYBOOK_LOI],
    missing_title: "Termination / drop-dead clause missing",
    missing_description: "No expiration or termination date was found.",
    explanation:
      "Without a drop-dead the LOI's binding provisions (especially exclusivity) could run indefinitely.",
    recommendation:
      "Add 'Termination' with a fixed expiration date (typically the exclusivity end date).",
    present_patterns: [/termin(ate|ation|ates)/i, /expir(es|ation)/i, /drop.dead\s+date/i],
  }),
  presence({
    id: "MNA-009",
    name: "Governing law / forum (binding)",
    description: "LOI should specify governing law and forum, declared binding.",
    citation: sigaPennzoil(),
    playbooks: [MA_PLAYBOOK_LOI],
    missing_title: "Governing law / forum clause missing",
    missing_description: "No governing-law clause was found.",
    explanation: "Choice of law / forum is universally a binding LOI provision.",
    recommendation: "Add 'Governing Law' and 'Forum' selections, expressly designated binding.",
    present_patterns: [
      /governing\s+law/i,
      /forum\s+selection/i,
      /jurisdiction\s+of\s+the\s+courts/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// D.2 — Stock Purchase Agreement (SPA). 10 rules: MNA-010..MNA-019.
// ────────────────────────────────────────────────────────────────────

const SPA_RULES: Rule[] = [
  presence({
    id: "MNA-010",
    name: "Purchase and sale of shares clause",
    description:
      "SPA must include an operative purchase-and-sale clause identifying the shares and the closing transfer.",
    citation: abaMapa("Section 1.01 Purchase and Sale of Shares"),
    playbooks: [MA_PLAYBOOK_SPA],
    missing_title: "Purchase-and-sale operative clause missing",
    missing_description:
      "No operative clause was found transferring the shares from seller to buyer.",
    explanation:
      "The operative clause is the substantive transfer provision; everything else is conditions, reps, indemnification, and mechanics.",
    recommendation:
      "Add 'Article I — Purchase and Sale' identifying the shares, sellers, and consideration.",
    present_patterns: [
      /purchase\s+and\s+sale/i,
      /sell.{0,40}shares?.{0,40}to\s+buyer/is,
      /buyer\s+shall\s+purchase.{0,40}shares?/is,
    ],
  }),
  presence({
    id: "MNA-011",
    name: "Purchase price and adjustments mechanism",
    description: "SPA must specify purchase price plus working-capital / debt / cash adjustments.",
    citation: dealPoints("spa-wc-adjustment", "SPA working-capital adjustment"),
    playbooks: [MA_PLAYBOOK_SPA],
    missing_title: "Purchase price / adjustment clause missing",
    missing_description: "No purchase price or post-closing adjustment mechanism was found.",
    explanation:
      "ABA deal-points studies report that working-capital, debt, and cash adjustments are present in nearly all private-target SPAs.",
    recommendation:
      "Add 'Article II — Purchase Price' with a closing payment plus a post-closing reconciliation against a target working-capital amount.",
    present_patterns: [
      /(purchase\s+price|aggregate\s+consideration)/i,
      /(working\s+capital|net\s+debt|cash\s+free|debt\s+free)/i,
      /post.closing\s+adjustment/i,
    ],
  }),
  presence({
    id: "MNA-012",
    name: "Representations and warranties of the company",
    description:
      "SPA must include reps of the target company (organization, authority, capitalization, financials, etc.).",
    citation: abaMapa("Article III Representations"),
    playbooks: [MA_PLAYBOOK_SPA],
    missing_title: "Reps and warranties article missing",
    missing_description: "No representations-and-warranties article was found.",
    explanation: "Reps allocate risk between buyer and seller and trigger indemnification.",
    recommendation:
      "Add 'Article III — Representations and Warranties of the Company' covering organization, capitalization, financial statements, litigation, taxes, and material contracts.",
    present_patterns: [
      /representations?\s+(and\s+)?warranties/i,
      /the\s+company\s+(hereby\s+)?represents/i,
    ],
  }),
  presence({
    id: "MNA-013",
    name: "Indemnification — survival and caps",
    description: "SPA must specify rep survival periods and indemnification caps.",
    citation: dealPoints("spa-survival", "ABA deal-points survival / caps"),
    playbooks: [MA_PLAYBOOK_SPA],
    missing_title: "Indemnification / survival clause missing",
    missing_description: "No indemnification or survival clause was found.",
    explanation:
      "ABA studies report 18-month survival and 10–15% caps as median private-target practice.",
    recommendation:
      "Add 'Article VIII — Indemnification' with survival, threshold (basket / deductible), cap, and procedural framework.",
    present_patterns: [
      /indemnif/i,
      /survival/i,
      /(basket|deductible|threshold)/i,
      /cap\s+on\s+(indemnification|claims)/i,
    ],
  }),
  presence({
    id: "MNA-014",
    name: "Closing conditions",
    description: "SPA must specify closing conditions for buyer and seller.",
    citation: abaMapa("Article VI Conditions to Closing"),
    playbooks: [MA_PLAYBOOK_SPA],
    missing_title: "Closing-conditions article missing",
    missing_description: "No closing-conditions article was found.",
    explanation:
      "Bring-down of reps, performance of covenants, no MAE, regulatory approval, and required consents are baseline.",
    recommendation:
      "Add 'Article VI — Conditions to Closing' with bring-down, performance, MAE, regulatory approval, and required-consents conditions.",
    present_patterns: [
      /conditions?\s+to\s+(the\s+)?closing/i,
      /bring.?down/i,
      /no\s+material\s+adverse\s+effect/i,
    ],
  }),
  presence({
    id: "MNA-015",
    name: "Material Adverse Effect (MAE) defined",
    description:
      "SPA must define Material Adverse Effect — central allocation-of-risk concept (Akorn / Channel Medsystems).",
    citation: maPractice(
      "akorn-mae",
      "Akorn, Inc. v. Fresenius Kabi AG, 198 A.3d 724 (Del. Ch. 2018); Channel Medsystems, Inc. v. Bos. Sci. Corp., 2019 WL 6896462 (Del. Ch.)",
      "https://courts.delaware.gov/Opinions/",
    ),
    playbooks: [MA_PLAYBOOK_SPA, MA_PLAYBOOK_MERGER],
    missing_title: "MAE definition missing",
    missing_description: "No Material Adverse Effect definition was found.",
    explanation:
      "*Akorn / Channel Medsystems* affirm the high bar to invoke MAE; nevertheless the definition is the linchpin of buyer walk rights and must be present.",
    recommendation:
      "Add a 'Material Adverse Effect' definition with the customary carve-outs (general economy, industry, war, pandemic) qualified by 'disproportionate impact'.",
    present_patterns: [/material\s+adverse\s+effect/i, /\bmae\b/i],
  }),
  presence({
    id: "MNA-016",
    name: "Non-solicit / non-compete on selling stockholders",
    description:
      "Selling stockholders typically agree to non-compete and non-solicit covenants (enforceable under state-law sale-of-business doctrine).",
    citation: ftcNcr(),
    playbooks: [MA_PLAYBOOK_SPA],
    missing_title: "Selling-stockholder restrictive covenants missing",
    missing_description:
      "No non-compete or non-solicit clause binding selling stockholders was found.",
    explanation:
      "Sale-of-business non-competes are enforceable under state-law goodwill doctrine (e.g., Cal. Bus. & Prof. Code § 16601) — even California's ban gives way here. Goodwill protection is universally expected from selling principals. (The vacated, never-effective FTC Non-Compete Rule would likewise have preserved them.)",
    recommendation:
      "Add 'Article IX — Restrictive Covenants' with non-compete (3–5 years), non-solicit (employees / customers), and confidentiality undertakings.",
    present_patterns: [/(non.?compete|non.?solicit)/i, /restrictive\s+covenant/i],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-017",
    name: "Sandbagging clause (pro- or anti-)",
    description:
      "SPA should address sandbagging — buyer's right to indemnify even with pre-closing knowledge.",
    citation: dealPoints("spa-sandbagging", "ABA deal-points sandbagging"),
    playbooks: [MA_PLAYBOOK_SPA],
    missing_title: "Sandbagging clause missing",
    missing_description: "No sandbagging clause was found.",
    explanation:
      "Pro-sandbagging clauses preserve buyer's indemnification rights even where it knew of a rep breach pre-closing; anti-sandbagging clauses bar them.",
    recommendation:
      "Add a clear sandbagging clause; ABA studies favor pro-sandbagging in most private deals.",
    present_patterns: [
      /(sandbag|sandbagging)/i,
      /buyer.s\s+knowledge.{0,80}(shall|will).{0,40}not\s+(affect|limit|impair)/is,
      /investigation.{0,40}(shall|will).{0,40}not\s+(affect|limit|impair)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-018",
    name: "Stockholder representative provision",
    description:
      "Multi-seller SPAs need a stockholder representative for post-closing administration.",
    citation: dealPoints("spa-rep", "ABA deal-points stockholder representative"),
    playbooks: [MA_PLAYBOOK_SPA],
    missing_title: "Stockholder-representative clause missing",
    missing_description: "No stockholder-representative clause was found.",
    explanation:
      "Without a designated representative the buyer must negotiate with every selling stockholder individually post-closing.",
    recommendation:
      "Add 'Article X — Stockholder Representative' identifying the representative and granting binding authority.",
    present_patterns: [
      /stockholder.s?\s+representative/i,
      /sellers.?\s+representative/i,
      /shareholders.?\s+agent/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-019",
    version: "1.1.0",
    name: "Governing law and forum",
    description: "SPA must include governing-law and forum-selection clauses.",
    citation: dgcl("115"),
    playbooks: [MA_PLAYBOOK_SPA, MA_PLAYBOOK_APA, MA_PLAYBOOK_MERGER],
    missing_title: "Governing-law / forum clause missing",
    missing_description: "No governing-law or forum-selection clause was found.",
    explanation: "Delaware Chancery is the typical forum for private-target M&A.",
    recommendation: "Add 'Governing Law' (Delaware) and 'Forum' (Delaware Chancery) selections.",
    // "This Agreement is governed by the laws of the State of X" is the
    // dominant §-body form; requiring the noun phrase "governing law" called
    // a present clause missing (critical) on a clean APA.
    present_patterns: [
      /governing\s+law/i,
      /governed\s+by\s+the\s+laws?\b/i,
      /(jurisdiction|forum).{0,40}(chancery|delaware)/is,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// D.3 — Asset Purchase Agreement (APA). 9 rules: MNA-020..MNA-028.
// ────────────────────────────────────────────────────────────────────

const APA_RULES: Rule[] = [
  presence({
    id: "MNA-020",
    name: "Purchased Assets — defined list / exhibit",
    description: "APA must define Purchased Assets with specificity (typically by exhibit).",
    citation: abaMapa("APA Section 1.01 Purchased Assets"),
    playbooks: [MA_PLAYBOOK_APA],
    missing_title: "Purchased Assets definition missing",
    missing_description: "No Purchased Assets definition was found.",
    explanation:
      "Asset deals depend on a precise list — ambiguity creates successor-liability and title disputes.",
    recommendation: "Add 'Purchased Assets' with an itemized list referencing a schedule.",
    present_patterns: [
      /purchased\s+assets/i,
      /transferred\s+assets/i,
      /assets\s+to\s+be\s+(sold|transferred|conveyed)/is,
    ],
  }),
  presence({
    id: "MNA-021",
    name: "Excluded Assets carve-out",
    description: "APA must define Excluded Assets carve-out.",
    citation: abaMapa("APA Section 1.02 Excluded Assets"),
    playbooks: [MA_PLAYBOOK_APA],
    missing_title: "Excluded Assets clause missing",
    missing_description: "No Excluded Assets clause was found.",
    explanation:
      "Without an explicit excluded-assets list, residual assets (cash, claims, IP outside the business) default to transferred.",
    recommendation:
      "Add 'Excluded Assets' enumerating items retained by seller (typically cash, tax refunds, retained IP, certain contracts).",
    present_patterns: [/excluded\s+assets/i],
  }),
  presence({
    id: "MNA-022",
    name: "Assumed Liabilities — defined",
    description: "APA must define Assumed Liabilities precisely.",
    citation: abaMapa("APA Section 2.01 Assumed Liabilities"),
    playbooks: [MA_PLAYBOOK_APA],
    missing_title: "Assumed Liabilities clause missing",
    missing_description: "No Assumed Liabilities clause was found.",
    explanation:
      "The structural advantage of an APA is that buyer assumes only specifically-identified liabilities; silence breaks that advantage.",
    recommendation:
      "Add 'Assumed Liabilities' enumerating each liability category buyer is assuming.",
    present_patterns: [/assumed\s+liabilities/i],
  }),
  presence({
    id: "MNA-023",
    name: "Excluded Liabilities — defined and broad",
    description:
      "APA must include a broad Excluded Liabilities clause covering everything not specifically assumed.",
    citation: abaMapa("APA Section 2.02 Excluded Liabilities"),
    playbooks: [MA_PLAYBOOK_APA],
    missing_title: "Excluded Liabilities clause missing",
    missing_description: "No Excluded Liabilities clause was found.",
    explanation:
      "The protective half of the assumed-liabilities pair. Standard pattern: 'all liabilities not expressly listed in § 2.01 as Assumed Liabilities'.",
    recommendation: "Add 'Excluded Liabilities' as a catch-all for everything not assumed.",
    present_patterns: [/excluded\s+liabilities/i],
  }),
  presence({
    id: "MNA-024",
    name: "Bulk-sales law treatment",
    description: "APA should address state bulk-sales law (former UCC Art. 6) where it survives.",
    citation: bulkSales(),
    playbooks: [MA_PLAYBOOK_APA],
    missing_title: "Bulk-sales law clause missing",
    missing_description: "No bulk-sales-law clause was found.",
    explanation:
      "Many states have repealed bulk-sales (former UCC Art. 6) but several retain it (CA Civ. § 6101 et seq., MD, etc.). The APA should waive compliance and shift creditor risk to seller.",
    recommendation:
      "Add 'Bulk Sales' waiving compliance with any applicable bulk-sales law and indemnifying buyer for resulting creditor claims.",
    present_patterns: [/bulk\s+(sales?|transfer)/i],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-025",
    name: "Allocation of purchase price (§ 1060 / Form 8594)",
    description: "APA must address purchase-price allocation under IRC § 1060.",
    citation: maPractice(
      "irc-1060",
      "26 U.S.C. § 1060 — Special allocation rules for certain asset acquisitions (Form 8594)",
      "https://www.law.cornell.edu/uscode/text/26/1060",
    ),
    playbooks: [MA_PLAYBOOK_APA],
    missing_title: "Purchase-price allocation clause missing",
    missing_description: "No purchase-price allocation / Form 8594 clause was found.",
    explanation:
      "IRC § 1060 requires consistent reporting on Form 8594. The APA should either set the allocation in an exhibit or describe the mechanism for setting it.",
    recommendation:
      "Add 'Purchase Price Allocation' specifying how the parties will allocate the price among asset classes for Form 8594 purposes.",
    present_patterns: [
      /allocation\s+of\s+(the\s+)?purchase\s+price/i,
      /(section\s+1060|form\s+8594)/i,
    ],
  }),
  presence({
    id: "MNA-026",
    version: "1.1.0",
    name: "Required consents and assignment mechanics",
    description:
      "APA must address required consents and the mechanics for transferring non-assignable contracts (§ 9-406 UCC anti-assignment overrides where applicable).",
    citation: ucc9("406"),
    playbooks: [MA_PLAYBOOK_APA],
    missing_title: "Required consents / assignment clause missing",
    missing_description: "No required-consents or assignment clause was found.",
    explanation:
      "Asset deals routinely depend on third-party consents — landlords, key customers, lenders.",
    recommendation:
      "Add 'Required Consents' identifying the consents needed for closing and an 'Assignment of Non-Transferable Contracts' fallback (alternative arrangement / pass-through).",
    // A consents CONDITION names its consent-giver: "assignment of the lease
    // … with the landlord's written consent". The generic branches missed
    // every named third party.
    present_patterns: [
      /required\s+consents/i,
      /(assignment|transfer).{0,40}(third.party\s+consent|consent\s+to\s+assign)/is,
      /non.assignable/i,
      /(?:assignment|assign|transfer)[^.]{0,120}?\b(?:landlord|lessor|licensor|lender|counterpart(?:y|ies)|third\s+part(?:y|ies))(?:'s)?\s+(?:prior\s+)?written\s+consent/is,
    ],
  }),
  presence({
    id: "MNA-027",
    name: "Employee transfer / WARN Act treatment",
    description:
      "Asset deals routinely transfer employees; the APA should address WARN Act / state mini-WARN exposure.",
    citation: maPractice(
      "warn-act",
      "Worker Adjustment and Retraining Notification Act (29 U.S.C. § 2101)",
      "https://www.law.cornell.edu/uscode/text/29/chapter-23",
    ),
    playbooks: [MA_PLAYBOOK_APA],
    missing_title: "Employee transfer / WARN clause missing",
    missing_description: "No employee-transfer or WARN-Act clause was found.",
    explanation:
      "Asset purchases can trigger WARN obligations on seller if employees are not offered comparable employment by buyer.",
    recommendation:
      "Add 'Employees' identifying transferred / terminated employees and allocating WARN-Act compliance risk.",
    present_patterns: [
      /transferred\s+employees?/i,
      /\bwarn\s+act\b/i,
      /offer\s+letters?\s+to\s+employees/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-028",
    name: "Bill of sale and assignment-and-assumption exhibits",
    description:
      "APA must contemplate a bill of sale + assignment-and-assumption agreement as closing deliverables.",
    citation: abaMapa("APA closing deliverables"),
    playbooks: [MA_PLAYBOOK_APA],
    missing_title: "Closing deliverables (bill of sale) clause missing",
    missing_description: "No bill-of-sale or assignment-and-assumption reference was found.",
    explanation: "These ancillary documents effect title transfer under state UCC / property law.",
    recommendation:
      "Add 'Closing Deliverables' referencing a bill of sale and an assignment-and-assumption agreement (exhibits A and B).",
    present_patterns: [/bill\s+of\s+sale/i, /assignment\s+and\s+assumption/i],
  }),
];

// ────────────────────────────────────────────────────────────────────
// D.4 — Merger Agreement. 10 rules: MNA-029..MNA-038.
// ────────────────────────────────────────────────────────────────────

const MERGER_RULES: Rule[] = [
  presence({
    id: "MNA-029",
    name: "Plan of merger / surviving corporation",
    description:
      "Merger agreement must identify the surviving corporation and the plan of merger (DGCL § 251).",
    citation: dgcl("251"),
    playbooks: [MA_PLAYBOOK_MERGER],
    missing_title: "Plan of merger / surviving corporation clause missing",
    missing_description: "No plan-of-merger clause was found.",
    explanation:
      "DGCL § 251 requires the merger agreement to identify the constituent corporations and the surviving corporation.",
    recommendation:
      "Add 'Plan of Merger' identifying the constituent corporations and the survivor.",
    present_patterns: [
      /plan\s+of\s+merger/i,
      /surviving\s+corporation/i,
      /constituent\s+corporation/i,
    ],
  }),
  presence({
    id: "MNA-030",
    name: "Merger consideration mechanics",
    description:
      "Merger agreement must specify the consideration mechanics — per-share consideration, treatment of equity awards, exchange agent.",
    citation: dgcl("251"),
    playbooks: [MA_PLAYBOOK_MERGER],
    missing_title: "Merger-consideration clause missing",
    missing_description: "No merger-consideration clause was found.",
    explanation:
      "Each share class needs a defined per-share consideration; equity awards (options / RSUs) need accelerated / rolled-over treatment.",
    recommendation:
      "Add 'Merger Consideration' specifying per-share consideration for each class and treatment of options / RSUs.",
    present_patterns: [
      /per.share\s+consideration/i,
      /merger\s+consideration/i,
      /exchange\s+agent/i,
    ],
  }),
  presence({
    id: "MNA-031",
    name: "Appraisal rights notice (DGCL § 262)",
    description: "Stockholders must be advised of appraisal rights under DGCL § 262.",
    citation: dgcl("262"),
    playbooks: [MA_PLAYBOOK_MERGER],
    missing_title: "Appraisal rights / § 262 notice clause missing",
    missing_description: "No appraisal-rights / DGCL § 262 reference was found.",
    explanation:
      "DGCL § 262 entitles dissenting stockholders to appraisal in qualifying mergers. The notice obligation is statutory and the agreement should restate it.",
    recommendation:
      "Add 'Appraisal Rights' describing dissenters' rights under DGCL § 262 and the notice mechanics.",
    present_patterns: [/(section\s+262|appraisal\s+rights|dissenters)/i],
  }),
  presence({
    id: "MNA-032",
    name: "Stockholder approval mechanism",
    description: "Merger agreement must address required stockholder approvals (DGCL § 251(c)).",
    citation: dgcl("251"),
    playbooks: [MA_PLAYBOOK_MERGER],
    missing_title: "Stockholder-approval clause missing",
    missing_description: "No stockholder-approval clause was found.",
    explanation:
      "DGCL § 251(c) requires the merger to be adopted by stockholders. The agreement should specify majority (or higher) approval and proxy / written-consent mechanics.",
    recommendation:
      "Add 'Stockholder Approval' specifying the required vote and contemplated mechanism (proxy statement or DGCL § 228 written consent).",
    present_patterns: [
      /stockholder\s+approval/i,
      /required\s+vote/i,
      /majority\s+of\s+(the\s+)?outstanding/i,
    ],
  }),
  presence({
    id: "MNA-033",
    name: "No-solicitation / fiduciary out covenant",
    description:
      "Public-company / target-board merger agreements need fiduciary-out language permitting board to respond to superior proposals.",
    citation: maPractice(
      "fiduciary-out-omnicare",
      "Omnicare, Inc. v. NCS Healthcare, Inc., 818 A.2d 914 (Del. 2003)",
      "https://courts.delaware.gov/Opinions/",
    ),
    playbooks: [MA_PLAYBOOK_MERGER],
    missing_title: "No-shop / fiduciary-out clause missing",
    missing_description: "No no-shop or fiduciary-out clause was found.",
    explanation:
      "*Omnicare* requires fiduciary-out language so the target board may respond to superior proposals; locking up the deal completely is invalid for public targets.",
    recommendation:
      "Add 'No Solicitation' with a fiduciary-out for Superior Proposals and a customary 'window-shop' allowance.",
    present_patterns: [
      /no.solicitation/i,
      /no.shop/i,
      /superior\s+proposal/i,
      /fiduciary\s+(out|exception|duty)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-034",
    name: "Termination fee / break-up fee",
    description:
      "Merger agreements typically include a break-up fee for fiduciary-out / superior-proposal scenarios.",
    citation: dealPoints("merger-breakup-fee", "Merger break-up fee practice"),
    playbooks: [MA_PLAYBOOK_MERGER],
    missing_title: "Break-up fee clause missing",
    missing_description: "No break-up fee / termination fee clause was found.",
    explanation: "Standard practice: 3–4% of equity value, paid on superior-proposal termination.",
    recommendation: "Add a break-up fee section with a percentage value and trigger events.",
    present_patterns: [/(break.?up|termination)\s+fee/i],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-035",
    name: "Drag-along / appraisal-waiver letter agreement reference",
    description:
      "Private-target mergers often pair with a stockholder consent / drag-along enforcement.",
    citation: maPractice(
      "drag-along-merger",
      "Drag-along and appraisal-waiver letter agreements in private-target mergers",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [MA_PLAYBOOK_MERGER],
    missing_title: "Stockholder-consent / drag-along reference missing",
    missing_description:
      "No reference to stockholder consents or drag-along letter agreements was found.",
    explanation:
      "Most private-target mergers close with DGCL § 228 written consents + drag-along letter agreements obtained from each significant stockholder.",
    recommendation:
      "Reference 'Stockholder Consents' or 'Drag-Along Letter Agreements' as a closing deliverable.",
    present_patterns: [
      /written\s+consent.{0,40}stockholders/is,
      /drag.along/i,
      /support\s+agreement/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-036",
    name: "Filing of certificate of merger (§ 251(c))",
    description:
      "Merger agreement should contemplate filing the certificate of merger with the Delaware Secretary of State.",
    citation: dgcl("251(c)"),
    playbooks: [MA_PLAYBOOK_MERGER],
    missing_title: "Certificate-of-merger filing clause missing",
    missing_description: "No certificate-of-merger filing clause was found.",
    explanation:
      "DGCL § 251(c) and § 103 make the merger effective on filing the certificate of merger.",
    recommendation:
      "Add 'Filing' specifying that the certificate of merger shall be filed with the Delaware Secretary of State at closing.",
    present_patterns: [
      /certificate\s+of\s+merger/i,
      /file\s+with\s+the\s+(secretary\s+of\s+state|delaware)/is,
    ],
  }),
  presence({
    id: "MNA-037",
    name: "Treatment of options and RSUs at closing",
    description:
      "Merger consideration must specify treatment of in-the-money / out-of-the-money options and RSUs.",
    citation: dealPoints("merger-equity-treatment", "Equity-award treatment in mergers"),
    playbooks: [MA_PLAYBOOK_MERGER],
    missing_title: "Equity-award treatment clause missing",
    missing_description: "No clause was found addressing treatment of options / RSUs at closing.",
    explanation:
      "ISO / NSO / RSU and underwater-option treatment differs widely; the agreement must specify (cash-out, rollover, cancellation).",
    recommendation:
      "Add 'Treatment of Equity Awards' specifying cash-out for vested in-the-money awards, cancellation for underwater, and treatment of unvested.",
    present_patterns: [
      /treatment\s+of.{0,40}(option|rsu|equity)/is,
      /cash.out.{0,40}option/is,
      /unvested\s+(option|rsu)/i,
    ],
  }),
  presence({
    id: "MNA-038",
    name: "Reverse vs forward / triangular structure stated",
    description: "Merger structure (forward, reverse, reverse-triangular) should be explicit.",
    citation: maPractice(
      "merger-structure",
      "Reverse-triangular merger practice baseline (tax + assignment treatment)",
      "https://www.americanbar.org/groups/business_law/resources/business-law-today/",
    ),
    playbooks: [MA_PLAYBOOK_MERGER],
    missing_title: "Merger-structure clause missing",
    missing_description:
      "No clause was found identifying the merger structure (forward / reverse / triangular).",
    explanation:
      "Structure determines tax treatment (e.g., § 368(a)(1)(A) vs (a)(2)(E)) and contract anti-assignment exposure.",
    recommendation: "Add a structure recital explicitly identifying the merger structure.",
    present_patterns: [
      /reverse\s+(triangular\s+)?merger/i,
      /forward\s+merger/i,
      /merger\s+sub\s+(shall|will)/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// D.5 — Disclosure Schedules. 7 rules: MNA-039..MNA-045.
// ────────────────────────────────────────────────────────────────────

const DISCLOSURE_SCHEDULE_RULES: Rule[] = [
  presence({
    id: "MNA-039",
    name: "Disclosure-schedule introduction / general notes",
    description:
      "Disclosure schedules should have an introduction reciting which reps they qualify and the scope rules (cross-section qualification, immateriality).",
    citation: dealPoints("ds-intro", "Disclosure schedule introduction practice"),
    playbooks: [MA_PLAYBOOK_DISCLOSURE],
    missing_title: "Disclosure schedule introduction missing",
    missing_description: "No disclosure-schedule introduction / general notes section was found.",
    explanation:
      "Practitioner baseline: schedules carry an introduction that (i) cross-references the SPA, (ii) addresses cross-section qualification, and (iii) disclaims materiality inferences.",
    recommendation:
      "Add 'General Notes' at the front of the schedules covering cross-section qualification and materiality disclaimers.",
    present_patterns: [/disclosure\s+schedule/i, /general\s+(notes|provisions|preamble)/i],
  }),
  language({
    id: "MNA-040",
    name: "Schedules disclose by mere reference to a data-room folder",
    description:
      "Mere reference to a data-room folder generally does not constitute disclosure (*Cobalt International* line).",
    citation: maPractice(
      "cobalt-disclosure",
      "Cobalt International Energy, Inc. line on data-room disclosure (Del. Ch.)",
      "https://courts.delaware.gov/Opinions/",
    ),
    playbooks: [MA_PLAYBOOK_DISCLOSURE],
    bad_patterns: [
      /see\s+(the\s+)?data.room/i,
      /reference(?:d)?\s+to\s+(the\s+)?(data.room|deal\s+room)/is,
      /materials?\s+in\s+(the\s+)?data.room/is,
    ],
    bad_title: "Disclosure by data-room reference flagged",
    // The patterns prove only that a data-room reference EXISTS, not that it is
    // the entire disclosure for the item, so the description must not claim the
    // schedule discloses "solely" that way — schedules routinely describe an
    // item specifically and point to the data room for executed copies.
    bad_description:
      "The schedule discloses by reference to a data-room folder; a bare reference typically does not constitute proper disclosure unless the item is also described specifically.",
    explanation:
      "Delaware Chancery has cautioned that mere availability of documents in the data room is insufficient; the schedules must identify or summarize the matter disclosed.",
    recommendation:
      "Replace data-room references with specific descriptions or document-by-document listings.",
    default_severity: "warning",
  }),
  presence({
    id: "MNA-041",
    name: "Cross-section qualification convention stated",
    description:
      "Schedules should state whether disclosure in one section qualifies other sections where reasonably apparent.",
    citation: dealPoints("ds-cross-qual", "Cross-section qualification practice"),
    playbooks: [MA_PLAYBOOK_DISCLOSURE],
    missing_title: "Cross-section qualification convention missing",
    missing_description:
      "No clause was found stating whether disclosure in one section qualifies other sections.",
    explanation:
      "ABA studies show a roughly even split between 'qualifies all reps where reasonably apparent' (seller-friendly) and 'qualifies only its specific rep' (buyer-friendly).",
    recommendation: "Pick a convention and state it explicitly in the introduction.",
    present_patterns: [/disclosure.{0,80}(qualifies|applies\s+to)/is, /reasonably\s+apparent/i],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-042",
    version: "1.1.0",
    name: "Materiality / dollar-threshold-conformity disclaimer",
    description:
      "Schedules should disclaim that listing of items above a stated threshold implies materiality.",
    citation: dealPoints("ds-materiality", "Materiality disclaimer practice"),
    playbooks: [MA_PLAYBOOK_DISCLOSURE],
    missing_title: "Materiality disclaimer missing",
    missing_description: "No materiality / threshold disclaimer was found.",
    explanation:
      "Sellers commonly list items above an internal threshold for thoroughness without conceding materiality. The disclaimer protects against later 'admission of materiality' arguments.",
    recommendation: "Add a materiality disclaimer in the General Notes.",
    present_patterns: [
      /materiality.{0,40}(disclaim|shall\s+not\s+(be|imply))/is,
      /threshold.{0,40}(disclaim|shall\s+not\s+(be|imply))/is,
      // The standard formulation: "the inclusion of any item … is NOT AN
      // ADMISSION that such item is MATERIAL", "no disclosure shall be
      // deemed to ENLARGE or ESTABLISH any STANDARD OF MATERIALITY".
      /not\s+an\s+admission\s+that[^.]{0,80}\bmaterial/is,
      /standard\s+of\s+materiality/i,
      /deemed\s+to\s+(?:enlarge|establish|expand)[^.]{0,60}(?:materiality|threshold)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-043",
    name: "Section-numbered references to SPA reps",
    description: "Disclosure schedules should be organized by SPA representation section number.",
    citation: dealPoints("ds-numbering", "Section-numbering practice"),
    playbooks: [MA_PLAYBOOK_DISCLOSURE],
    missing_title: "Section-numbered organization missing",
    missing_description: "No section-numbered organization of the disclosures was found.",
    explanation:
      "Schedules organized by rep section number give the simplest mapping for the buyer's diligence team.",
    recommendation: "Organize each schedule under the corresponding SPA rep section number.",
    present_patterns: [/section\s+\d/i, /schedule\s+\d/i],
  }),
  presence({
    id: "MNA-044",
    name: "Update / supplement mechanic",
    description:
      "SPA / schedules should address whether (and how) schedules may be updated between signing and closing.",
    citation: dealPoints("ds-updates", "Schedule updates practice"),
    playbooks: [MA_PLAYBOOK_DISCLOSURE],
    missing_title: "Schedule-update mechanic missing",
    missing_description: "No clause was found addressing schedule updates.",
    explanation:
      "ABA studies show roughly half of SPAs allow updates between signing and closing; the other half do not. Silence creates litigation risk.",
    recommendation:
      "Add a 'Supplemental Disclosure' section specifying whether updates are permitted and their effect on closing conditions and indemnification.",
    present_patterns: [/supplement(al)?\s+disclosure/i, /update.{0,40}(schedule|disclosure)/is],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-045",
    name: "Confidentiality of disclosure schedules",
    description: "Disclosure schedules should be designated as confidential.",
    citation: dealPoints("ds-confidentiality", "Schedules confidentiality"),
    playbooks: [MA_PLAYBOOK_DISCLOSURE],
    missing_title: "Confidentiality marking / clause missing",
    missing_description: "No confidentiality clause / marking was found.",
    explanation:
      "Schedules typically contain the target's most sensitive operational information; treating them as confidential prevents unintended disclosure.",
    recommendation: "Add a confidentiality clause or marking in the General Notes.",
    present_patterns: [/confidential/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// D.6 — Escrow Agreement. 9 rules: MNA-046..MNA-054.
// ────────────────────────────────────────────────────────────────────

const ESCROW_AGREEMENT_RULES: Rule[] = [
  presence({
    id: "MNA-046",
    name: "Escrow agent identified",
    description: "Escrow agreement must identify the escrow agent.",
    citation: maPractice(
      "escrow-agent",
      "Standard escrow practice (commercial escrow agents)",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_ESCROW],
    missing_title: "Escrow agent identification missing",
    missing_description: "No escrow-agent identification was found.",
    explanation: "Escrow without an agent is incomplete.",
    recommendation: "Add 'Parties' identifying buyer, seller, and the escrow agent.",
    present_patterns: [/escrow\s+agent/i],
  }),
  presence({
    id: "MNA-047",
    name: "Escrow amount, asset type, account specified",
    description: "Escrow agreement must specify amount, asset (cash / stock / other), and account.",
    citation: maPractice(
      "escrow-amount",
      "Standard escrow practice — funded amounts",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_ESCROW],
    missing_title: "Escrow amount / asset clause missing",
    missing_description: "No clause was found specifying escrow amount, asset, or account.",
    explanation: "The agreement must say what is held, how much, and where.",
    recommendation:
      "Add 'Escrow Fund' specifying the deposited amount / shares and the escrow account.",
    present_patterns: [
      /escrow\s+(fund|amount|account)/i,
      /\$[\d,]+\s+(in\s+escrow|escrow\s+deposit)/is,
    ],
  }),
  presence({
    id: "MNA-048",
    name: "Release / claim mechanics",
    description:
      "Escrow agreement must specify how funds are released — joint instructions / sole instructions / arbitration.",
    citation: maPractice(
      "escrow-release",
      "Escrow release mechanics (NVCA / ABA practice)",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [MA_PLAYBOOK_ESCROW],
    missing_title: "Release / claim mechanics clause missing",
    missing_description: "No release mechanics were found.",
    explanation:
      "Without a release mechanism the agent cannot pay out; standard pattern is joint instructions or unilateral claim with response window.",
    recommendation:
      "Add 'Release of Escrow Fund' with joint-instruction and unilateral-claim mechanics.",
    present_patterns: [
      /release\s+of\s+(the\s+)?escrow/i,
      /joint\s+(instruction|written\s+notice)/i,
      /claim\s+notice/i,
    ],
  }),
  presence({
    id: "MNA-049",
    name: "Dispute-resolution mechanics",
    description:
      "Escrow agreement must specify how disputes between buyer / seller over release are resolved.",
    citation: maPractice(
      "escrow-dispute",
      "Standard escrow dispute-resolution practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_ESCROW],
    missing_title: "Escrow dispute-resolution clause missing",
    missing_description: "No dispute-resolution clause was found.",
    explanation:
      "Without an agreed procedure, escrow agents default to interpleader, slowing release.",
    recommendation:
      "Add 'Disputes' specifying mediation / arbitration / judicial-determination steps.",
    present_patterns: [
      /interpleader/i,
      /arbitrat/i,
      /(dispute|disagreement).{0,40}(resolution|procedure)/is,
    ],
  }),
  presence({
    id: "MNA-050",
    name: "Escrow agent indemnification + limitations",
    description: "Escrow agreement should indemnify the agent for actions taken in good faith.",
    citation: maPractice(
      "escrow-agent-indemnification",
      "Standard escrow-agent indemnification practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_ESCROW],
    missing_title: "Escrow-agent indemnification clause missing",
    missing_description: "No escrow-agent indemnification clause was found.",
    explanation: "Commercial agents will not sign without indemnification for good-faith actions.",
    recommendation:
      "Add 'Indemnification of Escrow Agent' covering claims and expenses arising from the escrow except for the agent's gross negligence or willful misconduct.",
    present_patterns: [/indemnif(y|ication).{0,40}(escrow\s+agent|agent)/is],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-051",
    name: "Investment of escrow funds",
    description: "Escrow agreement should specify how funds are invested.",
    citation: maPractice(
      "escrow-investment",
      "Standard escrow investment-of-funds practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_ESCROW],
    missing_title: "Investment-of-funds clause missing",
    missing_description: "No investment-of-funds clause was found.",
    explanation:
      "Cash escrows of multi-month duration earn interest; the agreement should specify permitted investments (typically money-market / Treasury).",
    recommendation:
      "Add 'Investment of Funds' specifying permitted investments and tax allocation of investment income.",
    present_patterns: [
      /investment\s+of\s+(the\s+)?(escrow|funds)/i,
      /(money\s+market|treasury\s+bill)/i,
      /interest\s+(earned|allocated)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-052",
    name: "Tax reporting and treatment",
    description: "Escrow agreement should specify tax-reporting party and treatment of interest.",
    citation: maPractice(
      "escrow-tax",
      "Standard escrow tax-reporting practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_ESCROW],
    missing_title: "Tax-reporting clause missing",
    missing_description: "No tax-reporting clause was found.",
    explanation:
      "IRS treats interest as earned by one party (typically seller) for tax purposes; the agreement should designate.",
    recommendation:
      "Add 'Tax Reporting' designating the tax owner of escrow income and the agent's 1099 reporting obligation.",
    present_patterns: [/tax\s+reporting/i, /(1099|tax\s+owner|grantor\s+trust)/i],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-053",
    name: "Termination of escrow / final release",
    description: "Escrow agreement should specify the termination event triggering final release.",
    citation: maPractice(
      "escrow-termination",
      "Standard escrow termination practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_ESCROW],
    missing_title: "Escrow termination clause missing",
    missing_description: "No termination clause was found.",
    explanation:
      "Typical: termination on a date certain (e.g., 18 months post-closing) with release of any unclaimed balance to seller.",
    recommendation: "Add 'Termination' on the survival expiration date.",
    present_patterns: [
      /termination\s+of\s+(this\s+)?escrow/i,
      /final\s+release/i,
      /escrow\s+(period|term)\s+(expires|ends)/i,
    ],
  }),
  presence({
    id: "MNA-054",
    name: "Notices and addresses",
    description: "Escrow agreement must include notices addresses for buyer, seller, and agent.",
    citation: maPractice(
      "escrow-notices",
      "Standard escrow notices practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_ESCROW],
    missing_title: "Notices clause missing",
    missing_description: "No notices / addresses clause was found.",
    explanation: "Operationally critical — agents will not act without an updated notices block.",
    recommendation: "Add 'Notices' with addresses, emails, and a manner-of-delivery clause.",
    present_patterns: [/notices/i, /shall\s+be\s+delivered/i],
    default_severity: "info",
  }),
];

// ────────────────────────────────────────────────────────────────────
// D.7 — Transition Services Agreement (TSA). 8 rules: MNA-055..MNA-062.
// ────────────────────────────────────────────────────────────────────

const TSA_RULES: Rule[] = [
  presence({
    id: "MNA-055",
    name: "Transition services scope / schedule",
    description: "TSA must include a scope schedule listing the services being provided.",
    citation: maPractice(
      "tsa-scope",
      "TSA scope-schedule practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_TSA],
    missing_title: "Transition-services scope missing",
    missing_description: "No transition-services scope schedule was found.",
    explanation:
      "Without a scope schedule the TSA is unenforceable; standard pattern is a per-service line in Schedule A.",
    recommendation: "Add a 'Schedule of Services' enumerating each service, duration, and fee.",
    present_patterns: [
      /transition\s+services/i,
      /schedule\s+(of\s+)?services/i,
      /service\s+description/i,
    ],
  }),
  presence({
    id: "MNA-056",
    name: "Service period and extension mechanic",
    description: "TSA must specify duration of services and any extension rights.",
    citation: maPractice(
      "tsa-period",
      "TSA service-period practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_TSA],
    missing_title: "Service period clause missing",
    missing_description: "No service-period clause was found.",
    explanation:
      "Standard pattern: 6–12 month service period with limited extension at buyer's option.",
    recommendation: "Add 'Service Period' with default term + extension trigger + extension limit.",
    present_patterns: [/service\s+period/i, /extension/i, /\d+\s+months?\s+from\s+closing/i],
  }),
  presence({
    id: "MNA-057",
    name: "Fees and pricing — cost-plus, fixed-fee, or hybrid",
    description: "TSA must specify fee structure.",
    citation: maPractice(
      "tsa-fees",
      "TSA fee-structure practice (cost-plus, fixed, hybrid)",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_TSA],
    missing_title: "Fees / pricing clause missing",
    missing_description: "No fee / pricing clause was found.",
    explanation: "Cost-plus (~5–10% markup) is typical for affiliate services post-closing.",
    recommendation: "Add 'Fees' specifying cost basis + markup or fixed fee per service.",
    present_patterns: [
      /(fees?|fee\s+schedule)/i,
      /(cost.plus|fully.loaded\s+cost|markup)/i,
      /monthly\s+fee/i,
    ],
  }),
  presence({
    id: "MNA-058",
    name: "Service-level / performance standards",
    description:
      "TSA should specify the performance standard (same as provided pre-closing; reasonable efforts).",
    citation: maPractice(
      "tsa-slas",
      "TSA service-level practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_TSA],
    missing_title: "Service-level standard clause missing",
    missing_description: "No service-level standard clause was found.",
    explanation: "Standard: services provided in substantially the same manner as before closing.",
    recommendation: "Add 'Performance Standards' tying performance to pre-closing baseline.",
    present_patterns: [
      /service\s+level/i,
      /(substantially\s+the\s+same|same\s+manner).{0,40}(prior|before)/is,
      /reasonable\s+(commercial\s+)?efforts/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-059",
    name: "Limitation of liability (one-times-fees cap baseline)",
    description: "TSAs typically cap provider liability at fees paid in a defined period.",
    citation: maPractice(
      "tsa-liability",
      "TSA liability-cap practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_TSA],
    missing_title: "Liability cap clause missing",
    missing_description: "No liability cap was found.",
    explanation:
      "Standard cap: fees paid in the preceding 6–12 months, with carve-outs for IP infringement, confidentiality breach, and gross negligence / willful misconduct.",
    recommendation: "Add 'Limitation of Liability' with cap and standard carve-outs.",
    present_patterns: [
      /limitation\s+of\s+liability/i,
      /(cap|aggregate\s+liability)/i,
      /(consequential|indirect)\s+damages/i,
    ],
  }),
  presence({
    id: "MNA-060",
    name: "Confidentiality and data protection",
    description:
      "TSAs handle ongoing personal / business data; confidentiality and (where applicable) GDPR / state-privacy treatment is required.",
    citation: maPractice(
      "tsa-confidentiality",
      "TSA confidentiality / data-protection practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_TSA],
    missing_title: "Confidentiality / data-protection clause missing",
    missing_description: "No confidentiality or data-protection clause was found.",
    explanation:
      "Service provider necessarily handles confidential data and may process personal data triggering DPA obligations.",
    recommendation:
      "Add 'Confidentiality and Data Protection' incorporating a DPA where personal data is processed.",
    present_patterns: [/confidential/i, /data\s+protection/i, /\bdpa\b/i],
  }),
  presence({
    id: "MNA-061",
    name: "Termination of services",
    description:
      "TSA should specify per-service termination (buyer can early-terminate individual services).",
    citation: maPractice(
      "tsa-termination",
      "TSA termination practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_TSA],
    missing_title: "Termination clause missing",
    missing_description: "No termination clause was found.",
    explanation:
      "Buyers typically reserve the right to terminate services on 30 days' notice as they stand up their own capability.",
    recommendation:
      "Add 'Termination' allowing buyer-initiated per-service termination on 30 days' notice and termination for material breach.",
    present_patterns: [
      /termin(ate|ation)/i,
      /(thirty|30)\s+days?\s+(prior\s+)?(written\s+)?notice/i,
    ],
  }),
  presence({
    id: "MNA-062",
    name: "Cooperation / transition assistance",
    description:
      "TSA should include cooperation covenant: provider helps buyer stand up its own capability before the service ends.",
    citation: maPractice(
      "tsa-cooperation",
      "TSA cooperation / migration assistance practice",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [MA_PLAYBOOK_TSA],
    missing_title: "Cooperation / migration clause missing",
    missing_description: "No cooperation clause was found.",
    explanation:
      "Practical baseline: provider transfers documentation, runbooks, data, and provides reasonable migration assistance.",
    recommendation:
      "Add 'Cooperation and Migration' with documentation transfer, data transfer, and reasonable assistance.",
    present_patterns: [/cooperation/i, /migration\s+assistance/i, /transition\s+assistance/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// D.8 — Earnout Agreement. 9 rules: MNA-063..MNA-071.
// ────────────────────────────────────────────────────────────────────

const EARNOUT_RULES: Rule[] = [
  presence({
    id: "MNA-063",
    name: "Earnout period and milestones defined",
    description: "Earnout must define period and specific, measurable milestones.",
    citation: delawareEarnoutCases(),
    playbooks: [MA_PLAYBOOK_EARNOUT],
    missing_title: "Earnout period / milestones clause missing",
    missing_description: "No earnout period or milestones clause was found.",
    explanation:
      "Delaware Chancery (*Aveta / Lazard*) emphasizes specificity to avoid 'implied covenant' fights post-closing.",
    recommendation:
      "Add 'Earnout Period' and 'Milestones' with measurable financial or operational triggers.",
    present_patterns: [/earnout\s+period/i, /milestone/i, /performance\s+target/i],
  }),
  presence({
    id: "MNA-064",
    name: "Definition of 'Revenue' / 'EBITDA' for earnout",
    description: "Earnouts based on revenue / EBITDA must define those metrics precisely.",
    citation: delawareEarnoutCases(),
    playbooks: [MA_PLAYBOOK_EARNOUT],
    missing_title: "Revenue / EBITDA definition clause missing",
    missing_description: "No revenue / EBITDA definition was found.",
    explanation:
      "Ambiguity here is the most common source of earnout litigation. Define accounting principles and any adjustments.",
    recommendation:
      "Add definitions of 'Revenue' / 'EBITDA' tied to GAAP, with stated adjustments and excluded items.",
    present_patterns: [
      /(revenue|ebitda|adjusted\s+ebitda)/i,
      /(gaap|generally\s+accepted\s+accounting)/i,
    ],
  }),
  presence({
    id: "MNA-065",
    name: "Conduct-of-business covenant during earnout period",
    description:
      "Buyer should covenant to operate the business in a way consistent with achieving earnout milestones.",
    citation: delawareEarnoutCases(),
    playbooks: [MA_PLAYBOOK_EARNOUT],
    missing_title: "Conduct-of-business covenant missing",
    missing_description: "No conduct-of-business covenant was found.",
    explanation:
      "*Lazard* and *Aveta* litigated whether buyer's post-closing conduct frustrated the earnout. Explicit covenant (commercially-reasonable efforts to maximize earnout, no actions intended to reduce earnout) preempts the dispute.",
    recommendation:
      "Add 'Conduct of Business' with a chosen efforts standard (commercially reasonable / good faith) and a 'no actions intended to reduce earnout' covenant.",
    present_patterns: [
      /(conduct\s+of\s+(the\s+)?business|operate.{0,40}business).{0,80}earnout/is,
      /(commercially\s+reasonable|good\s+faith).{0,80}earnout/is,
      /no\s+action.{0,40}intended\s+to.{0,40}(reduce|frustrate)/is,
    ],
  }),
  presence({
    id: "MNA-066",
    name: "Implied covenant — express acknowledgment or waiver",
    description:
      "Delaware *Lazard* held that the implied covenant cannot be waived; the agreement should not purport to do so.",
    citation: delawareEarnoutCases(),
    playbooks: [MA_PLAYBOOK_EARNOUT],
    missing_title: "Implied-covenant acknowledgment missing",
    missing_description:
      "No acknowledgment of the implied covenant of good faith and fair dealing was found.",
    explanation:
      "*Lazard v. Qinetiq* affirms that the implied covenant remains in earnouts despite express conduct covenants. Some agreements affirmatively reference it as a backstop.",
    recommendation:
      "Add an acknowledgment that the implied covenant of good faith and fair dealing applies (or, if buyer is comfortable, an express disclaimer of implied earnout-maximization duties — knowing it will not waive the covenant under *Lazard*).",
    present_patterns: [/implied\s+covenant/i, /good\s+faith\s+and\s+fair\s+dealing/i],
    default_severity: "warning",
  }),
  language({
    id: "MNA-067",
    name: "Disclaimer of obligation to maximize earnout",
    description:
      "Disclaimers of any duty to maximize the earnout will not survive — *Lazard* still applies.",
    citation: delawareEarnoutCases(),
    playbooks: [MA_PLAYBOOK_EARNOUT],
    bad_patterns: [
      /(no\s+(duty|obligation)\s+to\s+(maximize|increase).{0,40}earnout)/is,
      /buyer\s+(may|shall)\s+operate.{0,40}sole\s+discretion.{0,80}earnout/is,
    ],
    bad_title: "Disclaimer of earnout-maximization duty flagged",
    bad_description:
      "The agreement disclaims any obligation to maximize the earnout, which Delaware courts will not enforce as a complete shield.",
    explanation:
      "*Lazard / Aveta* hold the implied covenant remains operative; disclaimers do not eliminate it.",
    recommendation: "Replace blanket disclaimers with a defined efforts standard.",
    default_severity: "warning",
  }),
  presence({
    id: "MNA-068",
    name: "Earnout calculation and payment mechanics",
    description:
      "Earnout must specify calculation, statement-delivery, dispute, and payment timing.",
    citation: delawareEarnoutCases(),
    playbooks: [MA_PLAYBOOK_EARNOUT],
    missing_title: "Calculation / payment mechanics missing",
    missing_description: "No calculation or payment mechanics clause was found.",
    explanation:
      "Practitioner baseline: buyer delivers Earnout Statement within X days of period end; seller has Y days to object; disputes resolved by independent accountant.",
    recommendation:
      "Add 'Calculation Mechanics' with statement delivery, objection, dispute resolution, and payment timing.",
    present_patterns: [
      /earnout\s+(statement|notice|payment)/i,
      /independent\s+accountant/i,
      /objection\s+notice/i,
    ],
  }),
  presence({
    id: "MNA-069",
    name: "Right of set-off against earnout",
    description: "Earnout often includes a right of set-off against indemnification obligations.",
    citation: dealPoints("earnout-setoff", "Earnout set-off practice"),
    playbooks: [MA_PLAYBOOK_EARNOUT],
    missing_title: "Set-off clause missing",
    missing_description: "No set-off clause was found.",
    explanation:
      "Buyers commonly negotiate a right to set off indemnifiable claims against earnout payments — protective and reduces collection friction.",
    recommendation:
      "Add a 'Right of Set-Off' clause tied to indemnification claims (with reasonable-good-faith standard).",
    present_patterns: [/set.off/i],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-070",
    name: "Acceleration on change of control",
    description:
      "Earnout should address acceleration if buyer undergoes a subsequent change of control.",
    citation: dealPoints("earnout-acceleration", "Earnout acceleration practice"),
    playbooks: [MA_PLAYBOOK_EARNOUT],
    missing_title: "Change-of-control acceleration clause missing",
    missing_description: "No change-of-control acceleration clause was found.",
    explanation:
      "Seller-protective: if buyer is acquired before earnout payment, the remaining unpaid earnout accelerates at maximum.",
    recommendation:
      "Add 'Acceleration on Change of Control' specifying that buyer's change of control triggers acceleration of the remaining earnout at maximum (or per-period max).",
    present_patterns: [/accelerat(e|ion).{0,80}change\s+of\s+control/is],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-071",
    name: "Tax treatment of earnout (imputed interest)",
    description: "Earnouts can trigger imputed-interest treatment under IRC § 483 / § 1274.",
    citation: maPractice(
      "irc-483",
      "26 U.S.C. § 483 / § 1274 — imputed interest on deferred payments",
      "https://www.law.cornell.edu/uscode/text/26",
    ),
    playbooks: [MA_PLAYBOOK_EARNOUT],
    missing_title: "Tax-treatment clause missing",
    missing_description: "No tax-treatment clause was found.",
    explanation:
      "Deferred earnout payments without stated interest can trigger IRC § 483 / § 1274 imputed-interest treatment; the parties typically allocate the interest component.",
    recommendation: "Add 'Tax Treatment' addressing imputed interest under IRC § 483 / § 1274.",
    present_patterns: [/(section\s+483|section\s+1274|imputed\s+interest)/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// D.9 — M&A Restrictive Covenant. 9 rules: MNA-072..MNA-080.
// ────────────────────────────────────────────────────────────────────

const MA_RESTRICTIVE_COVENANT_RULES: Rule[] = [
  presence({
    id: "MNA-072",
    name: "Sale-of-business identification (goodwill nexus)",
    description:
      "Restrictive covenants must be tied to the sale of a business to qualify for the state-law sale-of-business exceptions (e.g., Cal. Bus. & Prof. Code § 16601).",
    citation: ftcNcr(),
    playbooks: [MA_PLAYBOOK_MA_RC],
    missing_title: "Sale-of-business recital missing",
    missing_description:
      "No sale-of-business recital was found tying the covenants to the transaction's goodwill.",
    explanation:
      "State sale-of-business exceptions (e.g., Cal. Bus. & Prof. Code § 16601) preserve non-competes made in connection with a bona fide sale of a business and its goodwill. Without that nexus, the covenant is judged under the far stricter employee-covenant rules and may be void.",
    recommendation: "Add a recital identifying the sale of the business / acquisition transaction.",
    present_patterns: [
      /sale\s+of\s+the\s+business/i,
      /acquisition\s+(of|by)/i,
      /goodwill\s+of\s+the\s+(business|company)/i,
    ],
  }),
  presence({
    id: "MNA-073",
    name: "Non-compete duration stated and bounded",
    description:
      "Non-compete duration should be stated and within enforceability norms (typically 2–5 years for M&A sales).",
    citation: ftcNcr(),
    playbooks: [MA_PLAYBOOK_MA_RC],
    missing_title: "Non-compete duration missing",
    missing_description: "No duration was specified for the non-compete obligation.",
    explanation:
      "Even M&A sale-of-business non-competes need a bounded duration; 'forever' is unenforceable in most states.",
    recommendation: "Add 'Duration' specifying the non-compete period (typically 3–5 years).",
    present_patterns: [
      /non.?compete.{0,80}(\d{1,2})\s+years?/is,
      /(\d{1,2})\s+year.{0,40}non.?compete/is,
      /restricted\s+period/i,
    ],
  }),
  language({
    id: "MNA-074",
    name: "Non-compete > 5 years flagged",
    description: "Most states will not enforce sale-of-business non-competes longer than 5 years.",
    citation: maPractice(
      "non-compete-duration",
      "State court treatment of M&A non-competes (3–5 year norm)",
      "https://www.americanbar.org/",
    ),
    playbooks: [MA_PLAYBOOK_MA_RC],
    bad_patterns: [
      // The year count must be the covenant's DURATION, not merely a number
      // sharing a sentence with it — "the Company has 10 years of history
      // supporting the restricted period" is not a 10-year non-compete.
      /(?:non.?compete|non.?competition|restricted\s+period)[^.]{0,40}(?:of|shall\s+be|is|are|equal\s+to|not\s+exceed(?:ing)?)\s+(?:a\s+period\s+of\s+)?([6-9]|1[0-9])\s+years?/is,
      /(?:for|of)\s+(?:a\s+)?(?:period\s+of\s+)?([6-9]|1[0-9])\s+years?[^.]{0,40}(?:non.?compete|non.?competition|restricted\s+period|shall\s+not\s+compete)/is,
      /([6-9]|1[0-9])[\s-]*year\s+(?:non.?compete|non.?competition|restricted\s+period)/is,
    ],
    bad_title: "Non-compete duration appears > 5 years",
    bad_description:
      "The non-compete period exceeds 5 years, beyond the norm for M&A sale-of-business covenants.",
    explanation:
      "Periods above 5 years are commonly struck or blue-penciled. Drafters should justify under state law if longer.",
    recommendation: "Limit the non-compete to 3–5 years.",
    default_severity: "warning",
  }),
  presence({
    id: "MNA-075",
    name: "Geographic scope stated",
    description: "Non-compete must specify geographic scope.",
    citation: maPractice(
      "non-compete-geography",
      "Sale-of-business non-compete geographic scope practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [MA_PLAYBOOK_MA_RC],
    missing_title: "Geographic scope missing",
    missing_description: "No geographic scope clause was found.",
    explanation:
      "Open-ended geographic scope is unenforceable; scope should track the business's actual market.",
    recommendation: "Add 'Geographic Scope' specifying countries / states / counties.",
    present_patterns: [
      /(geographic|territory|scope).{0,80}(state|country|county|nation)/is,
      /worldwide/i,
      /united\s+states/i,
    ],
  }),
  presence({
    id: "MNA-076",
    name: "Activity scope (Competing Business defined)",
    description: "Non-compete must define what counts as Competing Business.",
    citation: maPractice(
      "non-compete-activity",
      "Sale-of-business non-compete activity-scope practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [MA_PLAYBOOK_MA_RC],
    missing_title: "Competing-Business definition missing",
    missing_description: "No Competing Business definition was found.",
    explanation: "Without a defined activity scope, the non-compete is overbroad.",
    recommendation:
      "Add a defined 'Competing Business' tied to the acquired business's product / service lines.",
    present_patterns: [/competing\s+business/i, /restricted\s+business/i],
  }),
  presence({
    id: "MNA-077",
    name: "Non-solicit of customers",
    description: "Non-solicit-of-customers covenant should be present.",
    citation: maPractice(
      "non-solicit-customer",
      "Sale-of-business customer non-solicit practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [MA_PLAYBOOK_MA_RC],
    missing_title: "Customer non-solicit clause missing",
    missing_description: "No customer non-solicit clause was found.",
    explanation:
      "Even where non-competes face state-law scrutiny, customer non-solicits are widely enforced.",
    recommendation:
      "Add 'Non-Solicitation of Customers' covering customers of the acquired business.",
    present_patterns: [/non.?solicit.{0,40}customers?/is, /not\s+to\s+solicit.{0,40}customers?/is],
  }),
  presence({
    id: "MNA-078",
    name: "Non-solicit of employees",
    description: "Employee non-solicit (no-poach) should be present.",
    citation: maPractice(
      "non-solicit-employee",
      "Sale-of-business employee non-solicit practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [MA_PLAYBOOK_MA_RC],
    missing_title: "Employee non-solicit clause missing",
    missing_description: "No employee non-solicit clause was found.",
    explanation: "Standard for M&A restrictive-covenant agreements with key sellers.",
    recommendation: "Add 'Non-Solicitation of Employees' for a defined period.",
    present_patterns: [/non.?solicit.{0,40}employees?/is, /no.?(hire|poach)/i],
  }),
  presence({
    id: "MNA-079",
    name: "Blue-pencil / reformation clause",
    description: "Restrictive-covenant agreement should empower courts to reform overbroad terms.",
    citation: maPractice(
      "blue-pencil",
      "Blue-pencil and reformation doctrine (state-law variant)",
      "https://www.americanbar.org/",
    ),
    playbooks: [MA_PLAYBOOK_MA_RC],
    missing_title: "Blue-pencil / reformation clause missing",
    missing_description: "No blue-pencil / reformation clause was found.",
    explanation:
      "Reformation is permissive in many states; a blue-pencil clause increases the chance of partial enforcement if the original terms are overbroad.",
    recommendation:
      "Add a 'Reformation' clause authorizing a court to modify any overbroad covenant to the maximum enforceable scope.",
    present_patterns: [/blue.?pencil/i, /reformation/i, /maximum\s+enforceable/i],
    default_severity: "warning",
  }),
  presence({
    id: "MNA-080",
    name: "Equitable relief and remedies",
    description:
      "Damages are usually inadequate; agreement should authorize injunctive relief without bond.",
    citation: maPractice(
      "equitable-remedies",
      "Standard equitable-relief / injunction practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [MA_PLAYBOOK_MA_RC],
    missing_title: "Equitable-remedies clause missing",
    missing_description: "No equitable-remedies clause was found.",
    explanation:
      "Breach of restrictive covenants causes irreparable harm; injunctive relief is the meaningful remedy.",
    recommendation:
      "Add 'Equitable Remedies' acknowledging irreparable harm and authorizing injunctive / specific-performance relief without bond.",
    present_patterns: [/injunctive\s+relief/i, /specific\s+performance/i, /irreparable/i],
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate.
// ────────────────────────────────────────────────────────────────────

export const M_AND_A_RULES: Rule[] = [
  ...LOI_TERM_SHEET_RULES,
  ...SPA_RULES,
  ...APA_RULES,
  ...MERGER_RULES,
  ...DISCLOSURE_SCHEDULE_RULES,
  ...ESCROW_AGREEMENT_RULES,
  ...TSA_RULES,
  ...EARNOUT_RULES,
  ...MA_RESTRICTIVE_COVENANT_RULES,
];

export {
  LOI_TERM_SHEET_RULES,
  SPA_RULES,
  APA_RULES,
  MERGER_RULES,
  DISCLOSURE_SCHEDULE_RULES,
  ESCROW_AGREEMENT_RULES,
  TSA_RULES,
  EARNOUT_RULES,
  MA_RESTRICTIVE_COVENANT_RULES,
};
