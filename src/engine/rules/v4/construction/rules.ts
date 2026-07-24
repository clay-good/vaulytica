/**
 * v4 Construction ruleset — 30 rules
 * (spec-v4.md §6.M, Step 56).
 *
 * Five new playbooks (M.1–M.5). Citations anchor to AIA A101 / A201 /
 * G701, state mechanic's-lien codes, Miller Act + state Little Miller
 * Acts, and Cal. Civ. § 2782 construction anti-indemnity.
 *
 * Rule ids are flat `CON-NNN` (001..030).
 */

import type { Rule } from "../../../finding.js";
import { buildV4PresenceRule, type V4PresenceSpec } from "../_helpers.js";
import {
  CON_PLAYBOOK_CONTRACT,
  CON_PLAYBOOK_SUBCONTRACTOR,
  CON_PLAYBOOK_LIEN_WAIVER,
  CON_PLAYBOOK_BOND,
  CON_PLAYBOOK_CHANGE_ORDER,
  aia,
  millerAct,
  littleMiller,
  mechanicsLien,
  caLienWaiver,
  caCiv2782,
  conPractice,
} from "./_helpers.js";

const CATEGORY = "construction";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// M.1 — Construction contract (AIA-style). 7 rules: CON-001..CON-007.
// ────────────────────────────────────────────────────────────────────

const CONSTRUCTION_CONTRACT_RULES: Rule[] = [
  presence({
    id: "CON-001",
    name: "Owner / contractor / architect identified",
    description:
      "Construction contract must identify owner, contractor, and (if applicable) architect.",
    citation: aia("A101", "Owner-Contractor Agreement (Stipulated Sum)"),
    playbooks: [CON_PLAYBOOK_CONTRACT],
    missing_title: "Owner / contractor / architect clause missing",
    missing_description: "No clause was found identifying owner, contractor, and architect.",
    explanation:
      "AIA A101 / A201 contemplate owner, contractor, and architect as the three principal parties. Without identification the General Conditions cannot apply.",
    recommendation:
      "Add 'Parties' clause identifying owner, contractor, and architect with addresses and licenses.",
    present_patterns: [/owner/i, /contractor/i, /(architect|design\s+professional)/i],
  }),
  presence({
    id: "CON-002",
    name: "Scope of work / contract documents",
    description:
      "Contract must define the scope of work and incorporate the contract documents (drawings, specs, addenda).",
    citation: aia("A201", "General Conditions"),
    playbooks: [CON_PLAYBOOK_CONTRACT],
    missing_title: "Scope of work / contract documents clause missing",
    missing_description: "No scope-of-work or contract-documents clause was found.",
    explanation:
      "AIA A201 § 1.1.1 defines the Contract Documents (Agreement + Conditions + Drawings + Specifications + addenda + Modifications). Without enumeration the contract is ambiguous.",
    recommendation:
      "Add 'Scope of Work' and 'Contract Documents' enumerating drawings, specifications, addenda, and modifications.",
    present_patterns: [
      /(scope\s+of\s+(the\s+)?work|work\s+to\s+be\s+performed)/i,
      /(contract\s+documents|drawings\s+and\s+specifications|specifications)/i,
    ],
  }),
  presence({
    id: "CON-003",
    name: "Contract sum + price / payment terms",
    description:
      "Contract must state contract sum (stipulated sum / GMP / cost-plus) and progress payments.",
    citation: aia("A101", "Contract Sum / Payment"),
    playbooks: [CON_PLAYBOOK_CONTRACT],
    missing_title: "Contract sum / payment terms clause missing",
    missing_description: "No contract-sum or payment-terms clause was found.",
    explanation:
      "AIA A101 §§ 4–5 require the contract sum and progress-payment schedule. The pricing model (stipulated / GMP / cost-plus) drives change-order treatment.",
    recommendation:
      "Add 'Contract Sum' (stipulated / GMP / cost-plus) and 'Progress Payments' with retainage and timing.",
    present_patterns: [
      /(contract\s+sum|stipulated\s+sum|guaranteed\s+maximum\s+price|gmp|cost.plus)/i,
      /(progress\s+payments?|payment\s+(schedule|terms))/i,
    ],
  }),
  presence({
    id: "CON-004",
    name: "Time of completion + liquidated damages",
    description:
      "Contract must establish time of completion (commencement + substantial completion + final completion) and liquidated-damages if applicable.",
    citation: aia("A101", "Date of Substantial Completion"),
    playbooks: [CON_PLAYBOOK_CONTRACT],
    missing_title: "Time / completion / LD clause missing",
    missing_description: "No time-of-completion or liquidated-damages clause was found.",
    explanation:
      "AIA A101 § 3 requires dates for commencement, substantial completion, and final completion. Schedule slip drives most disputes; liquidated damages are common where the owner has measurable delay damages.",
    recommendation:
      "Add 'Time of Completion' with commencement, substantial completion, and final completion dates; add 'Liquidated Damages' (or expressly waive).",
    present_patterns: [
      /(substantial\s+completion|final\s+completion|completion\s+date)/i,
      /(liquidated\s+damages|delay\s+damages|no\s+damages\s+for\s+delay)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "CON-005",
    name: "Differing site conditions clause",
    description:
      "Contract should address differing site conditions (Type I — concealed conditions; Type II — unknown conditions).",
    citation: aia("A201", "Concealed or Unknown Conditions"),
    playbooks: [CON_PLAYBOOK_CONTRACT],
    missing_title: "Differing-site-conditions clause missing",
    missing_description: "No differing-site-conditions clause was found.",
    explanation:
      "AIA A201 § 3.7.4 addresses concealed conditions different from those indicated in the Contract Documents OR materially unusual for the work. Without it, contractor bears the risk of unforeseen conditions.",
    recommendation:
      "Add 'Concealed or Unknown Conditions' permitting contract adjustment when conditions materially differ.",
    present_patterns: [
      /(differing\s+site\s+conditions|concealed\s+conditions|unknown\s+conditions)/i,
      /(materially\s+(differ|unusual)|hidden\s+conditions)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "CON-006",
    name: "Indemnification + insurance + waiver of subrogation",
    description:
      "Contract must include indemnification, insurance requirements, and waiver-of-subrogation provisions consistent with state anti-indemnity statutes.",
    citation: caCiv2782(),
    playbooks: [CON_PLAYBOOK_CONTRACT],
    missing_title: "Indemnification / insurance / waiver clause missing",
    missing_description: "No indemnification / insurance / waiver-of-subrogation clause was found.",
    explanation:
      "AIA A201 §§ 3.18 (indemnification) + 11 (insurance) provide the standard pattern. State anti-indemnity statutes (CA Civ. § 2782, NY Gen. Oblig. § 5-322.1, TX Ins. § 151) void indemnity for owner's own / sole negligence.",
    recommendation:
      "Add 'Indemnification' carving out indemnitee's sole / active negligence, 'Insurance' with limits + AI endorsement, and 'Waiver of Subrogation'.",
    present_patterns: [
      /(indemnif(y|ies|ied|ication))/i,
      /(insurance|cgl|workers?\s+compensation)/i,
      /(waiver\s+of\s+subrogation)/i,
    ],
  }),
  presence({
    id: "CON-007",
    name: "Termination — convenience + cause",
    description: "Contract must include termination for cause AND termination for convenience.",
    citation: aia("A201", "Termination of the Contract"),
    playbooks: [CON_PLAYBOOK_CONTRACT],
    missing_title: "Termination clause missing",
    missing_description:
      "No termination-for-cause or termination-for-convenience clause was found.",
    explanation:
      "AIA A201 § 14 provides for termination by the owner for convenience and by either party for cause. Termination provisions drive both early-exit and dispute-resolution mechanics.",
    recommendation:
      "Add 'Termination for Cause' (with cure) and 'Termination for Convenience' (with overhead / profit on completed work).",
    present_patterns: [/termination/i, /(for\s+cause|for\s+convenience|notice\s+to\s+cure)/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// M.2 — Subcontractor agreement. 6 rules: CON-008..CON-013.
// ────────────────────────────────────────────────────────────────────

const SUBCONTRACTOR_RULES: Rule[] = [
  presence({
    id: "CON-008",
    name: "General contractor / subcontractor / project identified",
    description:
      "Subcontractor agreement must identify the general contractor, subcontractor, and underlying project.",
    citation: conPractice(
      "subk-baseline",
      "Subcontractor agreement — baseline (ConsensusDocs 750 / AIA A401)",
      "https://www.americanbar.org/groups/construction_industry/",
    ),
    playbooks: [CON_PLAYBOOK_SUBCONTRACTOR],
    missing_title: "GC / subk / project identification missing",
    missing_description: "No clause was found identifying the GC, subcontractor, and project.",
    explanation:
      "Subcontract rights depend on identification of the parties and incorporation of the prime contract by reference.",
    recommendation:
      "Add 'Parties' identifying general contractor, subcontractor, and the prime / underlying project.",
    present_patterns: [
      /(general\s+contractor|contractor)/i,
      /(subcontractor)/i,
      /(project|prime\s+contract|underlying)/i,
    ],
  }),
  presence({
    id: "CON-009",
    name: "Subcontract scope of work + flow-down",
    description:
      "Subcontract must define the scope of work and flow down obligations from the prime contract.",
    citation: aia("A401", "Subcontractor flow-down"),
    playbooks: [CON_PLAYBOOK_SUBCONTRACTOR],
    missing_title: "Subcontract scope / flow-down clause missing",
    missing_description: "No subcontract-scope or flow-down clause was found.",
    explanation:
      "AIA A401 § 1.1 binds subcontractor to GC's obligations to owner so far as applicable. Without flow-down, GC bears risk it could have transferred down.",
    recommendation:
      "Add 'Scope of Work' (with reference to prime drawings / specs) and 'Flow-Down' incorporating the prime contract.",
    present_patterns: [
      /(scope\s+of\s+(the\s+)?work|work\s+to\s+be\s+performed)/i,
      /(flow.?down|prime\s+contract|bound\s+to\s+owner)/i,
    ],
  }),
  presence({
    id: "CON-010",
    name: "Pay-when-paid vs pay-if-paid",
    description:
      "Subcontract should clearly distinguish pay-when-paid (timing) from pay-if-paid (condition precedent).",
    citation: conPractice(
      "pwp",
      "Pay-when-paid vs pay-if-paid — state-specific enforceability",
      "https://www.americanbar.org/groups/construction_industry/",
    ),
    playbooks: [CON_PLAYBOOK_SUBCONTRACTOR],
    missing_title: "Pay-when-paid / pay-if-paid clause missing",
    missing_description: "No clause was found addressing pay-when-paid vs pay-if-paid.",
    explanation:
      "Pay-if-paid (condition precedent) is unenforceable in many states (CA, NC, NY, WI, others); pay-when-paid (timing) is generally enforceable. Many subcontracts use the wrong language for the desired effect.",
    recommendation:
      "Pick the intended construct and use the matching language explicitly; expect courts to construe ambiguity against the GC.",
    present_patterns: [
      /(pay.?when.?paid|pay.?if.?paid)/i,
      /(condition\s+precedent|timing\s+mechanism)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "CON-011",
    name: "Schedule + coordination + cleanup",
    description:
      "Subcontract should address schedule, coordination with other subs, and daily cleanup.",
    citation: conPractice(
      "subk-schedule",
      "Subcontract schedule / coordination / cleanup baseline",
      "https://www.americanbar.org/groups/construction_industry/",
    ),
    playbooks: [CON_PLAYBOOK_SUBCONTRACTOR],
    missing_title: "Schedule / coordination / cleanup clause missing",
    missing_description: "No clause was found addressing schedule, coordination, or cleanup.",
    explanation:
      "Job-site coordination is the most common source of subcontractor disputes (interference, delay, cleanup). Standard practice requires subk to comply with GC schedule and clean daily.",
    recommendation:
      "Add 'Schedule and Coordination' incorporating GC schedule and 'Cleanup' requiring daily / progressive cleanup.",
    present_patterns: [
      /(schedule|sequence|progress)/i,
      /(coordinat|coordination)/i,
      /(cleanup|clean.?up|debris\s+removal)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "CON-012",
    name: "Subcontractor warranties + workmanship + materials",
    description:
      "Subcontract must include workmanship + materials warranties matching the prime contract.",
    citation: conPractice(
      "subk-warranty",
      "Subcontract warranty baseline",
      "https://www.americanbar.org/groups/construction_industry/",
    ),
    playbooks: [CON_PLAYBOOK_SUBCONTRACTOR],
    missing_title: "Warranty clause missing",
    missing_description: "No warranty clause was found.",
    explanation:
      "Implied warranties under state codes are typically supplemented by an express one-year (or as-specified) warranty on workmanship + materials.",
    recommendation:
      "Add 'Warranty' covering workmanship, materials, and conformance to drawings / specs, with a stated warranty period.",
    present_patterns: [
      /warrant/i,
      /(workmanship|materials|conformance)/i,
      /(one\s+year|1\s+year|period\s+of)/i,
    ],
  }),
  presence({
    id: "CON-013",
    name: "Dispute resolution + venue + governing law",
    description:
      "Subcontract must include dispute-resolution, venue, and governing-law provisions.",
    citation: conPractice(
      "subk-dispute",
      "Subcontract dispute-resolution baseline",
      "https://www.americanbar.org/groups/construction_industry/",
    ),
    playbooks: [CON_PLAYBOOK_SUBCONTRACTOR],
    missing_title: "Dispute-resolution / venue / law clause missing",
    missing_description: "No dispute-resolution / venue / governing-law clause was found.",
    explanation:
      "AIA / ConsensusDocs use arbitration or mediation-then-litigation. Venue / law clauses align with the prime to avoid two-court disputes.",
    recommendation:
      "Add 'Dispute Resolution' (mediation → arbitration / litigation), 'Venue', and 'Governing Law' clauses; consider conditioning on prime-contract election.",
    present_patterns: [
      /(dispute\s+resolution|mediation|arbitration|litigation)/i,
      /(venue|jurisdiction)/i,
      /(governing\s+law|choice\s+of\s+law)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// M.3 — Lien waiver. 6 rules: CON-014..CON-019.
// ────────────────────────────────────────────────────────────────────

const LIEN_WAIVER_RULES: Rule[] = [
  presence({
    id: "CON-014",
    name: "Waiver type — conditional / unconditional + progress / final",
    description: "Lien waiver must identify type: conditional vs unconditional, progress vs final.",
    citation: caLienWaiver("8132"),
    playbooks: [CON_PLAYBOOK_LIEN_WAIVER],
    missing_title: "Lien-waiver type clause missing",
    missing_description:
      "No clause was found identifying the waiver type (conditional vs unconditional, progress vs final).",
    explanation:
      "California § 8132 (conditional progress), § 8134 (unconditional progress), § 8136 (conditional final), and § 8138 (unconditional final) are statutory forms. Many states have similar restrictions on enforceable waiver forms.",
    recommendation:
      "Label the waiver clearly: 'Conditional Waiver and Release on Progress Payment' (or analogous) and use the state's prescribed form where required.",
    present_patterns: [
      /(conditional|unconditional)/i,
      /(progress|final)/i,
      /(waiver\s+and\s+release|lien\s+waiver)/i,
    ],
  }),
  presence({
    id: "CON-015",
    name: "Identified claimant + property + project",
    description:
      "Lien waiver must identify the claimant, the property / project, and the through-date / payment amount.",
    citation: mechanicsLien(),
    playbooks: [CON_PLAYBOOK_LIEN_WAIVER],
    missing_title: "Claimant / property / through-date clause missing",
    missing_description:
      "No clause was found identifying the claimant, property, or through-date / payment amount.",
    explanation:
      "Statutory lien-waiver forms (CA § 8132–8138; TX § 53.281 et seq.) require identification of the claimant, customer, owner, property, through-date, and (for unconditional) the payment amount.",
    recommendation:
      "Add 'Claimant', 'Customer', 'Owner', 'Property / Project', 'Through Date', and 'Amount' fields.",
    present_patterns: [
      /(claimant|undersigned|subcontractor)/i,
      /(property|project|job)/i,
      /(through\s+(the\s+)?date|payment\s+amount|amount\s+of\s+\$)/i,
    ],
  }),
  presence({
    id: "CON-016",
    name: "Scope of waiver — limited to amount received / through-date",
    description:
      "Waiver must limit its effect to the amount actually received and through the stated date.",
    citation: caLienWaiver("8132"),
    playbooks: [CON_PLAYBOOK_LIEN_WAIVER],
    missing_title: "Scope-of-waiver clause missing",
    missing_description:
      "No clause was found limiting the waiver to the amount received and through-date.",
    explanation:
      "California statutory forms expressly limit the waiver to the dollar amount received and to work through a stated date — otherwise the waiver can be argued to extend beyond payments actually made.",
    recommendation:
      "Add 'Scope' limiting the waiver to the amount paid and through the through-date specified.",
    present_patterns: [/(amount\s+of\s+\$|through\s+(the\s+)?date)/i, /(waives?|releases?)/i],
  }),
  presence({
    id: "CON-017",
    name: "Conditional waiver — payment condition",
    description: "Conditional waivers must condition effectiveness on actual receipt of payment.",
    citation: caLienWaiver("8132"),
    playbooks: [CON_PLAYBOOK_LIEN_WAIVER],
    missing_title: "Conditional-waiver payment-condition clause missing",
    missing_description:
      "No clause conditioning a conditional waiver on payment receipt was found.",
    explanation:
      "Conditional waivers are only effective if the claimant actually receives the conditional payment; the form must include the 'this document does not affect any of the following' carve-out and the 'conditional' qualifier.",
    recommendation:
      "Add 'Condition' language stating the waiver is effective only upon claimant's receipt of payment (and identify the form of payment — joint check, bank wire, etc.).",
    present_patterns: [
      /(condition(al)?|upon\s+(actual\s+)?receipt)/i,
      /(payment|joint\s+check|wire)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "CON-018",
    version: "1.1.0",
    name: "Carve-outs — disputed claims / future rights",
    description:
      "Waiver should preserve carve-outs for retention, disputed claims, items not within waiver, and future rights.",
    citation: caLienWaiver("8132"),
    playbooks: [CON_PLAYBOOK_LIEN_WAIVER],
    missing_title: "Carve-outs clause missing",
    missing_description:
      "No carve-outs clause was found for disputed claims / retention / future rights.",
    explanation:
      "Statutory forms allow listing of disputed claims / extra work / retention that are NOT waived. Omitting carve-outs can waive valid claims inadvertently.",
    recommendation:
      "Add 'Exclusions / Carve-Outs' listing retention, disputed claims, extras / change orders, and items not included in the waiver amount.",
    present_patterns: [
      // A carve-out/exclusion counts only when it is ASSERTED, not denied.
      // "this waiver contains NO carve-out for disputed claims" is the
      // overbroad unconditional waiver this rule flags, so a negative
      // lookbehind excludes the "no/without carve-out|exclusion" denial while
      // keeping a genuine "expressly carved out" / "excludes disputed claims"
      // (the fake-carve-out false-negative class).
      /(?<!\b(?:no|not|without|any)\s)(?:disputed\s+claim|exclusion|carve.?out)/i,
      /(?<!\b(?:no|not|without|any)\s)(?:retention|retainage|change\s+order|extras?)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "CON-019",
    name: "Signature + date + statutory form recital",
    description:
      "Lien waiver must be signed and dated; in states using prescribed forms, the form recital must appear verbatim.",
    citation: caLienWaiver("8132"),
    playbooks: [CON_PLAYBOOK_LIEN_WAIVER],
    missing_title: "Signature / form recital missing",
    missing_description: "No signature / date / statutory-form recital was found.",
    explanation:
      "California § 8132 (and analogous statutes) require the lien waiver to follow the statutory form to be valid; the form must include specific notice language about the effect of the waiver.",
    recommendation:
      "Use the state-prescribed form text verbatim where required; add signature + date + claimant title.",
    present_patterns: [
      /(signature|signed|dated)/i,
      /(notice|warning|important)/i,
      /(this\s+document|the\s+claimant)/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// M.4 — Payment / performance bond. 6 rules: CON-020..CON-025.
// ────────────────────────────────────────────────────────────────────

const BOND_RULES: Rule[] = [
  presence({
    id: "CON-020",
    name: "Principal / surety / obligee identification",
    description: "Bond must identify principal, surety, and obligee.",
    citation: millerAct(),
    playbooks: [CON_PLAYBOOK_BOND],
    missing_title: "Principal / surety / obligee clause missing",
    missing_description: "No clause was found identifying principal, surety, and obligee.",
    explanation:
      "Bonds are tri-party instruments — principal (contractor), surety (bonding company), obligee (owner / claimants). Identification is essential for claim procedure.",
    recommendation: "Add 'Parties' identifying principal, surety (with NAIC number), and obligee.",
    present_patterns: [/(principal|contractor)/i, /surety/i, /(obligee|owner|government)/i],
  }),
  presence({
    id: "CON-021",
    name: "Bond type — payment / performance / dual-obligee",
    description: "Bond must clearly state whether it is a payment bond, performance bond, or dual.",
    citation: millerAct(),
    playbooks: [CON_PLAYBOOK_BOND],
    missing_title: "Bond-type clause missing",
    missing_description:
      "No clause was found identifying the bond as payment / performance / dual.",
    explanation:
      "Miller Act (federal) and state Little Miller Acts use separate payment and performance bonds. AIA A312 ships both. The type determines who can make a claim and the procedure.",
    recommendation:
      "Title the bond explicitly: 'Payment Bond' or 'Performance Bond' (or both, if dual).",
    present_patterns: [
      /(payment\s+bond|performance\s+bond)/i,
      /(aia\s+a312|miller\s+act|little\s+miller)/i,
    ],
  }),
  presence({
    id: "CON-022",
    name: "Penal sum",
    description: "Bond must state the penal sum (maximum surety liability).",
    citation: millerAct(),
    playbooks: [CON_PLAYBOOK_BOND],
    missing_title: "Penal sum clause missing",
    missing_description: "No penal-sum clause was found.",
    explanation:
      "Surety liability is capped at the penal sum; the bond must state it. Miller Act and Little Miller Acts require it.",
    recommendation: "Add 'Penal Sum' specifying the maximum surety obligation in dollars.",
    present_patterns: [/(penal\s+sum|sum\s+of\s+\$|in\s+the\s+penal\s+amount)/i, /\$\s*[\d,]+/],
  }),
  presence({
    id: "CON-023",
    name: "Underlying contract incorporation",
    description: "Bond must reference and incorporate the underlying construction contract.",
    citation: millerAct(),
    playbooks: [CON_PLAYBOOK_BOND],
    missing_title: "Underlying-contract incorporation clause missing",
    missing_description: "No clause was found incorporating the underlying construction contract.",
    explanation:
      "The bond's scope is defined by the underlying contract; that contract must be identified and incorporated.",
    recommendation:
      "Add 'Underlying Contract' identifying the construction contract by date / parties / project and incorporating it by reference.",
    present_patterns: [
      /(underlying\s+contract|construction\s+contract|incorporated\s+by\s+reference)/i,
      /(dated|date\s+of|project)/i,
    ],
  }),
  presence({
    id: "CON-024",
    name: "Claimant definition + notice procedure (payment bond)",
    description:
      "Payment bonds must define claimants and the notice / suit procedure (Miller Act 90-day / 1-year deadlines).",
    citation: millerAct(),
    playbooks: [CON_PLAYBOOK_BOND],
    missing_title: "Claimant / notice procedure clause missing",
    missing_description: "No clause was found defining claimants or the notice / suit procedure.",
    explanation:
      "Miller Act 40 U.S.C. § 3133: subcontractors without contractual privity with principal must give 90-day notice; suit must be filed within 1 year of last labor / materials. State Little Miller Acts vary but follow similar pattern.",
    recommendation:
      "Add 'Claimants' definition and 'Notice / Suit Procedure' with applicable 90-day notice and 1-year suit limit.",
    present_patterns: [
      /(claimant|persons\s+having\s+a\s+direct\s+contract|second.tier)/i,
      /(90\s+days?|ninety\s+days?|notice)/i,
      /(1\s+year|one\s+year|suit\s+limit)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "CON-025",
    name: "Performance-bond default + remedies",
    description:
      "Performance bond must specify default mechanics — declaration of default, surety options (complete / pay / tender).",
    citation: littleMiller(),
    playbooks: [CON_PLAYBOOK_BOND],
    missing_title: "Performance-bond default / remedies clause missing",
    missing_description: "No clause was found specifying performance-bond default mechanics.",
    explanation:
      "AIA A312 § 3 / § 5 prescribe owner notice → declaration of default → surety options (complete, tender new contractor, pay damages, or deny). Without this, owner-surety disputes follow.",
    recommendation:
      "Add 'Default and Surety Options' covering notice + declaration + surety's election among complete / tender / pay / deny.",
    present_patterns: [
      /(declaration\s+of\s+default|default)/i,
      /(complete|tender|surety\s+options)/i,
      /(notice|cure)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// M.5 — Change order. 5 rules: CON-026..CON-030.
// ────────────────────────────────────────────────────────────────────

const CHANGE_ORDER_RULES: Rule[] = [
  presence({
    id: "CON-026",
    name: "Original contract sum + revised contract sum",
    description:
      "Change order must reference the original contract sum and state the revised contract sum.",
    citation: aia("G701", "Change Order"),
    playbooks: [CON_PLAYBOOK_CHANGE_ORDER],
    missing_title: "Original / revised contract sum clause missing",
    missing_description: "No clause was found stating original / revised contract sum.",
    explanation:
      "AIA G701 § 5 requires the four-line summary: original contract sum, net change by previously authorized CO, contract sum prior to this CO, sum of this CO, new contract sum.",
    recommendation:
      "Add the four-line price summary running from original contract sum to revised contract sum.",
    present_patterns: [
      /(original\s+contract\s+sum)/i,
      /(revised\s+contract\s+sum|new\s+contract\s+sum)/i,
      /\$\s*[\d,]+/,
    ],
  }),
  presence({
    id: "CON-027",
    name: "Description of change in work",
    description:
      "Change order must describe the change in work (added, deleted, or modified items).",
    citation: aia("G701", "Change description"),
    playbooks: [CON_PLAYBOOK_CHANGE_ORDER],
    missing_title: "Description-of-change clause missing",
    missing_description: "No clause was found describing the change in work.",
    explanation:
      "AIA G701 § 1 requires a description of the change; without it the CO is ambiguous and likely unenforceable.",
    recommendation:
      "Add 'Description of Change' enumerating added / deleted / modified scope items.",
    present_patterns: [
      /(description\s+of\s+(the\s+)?change|change\s+in\s+(the\s+)?work)/i,
      /(add(ed|ition)|delete(d)?|modif(y|ies|ied))/i,
    ],
  }),
  presence({
    id: "CON-028",
    name: "Time impact — contract time adjustment",
    description: "Change order must address contract-time adjustment (or expressly state none).",
    citation: aia("G701", "Time adjustment"),
    playbooks: [CON_PLAYBOOK_CHANGE_ORDER],
    missing_title: "Time-adjustment clause missing",
    missing_description: "No clause addressing contract-time adjustment was found.",
    explanation:
      "AIA G701 § 4 requires the new contract time / date of substantial completion. Latent time impacts of accumulated COs are a major source of delay claims.",
    recommendation:
      "Add 'Contract Time' stating the time adjustment (in days) or that there is none, and the new substantial completion date.",
    present_patterns: [
      /(contract\s+time|time\s+adjustment|days?\s+(added|change))/i,
      /(new\s+(date\s+of\s+)?substantial\s+completion|no\s+change)/i,
    ],
  }),
  presence({
    id: "CON-029",
    name: "Signatures — owner + architect + contractor",
    description: "Change order must be signed by owner, architect, and contractor.",
    citation: aia("G701", "Signatures"),
    playbooks: [CON_PLAYBOOK_CHANGE_ORDER],
    missing_title: "Signatures clause missing",
    missing_description: "No signature block (owner / architect / contractor) was found.",
    explanation:
      "AIA G701 requires all three signatures. Unsigned COs are often treated as 'directives' that may not bind on price / time.",
    recommendation:
      "Add signature blocks for owner, architect, and contractor with name / title / date lines.",
    present_patterns: [/(owner)/i, /(architect|design\s+professional)/i, /(contractor)/i],
  }),
  presence({
    id: "CON-030",
    name: "Waiver of further claims for the changed work",
    description:
      "Change order should include a waiver of further claims related to the changed work.",
    citation: conPractice(
      "co-waiver",
      "Change order — waiver of further claims baseline",
      "https://www.americanbar.org/groups/construction_industry/",
    ),
    playbooks: [CON_PLAYBOOK_CHANGE_ORDER],
    missing_title: "Waiver-of-further-claims clause missing",
    missing_description: "No waiver-of-further-claims clause was found.",
    explanation:
      "Owners typically include language stating the contractor waives further claims (cost + time) related to the scope of this change order.",
    recommendation:
      "Add 'Waiver' stating contractor waives further claims for cost or time related to the changed work covered by this Change Order.",
    present_patterns: [
      /(waiv(es?|e|er|ed)|releases?)/i,
      /(further\s+claims|additional\s+(cost|time)|change\s+in\s+(scope|time))/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate. 30 rules total.
// ────────────────────────────────────────────────────────────────────

export const CONSTRUCTION_RULES: Rule[] = [
  ...CONSTRUCTION_CONTRACT_RULES,
  ...SUBCONTRACTOR_RULES,
  ...LIEN_WAIVER_RULES,
  ...BOND_RULES,
  ...CHANGE_ORDER_RULES,
];

export {
  CONSTRUCTION_CONTRACT_RULES,
  SUBCONTRACTOR_RULES,
  LIEN_WAIVER_RULES,
  BOND_RULES,
  CHANGE_ORDER_RULES,
};
