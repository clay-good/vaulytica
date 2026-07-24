/**
 * v4 Banking and lending ruleset — 51 rules
 * (spec-v4.md §6.L, Step 55).
 *
 * Eight new playbooks (L.1–L.8). Citations anchor to UCC Article 3
 * (negotiable instruments), UCC Article 9 (secured transactions),
 * Regulation Z (TILA), state usury statutes, the Statute of Frauds /
 * state suretyship law, state recording acts, and practitioner
 * baselines.
 *
 * Rule ids are flat `BNK-NNN` (001..051).
 */

import type { Rule } from "../../../finding.js";
import {
  buildV4PresenceRule,
  buildV4LanguageRule,
  type V4PresenceSpec,
  type V4LanguageSpec,
} from "../_helpers.js";
import {
  BNK_PLAYBOOK_PROMISSORY,
  BNK_PLAYBOOK_LOAN,
  BNK_PLAYBOOK_SECURITY,
  BNK_PLAYBOOK_GUARANTY,
  BNK_PLAYBOOK_INTERCREDITOR,
  BNK_PLAYBOOK_SUBORDINATION,
  BNK_PLAYBOOK_DOT,
  BNK_PLAYBOOK_UCC1,
  ucc,
  regZ,
  stateUsury,
  suretyship,
  recordingAct,
  bnkPractice,
} from "./_helpers.js";

const CATEGORY = "banking";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });
const language = (s: Omit<V4LanguageSpec, "category">): Rule =>
  buildV4LanguageRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// L.1 — Promissory note. 6 rules: BNK-001..BNK-006.
// ────────────────────────────────────────────────────────────────────

const PROMISSORY_NOTE_RULES: Rule[] = [
  presence({
    id: "BNK-001",
    name: "Maker, payee, and principal amount",
    description: "Promissory note must identify maker, payee, and principal amount.",
    citation: ucc("3-104", "Negotiable instrument requirements"),
    playbooks: [BNK_PLAYBOOK_PROMISSORY],
    missing_title: "Maker / payee / principal clause missing",
    missing_description: "No clause was found identifying the maker, payee, and principal amount.",
    explanation:
      "UCC § 3-104 requires a definite obligation to pay a fixed amount of money — these three elements must appear for negotiability.",
    recommendation: "Add 'Maker', 'Payee', and 'Principal Amount' lines stating each clearly.",
    present_patterns: [
      /(maker|borrower)/i,
      /(payee|lender|holder)/i,
      /(principal\s+(amount|sum)|\$)/i,
    ],
  }),
  presence({
    id: "BNK-002",
    name: "Unconditional promise to pay",
    description: "Promissory note must contain an unconditional promise to pay.",
    citation: ucc("3-104(a)(1)", "Unconditional promise"),
    playbooks: [BNK_PLAYBOOK_PROMISSORY],
    missing_title: "Unconditional-promise clause missing",
    missing_description: "No unconditional-promise clause was found.",
    explanation:
      "UCC § 3-104(a)(1) requires an unconditional promise or order; conditions defeat negotiability and convert the note into a non-negotiable IOU.",
    recommendation:
      "Add 'Promise to Pay' clause stating an unconditional promise (no 'subject to' qualifiers tied to the underlying transaction).",
    present_patterns: [
      /(unconditional(ly)?|absolutely\s+and\s+unconditional)/i,
      /(promise\s+to\s+pay|promises?\s+to\s+pay)/i,
    ],
  }),
  presence({
    id: "BNK-003",
    name: "Interest rate stated + state-usury compliance",
    description:
      "Promissory note must state the interest rate and comply with applicable state usury caps.",
    citation: stateUsury(),
    playbooks: [BNK_PLAYBOOK_PROMISSORY],
    missing_title: "Interest rate clause missing",
    missing_description: "No interest-rate clause was found.",
    explanation:
      "State usury caps vary widely (NY 16% civil / 25% criminal; CA 10% non-licensed; TX 18% absent agreement). Failure to state — or stating a rate above the cap — risks usury / forfeiture.",
    recommendation:
      "Add 'Interest' specifying the rate (fixed / variable / index), compounding, and a savings clause limiting interest to the highest lawful rate.",
    present_patterns: [
      /(interest\s+rate|rate\s+of\s+interest)/i,
      /\d+(\.\d+)?\s*(%|percent)/i,
      /(highest\s+lawful\s+rate|maximum\s+lawful\s+rate|usury\s+savings)/i,
    ],
  }),
  presence({
    id: "BNK-004",
    name: "Time of payment — demand or definite time",
    description:
      "Promissory note must be payable on demand or at a definite time (UCC § 3-104(a)(2)).",
    citation: ucc("3-104(a)(2)", "Time of payment"),
    playbooks: [BNK_PLAYBOOK_PROMISSORY],
    missing_title: "Time-of-payment clause missing",
    missing_description: "No clause was found specifying payment on demand or definite time.",
    explanation:
      "UCC § 3-104(a)(2) requires payment to be on demand OR at a definite time. Open-ended timing defeats negotiability.",
    recommendation:
      "Add 'Maturity / Time of Payment' specifying a definite maturity date OR demand language.",
    present_patterns: [
      /(maturity\s+date|due\s+date|date\s+of\s+maturity)/i,
      /(on\s+demand|payable\s+on\s+demand|definite\s+time)/i,
    ],
  }),
  presence({
    id: "BNK-005",
    name: "Default + acceleration",
    description: "Promissory note must address events of default and acceleration on default.",
    citation: bnkPractice(
      "note-default",
      "Promissory note — default / acceleration baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [BNK_PLAYBOOK_PROMISSORY, BNK_PLAYBOOK_LOAN],
    missing_title: "Default / acceleration clause missing",
    missing_description: "No default / acceleration clause was found.",
    explanation:
      "Without an enumerated default and acceleration mechanic, payee must wait for maturity to sue and may face unjust-enrichment / cure arguments.",
    recommendation:
      "Add 'Events of Default' (payment, cross-default, insolvency) and 'Acceleration' permitting holder to declare the full principal + accrued interest immediately due.",
    present_patterns: [
      /(events?\s+of\s+default|default)/i,
      /accelerat/i,
      /(insolvenc|bankruptc|payment\s+default)/i,
    ],
  }),
  presence({
    id: "BNK-006",
    name: "Maker waivers — presentment / notice / dishonor / protest",
    description:
      "Promissory note typically includes maker waivers of presentment, notice of dishonor, and protest (UCC § 3-504).",
    citation: ucc("3-504", "Presentment / dishonor waivers"),
    playbooks: [BNK_PLAYBOOK_PROMISSORY],
    missing_title: "Maker waivers clause missing",
    missing_description:
      "No maker-waivers clause (presentment / notice of dishonor / protest) was found.",
    explanation:
      "UCC § 3-504 permits waiver of presentment and notice of dishonor; standard institutional notes always waive these so that collection is not delayed by procedural formalities.",
    recommendation:
      "Add 'Waivers' covering presentment, demand, notice of dishonor, protest, and notice of protest.",
    present_patterns: [
      /(waive(s|d|r)?|waiver)/i,
      /(presentment|demand|notice\s+of\s+dishonor|protest)/i,
    ],
    default_severity: "warning",
  }),
  language({
    id: "BNK-051",
    name: "Confession of judgment / cognovit clause",
    description:
      "A confession-of-judgment (cognovit) clause lets the holder obtain judgment without notice or a hearing; it is void in consumer credit and prohibited or unenforceable in many states.",
    citation: bnkPractice(
      "ftc-credit-practices-cognovit",
      "FTC Credit Practices Rule, 16 C.F.R. \u00a7 444.2(a)(1) (cognovit / confession of judgment)",
      "https://www.ecfr.gov/current/title-16/chapter-I/subchapter-D/part-444",
    ),
    playbooks: [BNK_PLAYBOOK_PROMISSORY, BNK_PLAYBOOK_LOAN, BNK_PLAYBOOK_GUARANTY],
    bad_patterns: [
      /confess(?:es|ion)?\s+(?:of\s+)?judgment/i,
      /\bcognovit\b/i,
      /authorizes?\s+any\s+attorney[^.]{0,80}(?:appear|confess|judgment)/i,
      /warrant\s+of\s+attorney[^.]{0,60}(?:confess|judgment)/i,
    ],
    exclude_if: [
      /\bno\b[^.]{0,40}confession\s+of\s+judgment|confession\s+of\s+judgment[^.]{0,40}\b(?:is\s+)?(?:not|prohibited|void|waived|disclaimed)\b/i,
    ],
    bad_title: "Confession-of-judgment (cognovit) clause present",
    bad_description:
      "The instrument authorizes entry of judgment against the obligor without prior notice or a hearing.",
    explanation:
      "A cognovit / confession-of-judgment clause waives the obligor's due-process rights to notice and a hearing before judgment. The FTC Credit Practices Rule (16 C.F.R. \u00a7 444.2(a)(1)) makes such clauses an unfair practice in consumer credit, and many states hold them void or unenforceable outside a narrow commercial exception. Even where permitted, they are a hallmark of predatory lending and merchant-cash-advance abuse.",
    recommendation:
      "Remove the confession-of-judgment / cognovit / warrant-of-attorney provision, or confirm the transaction is a permitted commercial one in a state that recognizes it and that the obligor received independent counsel.",
    default_severity: "critical",
  }),
];

// ────────────────────────────────────────────────────────────────────
// L.2 — Loan agreement. 7 rules: BNK-007..BNK-013.
// ────────────────────────────────────────────────────────────────────

const LOAN_AGREEMENT_RULES: Rule[] = [
  presence({
    id: "BNK-007",
    name: "Loan amount, facility type, purpose",
    description:
      "Loan agreement must state the loan amount, facility type (term / revolver), and use of proceeds.",
    citation: bnkPractice(
      "loan-baseline",
      "Loan agreement — facility baseline (LSTA model)",
      "https://www.lsta.org/",
    ),
    playbooks: [BNK_PLAYBOOK_LOAN],
    missing_title: "Loan amount / facility / purpose clause missing",
    missing_description:
      "No clause was found stating the loan amount, facility type, and use of proceeds.",
    explanation:
      "Borrower, lender, lawyer, and any subsequent assignee need to know what is being lent and why. Use-of-proceeds restrictions are routinely litigated.",
    recommendation:
      "Add 'Loan / Facility' specifying principal commitment, facility type (term, revolver, delayed draw), and use of proceeds.",
    present_patterns: [
      /(loan\s+amount|commitment|principal)/i,
      /(term\s+loan|revolving|revolver|delayed.draw)/i,
      /(use\s+of\s+proceeds|purpose)/i,
    ],
  }),
  presence({
    id: "BNK-008",
    name: "Interest rate / margin / floor",
    description:
      "Loan agreement must state the interest rate / margin / floor (SOFR / prime / fixed).",
    citation: stateUsury(),
    playbooks: [BNK_PLAYBOOK_LOAN],
    missing_title: "Interest rate / margin clause missing",
    missing_description: "No interest-rate / margin / floor clause was found.",
    explanation:
      "Index + margin + floor define the pricing. Post-LIBOR transition (June 2023) the index is SOFR-based; legacy LIBOR fallbacks should be addressed.",
    recommendation:
      "Add 'Interest Rate' specifying index (SOFR + tenor), margin, floor, and LIBOR-fallback / Term-SOFR-replacement language as needed.",
    present_patterns: [
      /(sofr|prime\s+rate|libor)/i,
      /(margin|spread|basis\s+points|bps)/i,
      /(floor|cap|cap\s+and\s+floor)/i,
    ],
  }),
  presence({
    id: "BNK-009",
    name: "Affirmative covenants",
    description:
      "Loan agreement must include affirmative covenants (financials, compliance, books-and-records).",
    citation: bnkPractice(
      "affirmative-covenants",
      "Loan agreement — affirmative covenants baseline",
      "https://www.lsta.org/",
    ),
    playbooks: [BNK_PLAYBOOK_LOAN],
    missing_title: "Affirmative covenants clause missing",
    missing_description: "No affirmative-covenants clause was found.",
    explanation:
      "Affirmative covenants (maintain existence, comply with law, deliver financials, notify of defaults) protect the lender's information rights.",
    recommendation:
      "Add 'Affirmative Covenants' covering existence, compliance with law, taxes, financial statements, books-and-records, and notice of defaults.",
    present_patterns: [
      /affirmative\s+covenants?/i,
      /(financial\s+statements?|books\s+and\s+records|maintenance)/i,
    ],
  }),
  presence({
    id: "BNK-010",
    name: "Negative covenants",
    description:
      "Loan agreement must include negative covenants (debt incurrence, liens, restricted payments, asset sales).",
    citation: bnkPractice(
      "negative-covenants",
      "Loan agreement — negative covenants baseline",
      "https://www.lsta.org/",
    ),
    playbooks: [BNK_PLAYBOOK_LOAN],
    missing_title: "Negative covenants clause missing",
    missing_description: "No negative-covenants clause was found.",
    explanation:
      "Negative covenants (debt limits, lien caps, restricted payments, asset-sale baskets, fundamental-change consent) preserve collateral and credit support.",
    recommendation:
      "Add 'Negative Covenants' restricting indebtedness, liens, restricted payments, asset sales, mergers, and affiliate transactions.",
    present_patterns: [
      /negative\s+covenants?/i,
      /(indebtedness|liens?|restricted\s+payments?|asset\s+sales?)/i,
    ],
  }),
  presence({
    id: "BNK-011",
    name: "Financial covenants",
    description:
      "Most loan agreements include financial covenants (leverage, interest coverage, fixed-charge coverage, minimum liquidity).",
    citation: bnkPractice(
      "financial-covenants",
      "Loan agreement — financial covenants baseline",
      "https://www.lsta.org/",
    ),
    playbooks: [BNK_PLAYBOOK_LOAN],
    missing_title: "Financial covenants clause missing",
    missing_description: "No financial-covenants clause was found.",
    explanation:
      "Financial covenants are the early-warning system; covenant-lite deals are common but should be intentional, not accidental.",
    recommendation:
      "Add 'Financial Covenants' (leverage ratio, interest coverage, fixed-charge coverage, minimum liquidity) — or explicitly note 'covenant-lite' design.",
    present_patterns: [
      /financial\s+covenants?/i,
      /(leverage\s+ratio|interest\s+coverage|fixed.charge|minimum\s+liquidity)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "BNK-012",
    name: "Events of default + cross-default + cure periods",
    description:
      "Loan agreement must enumerate events of default with cure periods and cross-default to material indebtedness.",
    citation: bnkPractice(
      "loan-default",
      "Loan agreement — EoD + cross-default baseline",
      "https://www.lsta.org/",
    ),
    playbooks: [BNK_PLAYBOOK_LOAN],
    missing_title: "Events of default / cross-default clause missing",
    missing_description: "No EoD / cross-default / cure-period clause was found.",
    explanation:
      "Late payment, covenant breach (with cure), insolvency, rep / warranty breach, cross-default to material indebtedness, change of control, judgment threshold — these are the universal EoDs.",
    recommendation:
      "Add 'Events of Default' enumerating each category with applicable cure periods and a cross-default trigger keyed to a stated dollar threshold.",
    present_patterns: [
      /events?\s+of\s+default/i,
      /(cross.?default|cure\s+period|grace\s+period)/i,
      /(insolvenc|bankruptc)/i,
    ],
  }),
  presence({
    id: "BNK-013",
    name: "Reg Z disclosures (consumer loans only)",
    description:
      "Consumer-purpose loans must include TILA / Reg Z disclosures (APR, finance charge, amount financed, total of payments).",
    citation: regZ("18", "Closed-end credit disclosures"),
    playbooks: [BNK_PLAYBOOK_LOAN],
    missing_title: "Reg Z / TILA disclosures clause missing (consumer)",
    missing_description: "No Reg Z / TILA disclosure clause was found for a consumer-purpose loan.",
    explanation:
      "Regulation Z (12 C.F.R. § 1026.18) requires the four TILA disclosures (APR, finance charge, amount financed, total of payments) in segregated form for closed-end consumer credit.",
    recommendation:
      "If the loan is consumer-purpose, add the TILA disclosure block with APR, finance charge, amount financed, total of payments.",
    present_patterns: [
      /(annual\s+percentage\s+rate|apr)/i,
      /(finance\s+charge|amount\s+financed|total\s+of\s+payments)/i,
      /(regulation\s+z|tila|truth\s+in\s+lending)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// L.3 — Security agreement. 7 rules: BNK-014..BNK-020.
// ────────────────────────────────────────────────────────────────────

const SECURITY_AGREEMENT_RULES: Rule[] = [
  presence({
    id: "BNK-014",
    name: "Debtor / secured party identification",
    description: "Security agreement must identify debtor and secured party with full legal names.",
    citation: ucc("9-203", "Attachment"),
    playbooks: [BNK_PLAYBOOK_SECURITY],
    missing_title: "Debtor / secured party clause missing",
    missing_description: "No clause was found identifying debtor and secured party.",
    explanation:
      "UCC § 9-203 requires debtor authentication; § 9-502 requires the financing statement to identify both parties.",
    recommendation:
      "Add 'Debtor' and 'Secured Party' lines stating each party's full legal name and organizational form.",
    present_patterns: [/(debtor|borrower)/i, /(secured\s+party|lender|holder)/i],
  }),
  presence({
    id: "BNK-015",
    name: "Granting clause — grant of security interest",
    description:
      "Security agreement must contain an operative granting clause creating the security interest.",
    citation: ucc("9-203", "Granting clause"),
    playbooks: [BNK_PLAYBOOK_SECURITY],
    missing_title: "Granting clause missing",
    missing_description: "No granting clause creating the security interest was found.",
    explanation:
      "UCC § 9-203 requires the debtor's authentication to include language granting a security interest. Without grant language attachment fails.",
    recommendation:
      "Add 'Grant of Security Interest' stating debtor grants secured party a continuing security interest in the Collateral.",
    present_patterns: [
      /(grants?|hereby\s+grants?|assigns?\s+and\s+grants?).{0,80}security\s+interest/is,
      /security\s+interest/i,
    ],
  }),
  presence({
    id: "BNK-016",
    name: "Collateral description — reasonably identifies (§ 9-108)",
    description: "Collateral must be described with reasonable specificity per UCC § 9-108.",
    citation: ucc("9-108", "Sufficiency of description"),
    playbooks: [BNK_PLAYBOOK_SECURITY],
    missing_title: "Collateral description clause missing",
    missing_description:
      "No clause was found describing the collateral with reasonable specificity.",
    explanation:
      "UCC § 9-108 requires that the collateral description reasonably identify what is described. 'All assets' is permitted in the security agreement (but not in the financing statement absent specific exceptions).",
    recommendation:
      "Add 'Collateral' describing each category (accounts, inventory, equipment, general intangibles, deposit accounts, IP) with sufficient detail.",
    present_patterns: [
      /collateral/i,
      /(accounts?|inventory|equipment|general\s+intangibles?|deposit\s+account)/i,
    ],
  }),
  presence({
    id: "BNK-017",
    name: "After-acquired property + proceeds clause",
    description:
      "Security agreement should cover after-acquired property and proceeds (§ 9-204, § 9-315).",
    citation: ucc("9-204", "After-acquired property"),
    playbooks: [BNK_PLAYBOOK_SECURITY],
    missing_title: "After-acquired / proceeds clause missing",
    missing_description: "No after-acquired property or proceeds clause was found.",
    explanation:
      "Under UCC § 9-204, after-acquired property requires express language for most collateral categories (consumer-goods exception); § 9-315 attaches proceeds automatically but conventions confirm.",
    recommendation:
      "Add 'After-Acquired Property and Proceeds' covering all after-acquired collateral of the listed types and identifiable proceeds.",
    present_patterns: [/after.acquired/i, /proceeds/i],
    default_severity: "warning",
  }),
  presence({
    id: "BNK-018",
    name: "Authorization to file financing statements",
    description:
      "Security agreement should authorize secured party to file UCC-1 financing statements (§ 9-509).",
    citation: ucc("9-509", "Authorization to file"),
    playbooks: [BNK_PLAYBOOK_SECURITY],
    missing_title: "Financing-statement filing authorization missing",
    missing_description:
      "No clause was found authorizing the secured party to file UCC-1 financing statements.",
    explanation:
      "UCC § 9-509 requires debtor authorization for the filing of a financing statement; standard practice is to include the authorization in the security agreement so the secured party can perfect promptly.",
    recommendation:
      "Add 'Authorization to File' authorizing secured party (and counsel) to file UCC-1 financing statements (and amendments) describing the Collateral.",
    present_patterns: [
      /(authoriz(es?|ed|ation)).{0,40}(file|filing)/is,
      /(financing\s+statements?|ucc.?1)/i,
    ],
  }),
  presence({
    id: "BNK-019",
    name: "Debtor representations as to ownership / no liens",
    description: "Debtor must represent it owns the collateral free of competing liens.",
    citation: ucc("9-203(b)(2)", "Debtor rights"),
    playbooks: [BNK_PLAYBOOK_SECURITY],
    missing_title: "Debtor ownership / no-liens reps clause missing",
    missing_description:
      "No clause was found stating debtor's reps as to ownership and absence of liens.",
    explanation:
      "Attachment under § 9-203(b)(2) requires debtor to have 'rights in the collateral'; lender needs reps as to ownership and that no competing liens exist.",
    recommendation:
      "Add 'Representations and Warranties' covering ownership, no competing liens, and authority to grant the security interest.",
    present_patterns: [
      /(representations?\s+(and|&)\s+warranties|reps?\s+and\s+warranties)/i,
      /(own(s|ership)|title)/i,
      /(no\s+(competing\s+)?liens|free\s+of\s+(any\s+)?liens?)/i,
    ],
  }),
  presence({
    id: "BNK-020",
    name: "Remedies on default — UCC Part 6",
    description:
      "Security agreement must specify remedies on default (UCC Part 6 — sale, repossession, deficiency).",
    citation: ucc("9-601", "Remedies after default"),
    playbooks: [BNK_PLAYBOOK_SECURITY],
    missing_title: "Remedies-on-default clause missing",
    missing_description: "No clause was found specifying remedies on default.",
    explanation:
      "UCC Part 6 governs default remedies — collection, repossession, disposition (commercially reasonable sale), strict foreclosure (§ 9-620), and deficiency.",
    recommendation:
      "Add 'Remedies' incorporating UCC Part 6 — collection of accounts, repossession, commercially reasonable disposition, application of proceeds, and deficiency.",
    present_patterns: [
      /(remed(y|ies)|default)/i,
      /(repossess|disposition|foreclosure|deficiency)/i,
      /(commercially\s+reasonable|ucc|article\s+9)/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// L.4 — Guaranty. 6 rules: BNK-021..BNK-026.
// ────────────────────────────────────────────────────────────────────

const GUARANTY_RULES: Rule[] = [
  presence({
    id: "BNK-021",
    name: "Guarantor / obligee identification + underlying obligation",
    description:
      "Guaranty must identify guarantor, obligee (lender), and the underlying obligation.",
    citation: suretyship(),
    playbooks: [BNK_PLAYBOOK_GUARANTY],
    missing_title: "Guarantor / obligee / underlying clause missing",
    missing_description:
      "No clause was found identifying guarantor, obligee, and underlying obligation.",
    explanation:
      "Suretyship law and the Statute of Frauds require the underlying obligation and the guarantor's identity to appear in a signed writing.",
    recommendation:
      "Add 'Parties' identifying guarantor, lender / obligee, and the underlying obligation by reference (Note / Loan Agreement of [date]).",
    present_patterns: [
      /(guarantor|surety)/i,
      /(obligee|lender|holder|beneficiary)/i,
      /(underlying\s+obligation|note|loan\s+agreement)/i,
    ],
  }),
  presence({
    id: "BNK-022",
    name: "Payment-vs-collection (absolute vs collection guaranty)",
    description:
      "Guaranty must specify whether it is of payment (primary, absolute) or of collection (resort-first to collateral / borrower).",
    citation: suretyship(),
    playbooks: [BNK_PLAYBOOK_GUARANTY],
    missing_title: "Payment / collection clause missing",
    missing_description: "No clause was found distinguishing guaranty of payment vs collection.",
    explanation:
      "Guaranty of payment lets the lender pursue guarantor immediately on default; guaranty of collection requires exhaustion against the borrower / collateral. The distinction drives litigation strategy.",
    recommendation:
      "Add 'Type of Guaranty' clearly stating payment vs collection (almost always payment in institutional financings).",
    present_patterns: [
      /(guarant(y|ee)\s+of\s+(payment|collection))/i,
      /(absolute|primary|continuing)/i,
    ],
  }),
  presence({
    id: "BNK-023",
    name: "Suretyship defenses waived",
    description:
      "Institutional guaranties waive common-law suretyship defenses (release / modification / impairment of collateral).",
    citation: suretyship(),
    playbooks: [BNK_PLAYBOOK_GUARANTY],
    missing_title: "Suretyship-defenses waiver missing",
    missing_description: "No waiver of suretyship defenses was found.",
    explanation:
      "Common-law defenses (release, modification, impairment of collateral, failure to perfect, statute of limitations) can defeat a guaranty unless waived.",
    recommendation:
      "Add 'Waiver of Defenses' waiving common-law suretyship defenses including release, modification, impairment of collateral, and failure to pursue collateral first.",
    present_patterns: [
      /(waiv(e|er|es|ed))/i,
      /(defenses?|suretyship)/i,
      /(release|modification|impairment\s+of\s+collateral)/i,
    ],
  }),
  presence({
    id: "BNK-024",
    name: "Continuing nature + maximum amount (limited guaranty)",
    description:
      "Guaranty should state whether it is continuing and any maximum dollar limitation.",
    citation: bnkPractice(
      "continuing-guaranty",
      "Continuing guaranty baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [BNK_PLAYBOOK_GUARANTY],
    missing_title: "Continuing-guaranty / cap clause missing",
    missing_description: "No clause was found addressing continuing nature or any maximum amount.",
    explanation:
      "Continuing guaranties cover future advances; limited guaranties cap exposure. Ambiguity causes disputes over scope.",
    recommendation:
      "Add 'Continuing Guaranty' (or limited / capped guaranty) specifying scope and any maximum aggregate dollar limit.",
    present_patterns: [
      /continuing\s+guarant/i,
      /(maximum\s+(amount|liability)|cap|limit\s+of\s+\$|aggregate\s+liability)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "BNK-025",
    name: "Subrogation / contribution rights waived or deferred",
    description:
      "Institutional guaranties waive or defer guarantor's subrogation / contribution rights until full payment.",
    citation: suretyship(),
    playbooks: [BNK_PLAYBOOK_GUARANTY],
    missing_title: "Subrogation / contribution waiver missing",
    missing_description:
      "No clause was found addressing waiver / deferral of subrogation or contribution.",
    explanation:
      "Without a waiver or deferral, a guarantor who pays could compete with lender's recovery from the borrower or other guarantors before lender is paid in full.",
    recommendation:
      "Add 'Subrogation' deferring (or waiving) subrogation / contribution / reimbursement rights until lender is paid in full.",
    present_patterns: [
      /(subrogation|contribution|reimbursement|indemnification)/i,
      /(waive(s|d|r)?|defer(red)?|until\s+paid\s+in\s+full)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "BNK-026",
    name: "Reinstatement on preference / fraudulent transfer",
    description:
      "Guaranty should provide for reinstatement if payments are recovered as preferences / fraudulent transfers.",
    citation: bnkPractice(
      "reinstatement",
      "Guaranty — reinstatement / preference baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [BNK_PLAYBOOK_GUARANTY],
    missing_title: "Reinstatement clause missing",
    missing_description: "No reinstatement / preference clause was found.",
    explanation:
      "If borrower payments are clawed back as preferences (Bankr. Code § 547) or fraudulent transfers (§ 548), the guaranty must be reinstated to cover the restored liability.",
    recommendation:
      "Add 'Reinstatement' clause restoring the guaranty if any payment is recovered as a preference, fraudulent transfer, or otherwise.",
    present_patterns: [/reinstat/i, /(preference|fraudulent\s+transfer|avoidance|clawback)/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// L.5 — Intercreditor agreement. 6 rules: BNK-027..BNK-032.
// ────────────────────────────────────────────────────────────────────

const INTERCREDITOR_RULES: Rule[] = [
  presence({
    id: "BNK-027",
    name: "Senior / junior identification + priorities",
    description:
      "Intercreditor must identify senior creditor(s), junior creditor(s), and lien / payment priorities.",
    citation: ucc("9-339", "Subordination by agreement"),
    playbooks: [BNK_PLAYBOOK_INTERCREDITOR],
    missing_title: "Senior / junior / priority clause missing",
    missing_description: "No clause was found identifying senior / junior creditors or priorities.",
    explanation:
      "Lien priority and payment priority are the core of the agreement; ambiguity invites litigation when collateral is constrained.",
    recommendation:
      "Add 'Priorities' clearly stating lien priority and payment-waterfall priority between Senior and Junior Debt.",
    present_patterns: [
      /(senior|junior|subordinat)/i,
      /(priorit(y|ies)|lien\s+priority|payment\s+priority)/i,
    ],
  }),
  presence({
    id: "BNK-028",
    name: "Payment / lien blockage and turnover",
    description:
      "Intercreditor must address payment / lien blockage and turnover of payments received in breach.",
    citation: bnkPractice(
      "blockage-turnover",
      "Intercreditor blockage / turnover baseline (LSTA / ABA model intercreditor)",
      "https://www.lsta.org/",
    ),
    playbooks: [BNK_PLAYBOOK_INTERCREDITOR],
    missing_title: "Blockage / turnover clause missing",
    missing_description: "No payment-blockage / turnover clause was found.",
    explanation:
      "Standstill on payment / enforcement during senior default + turnover of any payment received in breach are essential to honor priorities.",
    recommendation:
      "Add 'Payment Blockage' and 'Turnover' obligating Junior to hold blocked payments in trust and turn them over to Senior.",
    present_patterns: [
      /(blockage|standstill|enforcement\s+standstill)/i,
      /(turnover|hold\s+in\s+trust|remit\s+to)/i,
    ],
  }),
  presence({
    id: "BNK-029",
    name: "Standstill — junior remedies",
    description: "Intercreditor must define a standstill on junior remedies during senior default.",
    citation: bnkPractice(
      "junior-standstill",
      "Intercreditor — junior standstill baseline",
      "https://www.lsta.org/",
    ),
    playbooks: [BNK_PLAYBOOK_INTERCREDITOR],
    missing_title: "Junior standstill clause missing",
    missing_description: "No junior-standstill clause was found.",
    explanation:
      "A common pattern: 180-day standstill on junior enforcement while senior pursues remedies. Without it, junior can race senior to collateral.",
    recommendation:
      "Add 'Junior Standstill' barring junior enforcement actions during a stated standstill period (typically 180 days) after notice of senior default.",
    present_patterns: [
      /(standstill\s+period|standstill)/i,
      /(180\s+days?|junior\s+enforcement|enforcement\s+actions?)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "BNK-030",
    name: "DIP financing / bankruptcy provisions",
    description:
      "Intercreditor should include bankruptcy provisions — DIP financing consent, plan voting, 363 sale consent.",
    citation: bnkPractice(
      "intercreditor-bankruptcy",
      "Intercreditor — bankruptcy / DIP / 363 sale baseline",
      "https://www.lsta.org/",
    ),
    playbooks: [BNK_PLAYBOOK_INTERCREDITOR],
    missing_title: "Bankruptcy / DIP / 363-sale clause missing",
    missing_description: "No bankruptcy / DIP financing / 363-sale clause was found.",
    explanation:
      "Intercreditors live or die in bankruptcy. Junior typically pre-agrees to senior DIP, 363 sales, plan support, and 1129(b) cramdown.",
    recommendation:
      "Add 'Bankruptcy' covering junior agreement to senior DIP, 363 sales free and clear, plan support, and lift-stay cooperation.",
    present_patterns: [
      /(bankruptcy|chapter\s+11|dip\s+financing)/i,
      /(363\s+sale|plan\s+support|cramdown|1129)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "BNK-031",
    name: "Buy-out / option to purchase senior debt",
    description: "Junior should have an option to purchase senior debt at par on enforcement.",
    citation: bnkPractice(
      "buy-out",
      "Intercreditor — junior buy-out / option baseline",
      "https://www.lsta.org/",
    ),
    playbooks: [BNK_PLAYBOOK_INTERCREDITOR],
    missing_title: "Junior buy-out / option clause missing",
    missing_description: "No junior buy-out option (par) was found.",
    explanation:
      "Junior often negotiates an option to purchase the senior facility at par + accrued interest on enforcement, to take control of the workout.",
    recommendation:
      "Add 'Junior Purchase Right' permitting junior to purchase senior debt at par + accrued upon senior acceleration or 363-sale election.",
    present_patterns: [
      /(option\s+to\s+purchase|purchase\s+option|right\s+to\s+purchase)/i,
      /(senior\s+debt|senior\s+facility|par\s+plus\s+accrued)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "BNK-032",
    name: "Amendment / waiver mechanics (consent rights)",
    description:
      "Intercreditor must specify amendment / waiver mechanics for each tier (consent rights, holdouts).",
    citation: bnkPractice(
      "intercreditor-amend",
      "Intercreditor — amendment / waiver baseline",
      "https://www.lsta.org/",
    ),
    playbooks: [BNK_PLAYBOOK_INTERCREDITOR],
    missing_title: "Amendment / consent-rights clause missing",
    missing_description: "No amendment / consent-rights clause was found.",
    explanation:
      "Without enumerated consent rights, junior or senior can be cornered by unilateral amendments to the other's documents.",
    recommendation:
      "Add 'Amendments' specifying when junior consent to senior amendments (or vice versa) is required (typically: maturity extension, interest-rate bumps above N%, principal-amount increase above stated cap).",
    present_patterns: [
      /(amendments?|waivers?|consent\s+rights?)/i,
      /(maturity|interest\s+rate|principal\s+amount)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// L.6 — Subordination agreement. 6 rules: BNK-033..BNK-038.
// ────────────────────────────────────────────────────────────────────

const SUBORDINATION_RULES: Rule[] = [
  presence({
    id: "BNK-033",
    name: "Subordinated debt identified",
    description: "Subordination agreement must identify the subordinated debt with specificity.",
    citation: ucc("9-339", "Subordination by agreement"),
    playbooks: [BNK_PLAYBOOK_SUBORDINATION],
    missing_title: "Subordinated-debt identification clause missing",
    missing_description: "No clause was found identifying the subordinated debt.",
    explanation:
      "UCC § 9-339 honors subordination by agreement; the agreement must identify the debt being subordinated by note / facility reference.",
    recommendation:
      "Add 'Subordinated Debt' identifying the note / loan agreement, principal, and date.",
    present_patterns: [/(subordinated\s+debt|junior\s+debt)/i, /(note|loan\s+agreement|facility)/i],
  }),
  presence({
    id: "BNK-034",
    name: "Senior debt identified + future advances treatment",
    description:
      "Subordination must identify the senior debt and address future advances / refinancings.",
    citation: bnkPractice(
      "subordination-senior",
      "Subordination — senior debt baseline (including refinancings)",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [BNK_PLAYBOOK_SUBORDINATION],
    missing_title: "Senior-debt identification clause missing",
    missing_description: "No clause identifying the senior debt was found.",
    explanation:
      "Subordination should reach the senior debt as-amended and any permitted refinancing — otherwise senior must re-negotiate on every refinance.",
    recommendation:
      "Add 'Senior Debt' identifying senior facility, with provision that subordination applies to extensions / refinancings / increases (subject to caps where appropriate).",
    present_patterns: [
      /(senior\s+debt|senior\s+facility|senior\s+indebtedness)/i,
      /(refinance|refinanc|extension|replacement)/i,
    ],
  }),
  presence({
    id: "BNK-035",
    name: "Payment subordination — blockage + turnover",
    description:
      "Subordination must address payment subordination, blockage windows, and turnover.",
    citation: bnkPractice(
      "subordination-payment",
      "Subordination — payment blockage + turnover baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [BNK_PLAYBOOK_SUBORDINATION],
    missing_title: "Payment subordination / blockage clause missing",
    missing_description: "No payment-subordination / blockage / turnover clause was found.",
    explanation:
      "Payment subordination defers junior payment during senior default. Blockage windows (typically 180 days per 360) plus turnover preserve senior priority.",
    recommendation:
      "Add 'Payment Subordination' deferring junior payment during senior default plus 'Blockage' (windows) and 'Turnover' clauses.",
    present_patterns: [
      /(payment\s+subordination|defer|blockage)/i,
      /(turnover|hold\s+in\s+trust|180\s+days?)/i,
    ],
  }),
  presence({
    id: "BNK-036",
    name: "Permitted payments / windows",
    description:
      "Subordination should permit ordinary-course interest / scheduled payments outside of default / blockage.",
    citation: bnkPractice(
      "permitted-payments",
      "Subordination — permitted payments baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [BNK_PLAYBOOK_SUBORDINATION],
    missing_title: "Permitted-payments clause missing",
    missing_description: "No permitted-payments clause was found.",
    explanation:
      "Total deferral is rare; junior typically receives scheduled interest in the absence of senior default. The permitted-payment window should be explicit.",
    recommendation:
      "Add 'Permitted Payments' permitting scheduled interest / principal absent senior default + blockage notice.",
    present_patterns: [
      /(permitted\s+payments?|scheduled\s+(payments?|interest))/i,
      /(unless|except).{0,40}(default|blockage|notice)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "BNK-037",
    name: "Standstill on enforcement",
    description:
      "Subordination must include standstill on enforcement against borrower / collateral.",
    citation: bnkPractice(
      "subordination-standstill",
      "Subordination — junior standstill baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [BNK_PLAYBOOK_SUBORDINATION],
    missing_title: "Standstill clause missing",
    missing_description: "No standstill-on-enforcement clause was found.",
    explanation:
      "Without standstill the junior creditor can race senior to enforcement; standard period is 120–180 days.",
    recommendation:
      "Add 'Standstill' barring junior enforcement actions during a stated period after notice of senior default.",
    present_patterns: [/standstill/i, /(120|180)\s+days?/i, /(enforcement|remedies)/i],
    default_severity: "warning",
  }),
  presence({
    id: "BNK-038",
    name: "Bankruptcy provisions — § 510(a) enforceability",
    description:
      "Subordination should expressly invoke Bankruptcy Code § 510(a) enforceability in bankruptcy.",
    citation: bnkPractice(
      "510a-enforceability",
      "11 U.S.C. § 510(a) — subordination agreement enforceable in bankruptcy",
      "https://www.law.cornell.edu/uscode/text/11/510",
    ),
    playbooks: [BNK_PLAYBOOK_SUBORDINATION],
    missing_title: "§ 510(a) bankruptcy-enforceability clause missing",
    missing_description: "No clause was found invoking § 510(a) bankruptcy enforceability.",
    explanation:
      "11 U.S.C. § 510(a) enforces subordination agreements in bankruptcy as outside of bankruptcy. Express acknowledgment + plan-support language strengthens enforcement.",
    recommendation:
      "Add 'Bankruptcy' expressly invoking § 510(a) and providing for senior plan-support / 363-sale cooperation.",
    present_patterns: [
      /(section\s+510|§\s*510|11\s+u\.?s\.?c\.?\s+§?\s*510)/i,
      /(bankruptcy|chapter\s+11)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// L.7 — Deed of trust / mortgage. 6 rules: BNK-039..BNK-044.
// ────────────────────────────────────────────────────────────────────

const DEED_OF_TRUST_RULES: Rule[] = [
  presence({
    id: "BNK-039",
    name: "Grantor / trustee / beneficiary identification (deed of trust)",
    description:
      "Deed of trust must identify grantor (trustor), trustee, and beneficiary (mortgagor / mortgagee for mortgage states).",
    citation: recordingAct(),
    playbooks: [BNK_PLAYBOOK_DOT],
    missing_title: "Grantor / trustee / beneficiary clause missing",
    missing_description: "No clause was found identifying grantor, trustee, and beneficiary.",
    explanation:
      "Recording acts require identification of the parties; the deed-of-trust / mortgage distinction also drives the foreclosure procedure (trustee non-judicial vs court judicial).",
    recommendation:
      "Add 'Parties' identifying grantor (trustor), trustee, and beneficiary (lender) — or mortgagor / mortgagee in mortgage states.",
    present_patterns: [
      /(grantor|trustor|mortgagor|borrower)/i,
      /(trustee|substitute\s+trustee)/i,
      /(beneficiary|mortgagee|lender)/i,
    ],
  }),
  presence({
    id: "BNK-040",
    name: "Legal description of real property",
    description:
      "Mortgage / deed of trust must contain a Statute-of-Frauds-grade legal description.",
    citation: bnkPractice(
      "legal-desc",
      "Real-property legal description baseline (metes-and-bounds / lot-and-block / reference)",
      "https://www.americanbar.org/groups/real_property_trust_estate/",
    ),
    playbooks: [BNK_PLAYBOOK_DOT],
    missing_title: "Legal description clause missing",
    missing_description: "No legal description of real property was found.",
    explanation:
      "An address alone is not a legal description; metes-and-bounds, lot / block / subdivision, or a recorded-plat reference is required to bind real property.",
    recommendation:
      "Add 'Legal Description' or Exhibit A with metes-and-bounds, lot-and-block, or recorded-plat reference (including book / page or instrument number).",
    present_patterns: [
      /(legal\s+description|exhibit\s+a)/i,
      /(metes\s+and\s+bounds|lot\s+\d|block\s+\d|book\s+\d.+page\s+\d|instrument\s+no)/i,
    ],
  }),
  presence({
    id: "BNK-041",
    name: "Granting / habendum clause",
    description:
      "Mortgage / deed of trust must contain a granting clause conveying the property to trustee / mortgagee.",
    citation: bnkPractice(
      "granting-habendum",
      "Granting / habendum clause baseline",
      "https://www.americanbar.org/groups/real_property_trust_estate/",
    ),
    playbooks: [BNK_PLAYBOOK_DOT],
    missing_title: "Granting / habendum clause missing",
    missing_description: "No granting / habendum clause was found.",
    explanation:
      "The granting / habendum clause is the operative conveyance — without it the instrument may be defective even when the parties intend to encumber.",
    recommendation:
      "Add 'Grant / Conveyance' conveying the described real property to trustee in trust (deed of trust) or to mortgagee (mortgage), with the customary 'to have and to hold' (habendum) language.",
    present_patterns: [
      /(grant(s|ed)?|convey(s|ed)?|mortgages?\s+and\s+warrants?)/i,
      /(to\s+have\s+and\s+to\s+hold|habendum|in\s+trust)/i,
    ],
  }),
  presence({
    id: "BNK-042",
    name: "Power of sale / judicial foreclosure election",
    description:
      "Deed of trust must include a power of sale (non-judicial foreclosure) — mortgages typically rely on judicial foreclosure.",
    citation: bnkPractice(
      "power-of-sale",
      "Power-of-sale / judicial-foreclosure baseline (state-specific)",
      "https://www.americanbar.org/groups/real_property_trust_estate/",
    ),
    playbooks: [BNK_PLAYBOOK_DOT],
    missing_title: "Power-of-sale / foreclosure clause missing",
    missing_description: "No power-of-sale / foreclosure clause was found.",
    explanation:
      "Power-of-sale enables non-judicial foreclosure in deed-of-trust states (CA / TX / VA / WA / etc.); the clause must follow state-specific notice / sale formalities.",
    recommendation:
      "Add 'Power of Sale' (or judicial-foreclosure recital) with state-required notice / publication / sale procedure.",
    present_patterns: [
      /(power\s+of\s+sale|non.?judicial\s+foreclosure|trustee.?s\s+sale)/i,
      /(notice|publication|sale\s+procedure)/i,
    ],
  }),
  presence({
    id: "BNK-043",
    name: "Due-on-sale + due-on-encumbrance",
    description:
      "Mortgage / deed of trust should include due-on-sale and due-on-encumbrance acceleration triggers.",
    citation: bnkPractice(
      "due-on-sale",
      "Garn-St Germain Depository Institutions Act of 1982 — due-on-sale enforcement",
      "https://www.law.cornell.edu/uscode/text/12/1701j-3",
    ),
    playbooks: [BNK_PLAYBOOK_DOT],
    missing_title: "Due-on-sale / encumbrance clause missing",
    missing_description: "No due-on-sale / encumbrance acceleration clause was found.",
    explanation:
      "Garn-St Germain (12 U.S.C. § 1701j-3) preempts most state restrictions on due-on-sale enforcement; the clause permits acceleration on transfer / further encumbrance, with statutory consumer carve-outs (intra-family transfers, etc.).",
    recommendation:
      "Add 'Due on Sale / Encumbrance' permitting acceleration on transfer / further encumbrance, subject to Garn-St Germain § 1701j-3(d) carve-outs.",
    present_patterns: [
      /due.?on.?(sale|transfer|encumbrance)/i,
      /(transfer|sale|assignment|conveyance)/i,
      /accelerat/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "BNK-044",
    name: "Recording acknowledgment + governing-law / homestead waiver",
    description:
      "Instrument should include a notarial acknowledgment and address homestead / dower / spousal-consent where applicable.",
    citation: recordingAct(),
    playbooks: [BNK_PLAYBOOK_DOT],
    missing_title: "Acknowledgment / homestead clause missing",
    missing_description:
      "No notarial acknowledgment or homestead / spousal-consent clause was found.",
    explanation:
      "Notarial acknowledgment is required for recording in nearly every state; homestead waiver / spousal consent is required in many states (TX, FL) for valid lien against the homestead.",
    recommendation:
      "Add 'Acknowledgment' (notarial) and 'Homestead / Spousal Consent' where applicable.",
    present_patterns: [
      /(acknowledg(e|ment)|notar(y|ial|ized))/i,
      /(homestead|spousal|dower|community\s+property)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// L.8 — UCC-1 financing statement (prose components). 6 rules: BNK-045..BNK-050.
// ────────────────────────────────────────────────────────────────────

const UCC1_RULES: Rule[] = [
  presence({
    id: "BNK-045",
    name: "Debtor name — exact legal name (§ 9-503)",
    description:
      "UCC-1 must list debtor's exact legal name — registered organization name from public organic record (§ 9-503).",
    citation: ucc("9-503", "Sufficiency of debtor's name"),
    playbooks: [BNK_PLAYBOOK_UCC1],
    missing_title: "Debtor exact-legal-name clause missing",
    missing_description: "No clause was found stating debtor's exact legal name.",
    explanation:
      "§ 9-503 requires the financing statement to use the debtor's exact legal name — for registered organizations, the name on the most recent public organic record. Errors are seriously misleading and can defeat perfection (§ 9-506).",
    recommendation:
      "State debtor's exact legal name from the public organic record (Secretary of State filing) and identify the type / jurisdiction of organization.",
    present_patterns: [
      /(exact\s+legal\s+name|registered\s+(name|organization))/i,
      /(secretary\s+of\s+state|public\s+organic\s+record)/i,
    ],
  }),
  presence({
    id: "BNK-046",
    name: "Secured party name + address",
    description: "UCC-1 must list secured party name and address (§ 9-502).",
    citation: ucc("9-502", "Contents of financing statement"),
    playbooks: [BNK_PLAYBOOK_UCC1],
    missing_title: "Secured party / address clause missing",
    missing_description: "No clause was found stating secured party's name and address.",
    explanation:
      "§ 9-502(a)(2) requires the name and mailing address of the secured party of record.",
    recommendation:
      "State secured party's exact name and mailing address (and, where used, the filing-agent's address).",
    present_patterns: [/secured\s+party/i, /(address|mailing\s+address|c\/o)/i],
  }),
  presence({
    id: "BNK-047",
    name: "Collateral description / indication (§ 9-504)",
    description:
      "UCC-1 must indicate the collateral covered (§ 9-504): description or 'all assets' / 'all personal property'.",
    citation: ucc("9-504", "Collateral indication"),
    playbooks: [BNK_PLAYBOOK_UCC1],
    missing_title: "Collateral indication clause missing",
    missing_description: "No collateral indication / description was found.",
    explanation:
      "§ 9-504 permits the financing statement to indicate collateral by description satisfying § 9-108 OR by 'all assets' / 'all personal property' supercollateral language.",
    recommendation:
      "Add a collateral block describing the collateral OR the 'all assets / all personal property' supercollateral indication.",
    present_patterns: [
      /collateral/i,
      /(all\s+(assets?|personal\s+property)|accounts?|inventory|equipment|general\s+intangibles?)/i,
    ],
  }),
  presence({
    id: "BNK-048",
    name: "Filing office identification",
    description:
      "UCC-1 should identify the filing office (state SoS) — typically based on debtor's location (§ 9-307).",
    citation: ucc("9-307", "Debtor's location"),
    playbooks: [BNK_PLAYBOOK_UCC1],
    missing_title: "Filing-office identification clause missing",
    missing_description: "No filing-office identification was found.",
    explanation:
      "Under § 9-307, a registered organization is located in the state of organization. The UCC-1 must be filed in the proper state's UCC office.",
    recommendation:
      "Identify the filing office (e.g., 'Delaware Secretary of State, UCC Division').",
    present_patterns: [
      /(secretary\s+of\s+state|filing\s+office|ucc\s+division)/i,
      /(delaware|california|new\s+york|texas|state\s+of)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "BNK-049",
    name: "Lapse / continuation timeline (5-year + continuation window)",
    description:
      "UCC-1 documentation should reference 5-year lapse and 6-month continuation window (§ 9-515).",
    citation: ucc("9-515", "Duration / continuation"),
    playbooks: [BNK_PLAYBOOK_UCC1],
    missing_title: "Lapse / continuation timeline clause missing",
    missing_description:
      "No clause referencing 5-year lapse / 6-month continuation window was found.",
    explanation:
      "§ 9-515 sets a 5-year effective period; a continuation statement must be filed in the 6 months immediately before lapse. Missed continuation = loss of perfection.",
    recommendation:
      "Reference the 5-year duration and the 6-month continuation window so the filing party tracks calendar deadlines.",
    present_patterns: [
      /(5\s+years?|five\s+years?|lapse|expir)/i,
      /(continuation|6\s+months?|six\s+months?)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "BNK-050",
    name: "Authorization by debtor (§ 9-509)",
    description: "UCC-1 must be filed with debtor's authentication / authorization (§ 9-509(a)).",
    citation: ucc("9-509", "Authorization to file"),
    playbooks: [BNK_PLAYBOOK_UCC1],
    missing_title: "Debtor-authorization clause missing",
    missing_description: "No debtor-authorization clause was found.",
    explanation:
      "§ 9-509(a)(1) requires the debtor's authentication (signed security agreement or other authorization). Unauthorized filings expose the filer to § 9-625(b) damages.",
    recommendation:
      "Reference the debtor's signed security agreement / authorization for the filing (e.g., 'authorized by Security Agreement of [date]').",
    present_patterns: [
      /(authoriz(e|ed|ation)|debtor.{0,20}(authorizes?|authenticated))/i,
      /(security\s+agreement|9.?509)/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate. 50 rules total.
// ────────────────────────────────────────────────────────────────────

export const BANKING_RULES: Rule[] = [
  ...PROMISSORY_NOTE_RULES,
  ...LOAN_AGREEMENT_RULES,
  ...SECURITY_AGREEMENT_RULES,
  ...GUARANTY_RULES,
  ...INTERCREDITOR_RULES,
  ...SUBORDINATION_RULES,
  ...DEED_OF_TRUST_RULES,
  ...UCC1_RULES,
];

export {
  PROMISSORY_NOTE_RULES,
  LOAN_AGREEMENT_RULES,
  SECURITY_AGREEMENT_RULES,
  GUARANTY_RULES,
  INTERCREDITOR_RULES,
  SUBORDINATION_RULES,
  DEED_OF_TRUST_RULES,
  UCC1_RULES,
};
