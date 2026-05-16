/**
 * v4 Equity / cap-table ruleset — 70 rules (spec-v4.md §6.C, Step 46).
 *
 * Nine playbooks (SAFE, convertible note, option grant, RSU, RSPA,
 * § 83(b) election, IRA, voting agreement, ROFR / co-sale). Citations
 * anchor to NVCA model docs, IRC § 409A / § 422 / § 83 / § 83(b),
 * Treas. Reg. § 1.83-2 / § 1.83-7, UCC Article 3, DGCL §§ 202, 218,
 * and state usury caps for the convertible-note family.
 *
 * Rule ids are flat `EQT-NNN` (001..070); each rule's
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
  EQT_PLAYBOOK_SAFE,
  EQT_PLAYBOOK_CONV_NOTE,
  EQT_PLAYBOOK_OPTION_GRANT,
  EQT_PLAYBOOK_RSU,
  EQT_PLAYBOOK_RSPA,
  EQT_PLAYBOOK_83B,
  EQT_PLAYBOOK_IRA,
  EQT_PLAYBOOK_VOTING,
  EQT_PLAYBOOK_ROFR,
  irc,
  treasReg,
  nvca,
  ycSafe,
  ucc3,
  dgcl,
  usuryGeneric,
  eqtPractice,
} from "./_helpers.js";

const CATEGORY = "equity";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });
const language = (s: Omit<V4LanguageSpec, "category">): Rule =>
  buildV4LanguageRule({ ...s, category: CATEGORY });
const compound = (s: Omit<V4CompoundSpec, "category">): Rule =>
  buildV4CompoundRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// C.1 — SAFE (Simple Agreement for Future Equity, Y Combinator).
// 9 rules: EQT-001..EQT-009.
// ────────────────────────────────────────────────────────────────────

const SAFE_RULES: Rule[] = [
  presence({
    id: "EQT-001",
    name: "SAFE identifies post-money vs pre-money variant",
    description:
      "Y Combinator publishes both post-money (2018+) and pre-money (legacy) SAFE templates; dilution mechanics differ materially.",
    citation: ycSafe("post-money"),
    playbooks: [EQT_PLAYBOOK_SAFE],
    missing_title: "Post-money / pre-money variant not identified",
    missing_description: "The SAFE does not state whether it is a post-money or pre-money variant.",
    explanation:
      "Post-money SAFEs (2018+) dilute existing equity but not other post-money SAFEs in the same round; pre-money SAFEs dilute each other. Investors and founders must know which they are signing.",
    recommendation:
      "Add a recital identifying the SAFE as post-money or pre-money and (for post-money) reference Y Combinator's 2018 templates.",
    present_patterns: [/post.money/i, /pre.money/i],
  }),
  presence({
    id: "EQT-002",
    name: "Conversion event defined (Equity Financing)",
    description:
      "SAFE must define the conversion event — typically the next preferred-stock financing above a threshold.",
    citation: ycSafe("post-money"),
    playbooks: [EQT_PLAYBOOK_SAFE],
    missing_title: "Equity Financing / conversion event clause missing",
    missing_description: "No Equity Financing or equivalent conversion-event definition was found.",
    explanation:
      "Without a defined Equity Financing the SAFE cannot convert. YC templates use 'Equity Financing' or 'Standard Preferred Stock' as the trigger.",
    recommendation:
      "Add a 'Definitions' clause defining Equity Financing (a bona fide transaction with the principal purpose of raising capital, pursuant to which the Company issues and sells Preferred Stock).",
    present_patterns: [
      /equity\s+financing/i,
      /preferred\s+stock\s+financing/i,
      /next\s+priced\s+round/i,
    ],
  }),
  presence({
    id: "EQT-003",
    name: "Valuation cap or discount rate stated",
    description: "SAFE must specify at least one of: valuation cap, discount rate, or MFN.",
    citation: ycSafe("post-money"),
    playbooks: [EQT_PLAYBOOK_SAFE],
    missing_title: "Valuation cap / discount / MFN missing",
    missing_description:
      "Neither a valuation cap, a discount rate, nor an MFN provision was found.",
    explanation:
      "The economic essence of a SAFE is the conversion price. Without a cap, discount, or MFN, the SAFE converts at the next round price with no investor upside.",
    recommendation:
      "Specify a 'Post-Money Valuation Cap', a 'Discount Rate' (commonly 80%), or 'Most Favored Nation' treatment — at minimum one.",
    present_patterns: [
      /post.money\s+valuation\s+cap/i,
      /valuation\s+cap/i,
      /discount\s+rate/i,
      /most\s+favored\s+nation/i,
      /\bmfn\b/i,
    ],
  }),
  presence({
    id: "EQT-004",
    name: "Liquidity event treatment",
    description: "SAFE must address acquisition / change of control before conversion.",
    citation: ycSafe("post-money"),
    playbooks: [EQT_PLAYBOOK_SAFE],
    missing_title: "Liquidity-event treatment clause missing",
    missing_description:
      "No clause was found addressing what happens on a liquidity event (acquisition, change of control, IPO).",
    explanation:
      "YC SAFE treats acquisition as a liquidity event where the investor receives the greater of (a) the purchase amount or (b) the as-converted amount. Without it the investor's exit treatment is undefined.",
    recommendation:
      "Add a 'Liquidity Event' section providing for the investor's choice of cash-back or as-converted treatment on acquisition / change of control.",
    present_patterns: [/liquidity\s+event/i, /change\s+of\s+control/i, /acquisition/i],
  }),
  presence({
    id: "EQT-005",
    name: "Dissolution event treatment",
    description: "SAFE must address treatment on dissolution.",
    citation: ycSafe("post-money"),
    playbooks: [EQT_PLAYBOOK_SAFE],
    missing_title: "Dissolution-event clause missing",
    missing_description: "No clause was found addressing dissolution.",
    explanation:
      "YC SAFE gives the investor a return-of-purchase-amount priority on dissolution before common stockholders.",
    recommendation:
      "Add a 'Dissolution Event' clause prioritizing return of purchase amount before any distribution to common.",
    present_patterns: [/dissolution/i],
  }),
  presence({
    id: "EQT-006",
    name: "MFN provision references later instruments",
    description:
      "MFN should clearly attach to subsequent SAFEs or convertible securities of the company.",
    citation: ycSafe("post-money"),
    playbooks: [EQT_PLAYBOOK_SAFE],
    missing_title: "MFN scope unclear or absent",
    missing_description:
      "No MFN clause was found, or the MFN does not specify the universe of later instruments to which it attaches.",
    explanation:
      "An MFN that does not specify 'subsequent SAFEs' or 'subsequent convertible securities' is ambiguous and may not extend to later raises.",
    recommendation:
      "Phrase the MFN to attach to 'any subsequent convertible instrument' the Company issues prior to the Equity Financing.",
    present_patterns: [
      /most\s+favored\s+nation.{0,80}(subsequent|future|later)/is,
      /\bmfn\b.{0,80}(subsequent|future|later)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-007",
    name: "Representations of the company and the investor",
    description:
      "SAFE should carry baseline representations of the company and accredited-investor representation of the investor (Reg D Rule 506).",
    citation: ycSafe("post-money"),
    playbooks: [EQT_PLAYBOOK_SAFE],
    missing_title: "Reps clause missing",
    missing_description: "No company / investor representations clause was found.",
    explanation:
      "YC templates include reciprocal representations and the investor's accredited-investor representation under Reg D Rule 506(b)/(c).",
    recommendation:
      "Add 'Representations' covering the company's authority and the investor's accredited-investor status.",
    present_patterns: [/accredited\s+investor/i, /representations?\s+(of|and\s+warranties)/i],
  }),
  language({
    id: "EQT-008",
    name: "Interest-bearing SAFE language",
    description:
      "A SAFE is not a debt instrument; interest accrual is inconsistent with the YC SAFE form.",
    citation: ycSafe("post-money"),
    playbooks: [EQT_PLAYBOOK_SAFE],
    bad_patterns: [
      /this\s+safe\s+(shall|will)\s+(bear|accrue)\s+interest/i,
      /interest\s+(rate|accrues|shall\s+accrue)\s+(at|of)\s+\d/i,
    ],
    bad_title: "SAFE appears to bear interest — re-characterization risk",
    bad_description:
      "The SAFE includes interest-accrual language, which is inconsistent with the YC template and may indicate a convertible note in disguise.",
    explanation:
      "SAFEs are equity-like; interest is the hallmark of a convertible note. Interest accrual is also state-law-sensitive under usury caps.",
    recommendation:
      "Strike the interest provision. If interest is desired use a convertible note instead.",
    default_severity: "critical",
  }),
  presence({
    id: "EQT-009",
    name: "Governing law and forum (Delaware)",
    description: "YC SAFE governing law is Delaware unless modified.",
    citation: ycSafe("post-money"),
    playbooks: [EQT_PLAYBOOK_SAFE],
    missing_title: "Governing-law clause missing",
    missing_description: "No governing-law clause was found.",
    explanation:
      "YC templates govern by Delaware law. Silence creates ambiguity about which corporate-law regime controls conversion mechanics.",
    recommendation: "Add 'Governing Law' selecting Delaware.",
    present_patterns: [/governing\s+law/i, /governed\s+by\s+the\s+laws/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// C.2 — Convertible Promissory Note. UCC Art. 3; state usury.
// 9 rules: EQT-010..EQT-018.
// ────────────────────────────────────────────────────────────────────

const CONVERTIBLE_NOTE_RULES: Rule[] = [
  presence({
    id: "EQT-010",
    name: "Principal amount stated",
    description:
      "Convertible note must state principal (UCC § 3-104 — unconditional promise to pay a fixed amount).",
    citation: ucc3("104"),
    playbooks: [EQT_PLAYBOOK_CONV_NOTE],
    missing_title: "Principal amount missing",
    missing_description: "No stated principal amount was found.",
    explanation:
      "UCC § 3-104 requires a negotiable instrument to state an unconditional promise to pay a fixed amount of money.",
    recommendation:
      "Add 'FOR VALUE RECEIVED, [Maker] promises to pay to the order of [Payee] the principal amount of $[X]'.",
    present_patterns: [
      /principal\s+amount\s+of\s+\$/i,
      /promise(s)?\s+to\s+pay/i,
      /for\s+value\s+received/i,
    ],
  }),
  presence({
    id: "EQT-011",
    name: "Interest rate stated",
    description:
      "Convertible note should state interest rate (vs. SAFE which does not bear interest).",
    citation: ucc3("104"),
    playbooks: [EQT_PLAYBOOK_CONV_NOTE],
    missing_title: "Interest rate missing",
    missing_description: "No interest-rate clause was found.",
    explanation:
      "Convertible notes carry interest; absence is the hallmark of a SAFE. The note should specify a simple or compound rate and accrual convention.",
    recommendation:
      "Add 'Interest shall accrue on the unpaid principal at a rate of [X]% per annum, compounded annually, until paid in full or converted'.",
    present_patterns: [
      /interest\s+(rate|shall|accrues?|of\s+\d)/i,
      /\d+(\.\d+)?\s*%\s*per\s+annum/i,
    ],
  }),
  language({
    id: "EQT-012",
    name: "Interest rate above plausible usury threshold",
    description:
      "Most state usury caps for non-bank lenders sit in the 7–24% range; rates above 25% are heuristically usurious in many states.",
    citation: usuryGeneric(),
    playbooks: [EQT_PLAYBOOK_CONV_NOTE],
    bad_patterns: [/(2[5-9]|[3-9]\d|1\d{2,})\s*%\s*per\s+annum/i],
    bad_title: "Interest rate may exceed state usury cap",
    bad_description:
      "The convertible note carries an interest rate at or above 25% per annum, which exceeds many state usury caps.",
    explanation:
      "Many state usury statutes cap non-bank consumer / commercial lending in the 7–24% range. Confirm against the applicable state's usury statute and corporate-lender exception.",
    recommendation:
      "Verify the rate against the applicable state's usury cap and corporate-borrower exception; consider a 'usury savings' clause capping at the legal maximum.",
    default_severity: "critical",
  }),
  presence({
    id: "EQT-013",
    name: "Maturity date specified",
    description: "Convertible note must have a maturity date.",
    citation: ucc3("108"),
    playbooks: [EQT_PLAYBOOK_CONV_NOTE],
    missing_title: "Maturity date missing",
    missing_description: "No maturity-date clause was found.",
    explanation:
      "UCC § 3-108 requires the time of payment to be on demand or at a definite time. A note without a maturity date is non-negotiable.",
    recommendation:
      "Add 'Maturity Date' stating a date certain on which principal and accrued interest become due if not previously converted.",
    present_patterns: [/maturity\s+date/i, /due\s+(on|and\s+payable\s+on)/i],
  }),
  presence({
    id: "EQT-014",
    name: "Qualified financing / conversion mechanics",
    description:
      "Convertible note must define qualified-financing trigger and conversion price (discount and/or cap).",
    citation: eqtPractice(
      "convertible-note-practice",
      "Practitioner-baseline convertible note (NVCA / Cooley / Wilson Sonsini forms)",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [EQT_PLAYBOOK_CONV_NOTE],
    missing_title: "Qualified-financing conversion clause missing",
    missing_description: "No qualified-financing conversion mechanics were found.",
    explanation:
      "Without a defined qualified financing and conversion price, the note cannot convert — it would simply mature as debt.",
    recommendation:
      "Add 'Qualified Financing' (threshold-sized preferred-stock financing) and the conversion price = lesser of (discount × QF price) or (cap ÷ FDC).",
    present_patterns: [
      /qualified\s+financing/i,
      /next\s+equity\s+financing/i,
      /(discount\s+rate|valuation\s+cap)/i,
    ],
  }),
  presence({
    id: "EQT-015",
    name: "Change-of-control treatment",
    description: "Convertible note must address change of control before conversion.",
    citation: eqtPractice(
      "cn-change-of-control",
      "Convertible-note change-of-control practice (NVCA / Cooley)",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [EQT_PLAYBOOK_CONV_NOTE],
    missing_title: "Change-of-control clause missing",
    missing_description: "No change-of-control clause was found.",
    explanation:
      "Practice baseline: investor's choice of (a) repayment plus premium (1.5–2x) or (b) conversion immediately prior to the change of control at the cap.",
    recommendation:
      "Add a 'Change of Control' clause with both repayment-with-premium and pre-closing-conversion alternatives at investor option.",
    present_patterns: [/change\s+of\s+control/i, /sale\s+of\s+the\s+(company|business)/i],
  }),
  presence({
    id: "EQT-016",
    name: "Subordination acknowledgment",
    description:
      "Convertible notes are typically subordinate to senior debt — clause should say so.",
    citation: eqtPractice(
      "cn-subordination",
      "Practitioner-baseline subordination treatment",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [EQT_PLAYBOOK_CONV_NOTE],
    missing_title: "Subordination clause missing",
    missing_description: "No subordination clause was found.",
    explanation:
      "Practice baseline subordinates convertible notes to senior bank debt and venture debt.",
    recommendation:
      "Add 'Subordination' subordinating the note to existing and future senior indebtedness.",
    present_patterns: [/subordinat/i],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-017",
    name: "Events of default enumerated",
    description: "Convertible note must enumerate events of default.",
    citation: ucc3("104"),
    playbooks: [EQT_PLAYBOOK_CONV_NOTE],
    missing_title: "Events-of-default clause missing",
    missing_description: "No events-of-default clause was found.",
    explanation:
      "Without defined defaults the lender's remedies are limited; standard list: non-payment, bankruptcy, material breach.",
    recommendation:
      "Add 'Events of Default' including non-payment, voluntary / involuntary bankruptcy, and material breach with cure period.",
    present_patterns: [/events?\s+of\s+default/i],
  }),
  presence({
    id: "EQT-018",
    name: "Investor accredited-investor representation",
    description:
      "Convertible notes are sold under Reg D Rule 506; investor must represent accredited-investor status.",
    citation: eqtPractice(
      "reg-d-506",
      "SEC Regulation D Rule 506 — Accredited Investor",
      "https://www.law.cornell.edu/cfr/text/17/230.506",
    ),
    playbooks: [EQT_PLAYBOOK_CONV_NOTE],
    missing_title: "Accredited-investor representation missing",
    missing_description: "No accredited-investor representation was found.",
    explanation:
      "Practice baseline: a Reg D Rule 506(b) / (c) offering requires the issuer to reasonably believe investors are accredited.",
    recommendation:
      "Add an 'Investor Representations' section confirming accredited-investor status under Rule 501.",
    present_patterns: [/accredited\s+investor/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// C.3 — Stock Option Grant Notice + Agreement. IRC § 409A / § 422.
// 10 rules: EQT-019..EQT-028.
// ────────────────────────────────────────────────────────────────────

const OPTION_GRANT_RULES: Rule[] = [
  presence({
    id: "EQT-019",
    name: "Grant date and number of shares stated",
    description:
      "Grant notice must state grant date and the number of shares subject to the option.",
    citation: irc("422", "Incentive Stock Options"),
    playbooks: [EQT_PLAYBOOK_OPTION_GRANT],
    missing_title: "Grant date / number of shares missing",
    missing_description: "No grant date or number of shares clause was found.",
    explanation:
      "IRC § 422(b)(7) requires ISO grants to state grant date; § 409A grants need an objective grant date.",
    recommendation: "Add 'Grant Date' and 'Number of Shares' lines in the grant notice header.",
    present_patterns: [
      /grant\s+date/i,
      /number\s+of\s+shares/i,
      /shares?\s+subject\s+to\s+(the\s+)?option/i,
    ],
  }),
  presence({
    id: "EQT-020",
    name: "Exercise price stated",
    description: "Option grant must state exercise price.",
    citation: irc("409A", "Stock right valuation"),
    playbooks: [EQT_PLAYBOOK_OPTION_GRANT],
    missing_title: "Exercise price missing",
    missing_description: "No exercise-price clause was found.",
    explanation:
      "IRC § 409A and § 422 both require the exercise price to be no less than fair market value at grant. Silence creates immediate § 409A exposure.",
    recommendation:
      "Add 'Exercise Price' line stating the per-share price (must be ≥ FMV at grant).",
    present_patterns: [/exercise\s+price/i, /strike\s+price/i],
  }),
  presence({
    id: "EQT-021",
    name: "Fair-market-value-at-grant representation",
    description:
      "Grant must represent that the exercise price equals or exceeds FMV at grant (§ 409A safe harbor / § 422(b)(4)).",
    citation: treasReg("1.409A-1(b)(5)(iv)", "FMV safe harbors"),
    playbooks: [EQT_PLAYBOOK_OPTION_GRANT],
    missing_title: "FMV-at-grant representation missing",
    missing_description: "No fair-market-value-at-grant representation was found.",
    explanation:
      "§ 409A safe-harbor requires the exercise price to be no less than the FMV at grant. Boards typically rely on a 409A valuation; the grant should recite the FMV determination.",
    recommendation:
      "Add a recital that the exercise price is equal to or greater than the FMV of the Common Stock as determined by the Board in good faith on the Grant Date.",
    present_patterns: [/fair\s+market\s+value/i, /\bfmv\b/i, /409a\s+valuation/i],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-022",
    name: "Vesting schedule stated",
    description: "Grant must state vesting schedule.",
    citation: eqtPractice(
      "vesting-practice",
      "Standard 4-year vesting / 1-year cliff practice (NVCA + Common Paper)",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [EQT_PLAYBOOK_OPTION_GRANT],
    missing_title: "Vesting schedule missing",
    missing_description: "No vesting-schedule clause was found.",
    explanation:
      "Standard: 4-year vesting with 1-year cliff. Absence makes the option immediately vested (the default), which is rarely intended.",
    recommendation:
      "Add 'Vesting Schedule' stating 4-year monthly vesting with a 1-year cliff (or chosen variant).",
    present_patterns: [
      /vesting\s+schedule/i,
      /(monthly|quarterly|annually)\s+(vest|over)/is,
      /cliff/i,
    ],
  }),
  presence({
    id: "EQT-023",
    name: "ISO vs NSO designation",
    description:
      "Grant must designate the option as an Incentive Stock Option (§ 422) or Non-qualified Stock Option.",
    citation: irc("422"),
    playbooks: [EQT_PLAYBOOK_OPTION_GRANT],
    missing_title: "ISO / NSO designation missing",
    missing_description: "No ISO / NSO designation was found.",
    explanation:
      "Tax treatment differs sharply: ISOs require § 422 qualification (10-year term, FMV exercise price, $100K limit, employee status, etc.); NSOs trigger ordinary income at exercise.",
    recommendation:
      "Add an 'Option Type' line clearly designating Incentive Stock Option or Non-qualified Stock Option.",
    present_patterns: [
      /incentive\s+stock\s+option/i,
      /\biso\b/i,
      /non.qualified\s+stock\s+option/i,
      /\bnso\b/i,
      /\bnqso\b/i,
    ],
  }),
  presence({
    id: "EQT-024",
    name: "ISO — $100,000 annual limit acknowledgment",
    description:
      "ISO grants vesting in any single year > $100K aggregate FMV at grant convert to NSOs (§ 422(d)).",
    citation: irc("422(d)", "ISO $100,000 limit"),
    playbooks: [EQT_PLAYBOOK_OPTION_GRANT],
    missing_title: "ISO $100K-limit acknowledgment missing",
    missing_description: "No acknowledgment of the § 422(d) ISO $100K-per-year limit was found.",
    explanation:
      "If aggregate FMV of stock with respect to which ISOs are exercisable for the first time in any calendar year exceeds $100K, the excess converts to NSO treatment.",
    recommendation:
      "Add an acknowledgment that ISOs in excess of the § 422(d) $100K annual limit are treated as NSOs.",
    present_patterns: [/\$100,?000/i, /section\s+422\s*\(d\)/i, /100,?000.{0,40}limit/is],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-025",
    name: "Post-termination exercise window",
    description:
      "Option must specify post-termination exercise window (typically 3 months for ISO under § 422).",
    citation: irc("422(a)(2)", "ISO 3-month post-termination rule"),
    playbooks: [EQT_PLAYBOOK_OPTION_GRANT],
    missing_title: "Post-termination exercise window missing",
    missing_description: "No post-termination exercise window was found.",
    explanation:
      "ISO status is lost if option exercised more than 3 months after termination (12 months for disability; longer post-death). Grant should specify.",
    recommendation:
      "Add 'Post-Termination Exercise' specifying 3 months (ISO), 12 months disability, and a chosen post-death window.",
    present_patterns: [
      /post.termination/i,
      /3\s+months?\s+after\s+termination/i,
      /ninety\s*\(?90\)?\s+days?/i,
      /exercise\s+period.{0,40}termination/is,
    ],
  }),
  presence({
    id: "EQT-026",
    name: "Option expiration / maximum term (10 years)",
    description: "ISOs cap at 10-year term per § 422(b)(3); NSOs follow the same convention.",
    citation: irc("422(b)(3)"),
    playbooks: [EQT_PLAYBOOK_OPTION_GRANT],
    missing_title: "Option-expiration / maximum-term clause missing",
    missing_description: "No expiration-date clause was found.",
    explanation:
      "Option without a stated expiration is non-qualifying under § 422 and creates uncertainty for the holder.",
    recommendation:
      "Add 'Expiration Date' stating the option expires on the 10-year anniversary of the Grant Date.",
    present_patterns: [/expiration\s+date/i, /ten\s*\(?10\)?\s+years/i, /\b10.year\s+term\b/i],
  }),
  presence({
    id: "EQT-027",
    name: "Plan reference",
    description: "Grant must reference the equity-incentive plan under which it is granted.",
    citation: eqtPractice(
      "equity-plan-reference",
      "Practitioner-baseline equity-plan reference",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [EQT_PLAYBOOK_OPTION_GRANT],
    missing_title: "Plan-reference missing",
    missing_description: "No equity-plan reference was found.",
    explanation:
      "Stand-alone option grants exist but are unusual; the standard pattern is grants under an equity-incentive plan with the plan controlling on conflict.",
    recommendation:
      "Reference the plan name and effective date; state that the plan controls in case of conflict.",
    present_patterns: [/equity\s+incentive\s+plan/i, /the\s+plan/i, /stock\s+plan/i],
  }),
  language({
    id: "EQT-028",
    name: "Repricing without stockholder approval",
    description:
      "Most equity-incentive plans prohibit repricing without stockholder approval; standalone repricing language is suspicious.",
    citation: eqtPractice(
      "repricing-practice",
      "Equity-plan repricing practice (NYSE / Nasdaq listed-issuer rules)",
      "https://nyseguide.srorules.com/listed-company-manual/",
    ),
    playbooks: [EQT_PLAYBOOK_OPTION_GRANT],
    bad_patterns: [/reprice.{0,80}without.{0,40}(stockholder|shareholder)\s+approval/is],
    bad_title: "Repricing without stockholder approval permitted",
    bad_description:
      "The grant permits the board to reprice the option without stockholder approval, in tension with listed-issuer governance and most plan terms.",
    explanation:
      "NYSE / Nasdaq listing standards generally require stockholder approval for repricing. Most well-drafted plans incorporate this constraint.",
    recommendation: "Strike the repricing override; rely on the plan's standard repricing limits.",
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// C.4 — RSU grant. IRC § 409A; Treas. Reg. § 1.83.
// 7 rules: EQT-029..EQT-035.
// ────────────────────────────────────────────────────────────────────

const RSU_RULES: Rule[] = [
  presence({
    id: "EQT-029",
    name: "Grant date and number of units",
    description: "RSU grant must state grant date and number of units.",
    citation: irc("83"),
    playbooks: [EQT_PLAYBOOK_RSU],
    missing_title: "Grant date / number of units missing",
    missing_description: "No grant date or number-of-units clause was found.",
    explanation: "Number of units and grant date anchor the § 83 income measurement.",
    recommendation: "Add 'Grant Date' and 'Number of Units' header lines.",
    present_patterns: [
      /grant\s+date/i,
      /(number\s+of\s+units|number\s+of\s+rsus|units\s+granted)/i,
    ],
  }),
  presence({
    id: "EQT-030",
    name: "Vesting schedule for RSUs",
    description: "Standard 4-year vesting / 1-year cliff or similar.",
    citation: eqtPractice(
      "rsu-vesting",
      "Standard RSU vesting (Common Paper / NVCA)",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [EQT_PLAYBOOK_RSU],
    missing_title: "Vesting schedule missing",
    missing_description: "No RSU vesting-schedule clause was found.",
    explanation: "RSU vesting controls when settlement (and taxation) occurs.",
    recommendation: "Add 'Vesting' with cliff and tail; reference the plan.",
    present_patterns: [/vesting/i, /cliff/i],
  }),
  presence({
    id: "EQT-031",
    name: "Settlement timing — § 409A short-term-deferral",
    description:
      "Settlement should occur within the § 409A short-term-deferral window (by 2.5 months after vest) or be a § 409A-compliant deferred-compensation plan.",
    citation: treasReg("1.409A-1(b)(4)", "Short-term deferral"),
    playbooks: [EQT_PLAYBOOK_RSU],
    missing_title: "Settlement-timing clause missing",
    missing_description: "No settlement-timing clause was found.",
    explanation:
      "Under Treas. Reg. § 1.409A-1(b)(4), short-term deferral status requires settlement by 2.5 months after the year in which the right vests. Outside that window the RSU is § 409A deferred compensation.",
    recommendation:
      "Add 'Settlement' stating the units settle on (or as soon as practicable after, but no later than 2.5 months after) the vesting date.",
    present_patterns: [/settlement/i, /short.term\s+deferral/i, /2\.5\s+months?/i],
  }),
  presence({
    id: "EQT-032",
    name: "Tax-withholding mechanics",
    description: "RSU vesting triggers FICA / FIT withholding under § 3401.",
    citation: irc("3401", "Withholding"),
    playbooks: [EQT_PLAYBOOK_RSU],
    missing_title: "Tax-withholding mechanics clause missing",
    missing_description: "No tax-withholding clause was found.",
    explanation:
      "Companies typically use sell-to-cover, net settlement, or required cash withholding to satisfy mandatory withholding at vest.",
    recommendation:
      "Add 'Tax Withholding' specifying sell-to-cover or net-share settlement and the holder's obligation if withholding cannot be satisfied.",
    present_patterns: [/withholding/i, /sell.to.cover/i, /net\s+settlement/i],
  }),
  presence({
    id: "EQT-033",
    name: "No § 83(b) for RSUs",
    description:
      "§ 83(b) elections are not available for RSUs (no current property transfer); grant should make this clear.",
    citation: treasReg("1.83-2", "§ 83(b) elections"),
    playbooks: [EQT_PLAYBOOK_RSU],
    missing_title: "§ 83(b)-not-available clause missing",
    missing_description:
      "No clause was found explaining that § 83(b) elections are not available for RSUs.",
    explanation:
      "Treas. Reg. § 1.83-2 requires property to be transferred for a § 83(b) election to be available. RSUs (mere promises) are not property until settlement.",
    recommendation:
      "Add a recital that an 83(b) election is not available with respect to the Units because no property is transferred at grant.",
    present_patterns: [
      /83\s*\(\s*b\s*\).{0,80}not\s+(available|applicable)/is,
      /no\s+(section\s+)?83\s*\(\s*b\s*\)\s+election/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-034",
    name: "Termination of service — unvested units forfeited",
    description: "RSU grant should state that unvested units are forfeited on termination.",
    citation: eqtPractice(
      "rsu-forfeiture",
      "Standard RSU forfeiture on termination",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [EQT_PLAYBOOK_RSU],
    missing_title: "Termination-forfeiture clause missing",
    missing_description: "No termination-forfeiture clause was found.",
    explanation:
      "Standard practice: unvested RSUs are forfeited on termination of service for any reason. Without this, holder may claim continued vesting.",
    recommendation:
      "Add 'Termination of Service' stating any Units not vested as of the termination date are forfeited.",
    present_patterns: [/forfeit/i, /termination\s+of\s+(service|employment)/i],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-035",
    name: "Plan reference and conflict-resolution",
    description: "RSU agreement must reference its plan and provide a conflict rule.",
    citation: eqtPractice(
      "rsu-plan-reference",
      "Standard plan-reference language",
      "https://nvca.org/model-legal-documents/",
    ),
    playbooks: [EQT_PLAYBOOK_RSU],
    missing_title: "Plan-reference / conflict-resolution missing",
    missing_description: "No plan reference or conflict-resolution clause was found.",
    explanation:
      "Standard pattern: the equity-incentive plan governs and controls in case of conflict.",
    recommendation:
      "Add a reference to the plan, including a statement that the plan controls on any inconsistency.",
    present_patterns: [/equity\s+incentive\s+plan/i, /the\s+plan/i],
  }),
];

// ────────────────────────────────────────────────────────────────────
// C.5 — Restricted Stock Purchase Agreement (RSPA). IRC § 83.
// 7 rules: EQT-036..EQT-042.
// ────────────────────────────────────────────────────────────────────

const RSPA_RULES: Rule[] = [
  presence({
    id: "EQT-036",
    name: "Purchase price stated",
    description: "RSPA must state purchase price (often par or de minimis).",
    citation: irc("83"),
    playbooks: [EQT_PLAYBOOK_RSPA],
    missing_title: "Purchase price missing",
    missing_description: "No purchase-price clause was found.",
    explanation:
      "Without a purchase price the property is treated as compensation income at FMV on transfer (§ 83(a)).",
    recommendation: "Add 'Purchase Price' line with per-share price.",
    present_patterns: [/purchase\s+price/i, /price\s+per\s+share/i],
  }),
  presence({
    id: "EQT-037",
    name: "Vesting / repurchase right",
    description: "RSPA must specify vesting schedule and corresponding repurchase right.",
    citation: dgcl("202"),
    playbooks: [EQT_PLAYBOOK_RSPA],
    missing_title: "Vesting / repurchase right missing",
    missing_description: "No vesting or repurchase-right clause was found.",
    explanation:
      "Standard pattern: 4-year vesting with 1-year cliff, and the company has the right to repurchase unvested shares at original cost on termination.",
    recommendation:
      "Add 'Vesting' and 'Repurchase Right' covering company's right to repurchase unvested shares on termination.",
    present_patterns: [/vesting/i, /repurchase\s+right/i, /unvested\s+shares/i],
  }),
  presence({
    id: "EQT-038",
    name: "§ 83(b) election advisory",
    description: "RSPA must include § 83(b) election advisory and 30-day deadline.",
    citation: treasReg("1.83-2", "§ 83(b) election"),
    playbooks: [EQT_PLAYBOOK_RSPA],
    missing_title: "§ 83(b) election advisory missing",
    missing_description: "No § 83(b) election advisory was found.",
    explanation:
      "Treas. Reg. § 1.83-2(b) requires the § 83(b) election to be filed within 30 days of transfer. Missing the deadline cannot be cured; the advisory protects the recipient.",
    recommendation:
      "Add an 83(b) advisory recital and exhibit the § 83(b) election form; recommend consultation with tax advisor.",
    present_patterns: [
      /83\s*\(\s*b\s*\)/i,
      /thirty\s*\(?30\)?\s+days/i,
      /30.day\s+(election|filing|window)/i,
    ],
  }),
  presence({
    id: "EQT-039",
    name: "Stock-power exhibit / escrow arrangement",
    description:
      "Repurchase right is typically enforced via stock power + escrow / book-entry restriction.",
    citation: dgcl("202"),
    playbooks: [EQT_PLAYBOOK_RSPA],
    missing_title: "Escrow / stock-power clause missing",
    missing_description: "No escrow / stock-power clause was found.",
    explanation:
      "Without escrow / stock power, the company cannot operationally enforce its repurchase right when the holder departs.",
    recommendation:
      "Add 'Escrow' attaching an assignment-separate-from-certificate stock power and depositing unvested shares with the corporate secretary.",
    present_patterns: [/escrow/i, /stock\s+power/i, /assignment\s+separate\s+from\s+certificate/i],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-040",
    name: "Right of first refusal",
    description: "RSPA typically grants the company a ROFR on vested-share transfers (DGCL § 202).",
    citation: dgcl("202"),
    playbooks: [EQT_PLAYBOOK_RSPA],
    missing_title: "Right-of-first-refusal clause missing",
    missing_description: "No ROFR clause was found.",
    explanation: "Standard pattern: company ROFR on third-party transfers of vested shares.",
    recommendation:
      "Add a ROFR section on transfers of vested shares to third parties; include the standard family-trust / estate carve-outs.",
    present_patterns: [/right\s+of\s+first\s+refusal/i, /\brofr\b/i],
  }),
  presence({
    id: "EQT-041",
    name: "Lock-up / market stand-off",
    description: "Modern RSPAs include a 180-day IPO lock-up.",
    citation: eqtPractice(
      "ipo-lockup",
      "FINRA Rule 5131 + practice baseline 180-day IPO lock-up",
      "https://www.finra.org/rules-guidance/rulebooks/finra-rules/5131",
    ),
    playbooks: [EQT_PLAYBOOK_RSPA],
    missing_title: "IPO lock-up / market stand-off clause missing",
    missing_description: "No lock-up / market stand-off was found.",
    explanation:
      "Underwriters require 180-day lock-ups in connection with IPO; building it into the RSPA at issuance avoids future amendments.",
    recommendation:
      "Add a 'Market Stand-Off' section requiring the holder to honor a 180-day lock-up requested by the underwriters in connection with an IPO.",
    present_patterns: [/market\s+stand.?off/i, /lock.up/i, /180\s+days?/i],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-042",
    name: "Securities-law legend on certificates",
    description: "Restricted shares must bear Rule 144 / state-securities legends.",
    citation: eqtPractice(
      "rule-144-legend",
      "SEC Rule 144 + state securities legend practice",
      "https://www.law.cornell.edu/cfr/text/17/230.144",
    ),
    playbooks: [EQT_PLAYBOOK_RSPA],
    missing_title: "Restricted-securities legend clause missing",
    missing_description: "No Rule 144 / state-securities legend clause was found.",
    explanation:
      "Restricted securities sold under § 4(a)(2) / Reg D must bear a Rule 144 legend; state securities laws often add their own legend.",
    recommendation:
      "Add a 'Legends' section requiring the Rule 144 / state-securities legends until eligibility for unrestricted resale.",
    present_patterns: [
      /rule\s+144/i,
      /restrictive\s+legend/i,
      /these\s+(shares|securities)\s+have\s+not\s+been\s+registered/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// C.6 — § 83(b) Election Form. Treas. Reg. § 1.83-2.
// 6 rules: EQT-043..EQT-048.
// ────────────────────────────────────────────────────────────────────

const ELECTION_83B_RULES: Rule[] = [
  presence({
    id: "EQT-043",
    name: "Election cites § 83(b)",
    description: "§ 83(b) election must reference IRC § 83(b).",
    citation: irc("83(b)"),
    playbooks: [EQT_PLAYBOOK_83B],
    missing_title: "§ 83(b) citation missing",
    missing_description: "No reference to IRC § 83(b) was found.",
    explanation: "Treas. Reg. § 1.83-2 requires the election to be 'an election under § 83(b)'.",
    recommendation:
      "Add the header 'Election to Include in Gross Income in Year of Transfer Pursuant to Section 83(b) of the Internal Revenue Code'.",
    present_patterns: [/section\s+83\s*\(\s*b\s*\)/i, /83\s*\(\s*b\s*\)\s+election/i],
  }),
  presence({
    id: "EQT-044",
    name: "Taxpayer name, address, SSN",
    description: "§ 83(b) form must include taxpayer identification (Treas. Reg. § 1.83-2(e)(1)).",
    citation: treasReg("1.83-2(e)(1)", "Required content"),
    playbooks: [EQT_PLAYBOOK_83B],
    missing_title: "Taxpayer-identification fields missing",
    missing_description: "No taxpayer name / address / SSN fields were found.",
    explanation:
      "Treas. Reg. § 1.83-2(e)(1) requires the election to state the taxpayer's name, address, and taxpayer-identification number.",
    recommendation: "Include taxpayer name, address, and SSN / TIN.",
    present_patterns: [
      /(name|address).{0,40}(taxpayer|undersigned)/is,
      /social\s+security\s+number/i,
      /taxpayer\s+identification/i,
    ],
  }),
  presence({
    id: "EQT-045",
    name: "Description of property",
    description: "Election must describe the property (Treas. Reg. § 1.83-2(e)(2)).",
    citation: treasReg("1.83-2(e)(2)", "Property description"),
    playbooks: [EQT_PLAYBOOK_83B],
    missing_title: "Property description missing",
    missing_description: "No description of the property (shares + class + number) was found.",
    explanation:
      "The election must describe the property — typically '[X] shares of [Class] common stock of [Company]'.",
    recommendation: "Add the description: number of shares, class, and issuing company.",
    present_patterns: [/shares?\s+of\s+(common|preferred)\s+stock/i, /restricted\s+stock/i],
  }),
  presence({
    id: "EQT-046",
    name: "Date of transfer / restrictions",
    description:
      "Election must state the date of transfer and any restrictions (Treas. Reg. § 1.83-2(e)(3)–(4)).",
    citation: treasReg("1.83-2(e)(3)"),
    playbooks: [EQT_PLAYBOOK_83B],
    missing_title: "Date-of-transfer / restrictions clause missing",
    missing_description: "No date-of-transfer or description-of-restrictions clause was found.",
    explanation:
      "Treas. Reg. § 1.83-2(e)(3)–(4) requires the date of transfer and a description of the restrictions to which the property is subject.",
    recommendation:
      "Add 'Date of Transfer' and 'Restrictions' (e.g., subject to vesting and repurchase by the Company at original cost on termination).",
    present_patterns: [/date\s+of\s+transfer/i, /restrictions?\s+(to\s+which|on)/i],
  }),
  presence({
    id: "EQT-047",
    name: "FMV / amount paid",
    description:
      "Election must state FMV of the property at transfer and the amount paid for it (Treas. Reg. § 1.83-2(e)(5)–(6)).",
    citation: treasReg("1.83-2(e)(5)"),
    playbooks: [EQT_PLAYBOOK_83B],
    missing_title: "FMV / amount-paid clause missing",
    missing_description: "No fair-market-value or amount-paid clause was found.",
    explanation:
      "FMV and amount paid are required to compute the § 83(b) inclusion (FMV − amount paid).",
    recommendation: "Add 'Fair Market Value at Transfer' and 'Amount Paid' lines.",
    present_patterns: [/fair\s+market\s+value/i, /amount\s+paid/i],
  }),
  compound({
    id: "EQT-048",
    name: "30-day filing notice + copies to IRS / employer / return",
    description:
      "Treas. Reg. § 1.83-2(c) requires filing within 30 days and copies to the IRS / employer / taxpayer's return.",
    citation: treasReg("1.83-2(c)", "30-day filing + copies"),
    playbooks: [EQT_PLAYBOOK_83B],
    required_patterns: [
      /thirty\s*\(?30\)?\s+days/i,
      /(internal\s+revenue\s+service|irs)\s+(service\s+center|office)/i,
      /(employer|company).{0,40}(copy|file)/is,
    ],
    min_match: 2,
    missing_title: "30-day / filing-copies recitals incomplete",
    missing_description:
      "One or more of the three Treas. Reg. § 1.83-2(c) procedural recitals (30-day window, IRS filing, employer / return copies) is missing.",
    explanation:
      "Treas. Reg. § 1.83-2(c) requires the election to be filed within 30 days; a copy must be furnished to the employer; and (under § 1.83-2(c) historically) attached to the taxpayer's return — though the IRS has waived the latter for tax years 2016+, the filing-deadline and employer-copy still apply.",
    recommendation:
      "Add procedural recitals covering the 30-day filing window, the IRS service center, and the employer copy.",
    default_severity: "critical",
  }),
];

// ────────────────────────────────────────────────────────────────────
// C.7 — Investor Rights Agreement (IRA). NVCA model.
// 8 rules: EQT-049..EQT-056.
// ────────────────────────────────────────────────────────────────────

const IRA_RULES: Rule[] = [
  presence({
    id: "EQT-049",
    name: "Demand registration rights",
    description: "IRA should include demand registration rights (NVCA Model IRA § 2).",
    citation: nvca("ira-demand-registration", "Investor Rights Agreement — Demand Registration"),
    playbooks: [EQT_PLAYBOOK_IRA],
    missing_title: "Demand registration rights clause missing",
    missing_description: "No demand registration rights clause was found.",
    explanation:
      "NVCA model provides preferred holders the right to demand Form S-1 / S-3 registrations after the IPO.",
    recommendation:
      "Add 'Demand Registration' covering S-1 demands (typically 2, after a holding period) and S-3 demands (typically unlimited, subject to a dollar minimum).",
    present_patterns: [/demand\s+registration/i, /form\s+s.1\s+demand/i],
  }),
  presence({
    id: "EQT-050",
    name: "Piggyback registration rights",
    description:
      "IRA should provide piggyback rights letting investors include their shares in company-initiated registrations.",
    citation: nvca("ira-piggyback", "IRA — Piggyback Registration"),
    playbooks: [EQT_PLAYBOOK_IRA],
    missing_title: "Piggyback registration rights clause missing",
    missing_description: "No piggyback registration rights clause was found.",
    explanation:
      "NVCA model gives preferred holders piggyback rights on company-initiated registrations (with underwriter cutback).",
    recommendation:
      "Add 'Piggyback Registration' including underwriter cutback and pro rata allocation.",
    present_patterns: [/piggyback/i],
  }),
  presence({
    id: "EQT-051",
    name: "Form S-3 registration rights",
    description: "IRA should provide separate S-3 demand mechanics.",
    citation: nvca("ira-s3", "IRA — S-3 Registration"),
    playbooks: [EQT_PLAYBOOK_IRA],
    missing_title: "S-3 demand registration clause missing",
    missing_description: "No S-3 demand registration clause was found.",
    explanation: "NVCA model includes a separate S-3 demand right (cheaper, shelf registration).",
    recommendation: "Add 'Form S-3 Registration' with the customary $1M-$5M aggregate minimum.",
    present_patterns: [/form\s+s.3/i, /\bs.3\s+registration/i],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-052",
    name: "Pro rata participation rights",
    description: "Major investors get pro rata participation in subsequent issuances.",
    citation: nvca("ira-pro-rata", "IRA — Pro Rata Right"),
    playbooks: [EQT_PLAYBOOK_IRA],
    missing_title: "Pro rata rights clause missing",
    missing_description: "No pro rata rights clause was found.",
    explanation:
      "NVCA model preserves ownership percentage for major investors in subsequent rounds.",
    recommendation:
      "Add a 'Right to Maintain Proportionate Ownership' section with a major-investor threshold and the standard excluded-issuance carve-outs.",
    present_patterns: [/pro\s.?rata/i, /right\s+to\s+maintain/i, /preemptive/i],
  }),
  presence({
    id: "EQT-053",
    name: "Information rights",
    description: "Annual / quarterly financials, monthly financials at threshold, budget.",
    citation: nvca("ira-info-rights", "IRA — Information Rights"),
    playbooks: [EQT_PLAYBOOK_IRA],
    missing_title: "Information rights clause missing",
    missing_description: "No information-rights clause was found.",
    explanation: "NVCA model grants major investors quarterly + annual + budget information.",
    recommendation:
      "Add 'Information Rights' for major investors with the standard cadence and an inspection right.",
    present_patterns: [
      /information\s+rights/i,
      /(quarterly|annual)\s+(unaudited|audited)?\s*financial\s+statements?/is,
    ],
  }),
  presence({
    id: "EQT-054",
    name: "Right of first offer on new issuances",
    description:
      "Often combined with pro rata: investors get a right of first offer on new securities issuances.",
    citation: nvca("ira-rofo", "IRA — Right of First Offer"),
    playbooks: [EQT_PLAYBOOK_IRA],
    missing_title: "Right-of-first-offer clause missing",
    missing_description: "No right-of-first-offer clause was found.",
    explanation:
      "NVCA-style IRA: company must offer new securities to existing investors before third parties.",
    recommendation:
      "Add 'Right of First Offer' on new securities subject to standard exclusions (employee equity, conversions, M&A).",
    present_patterns: [/right\s+of\s+first\s+offer/i, /\brofo\b/i],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-055",
    name: "Market stand-off / lock-up on IPO",
    description: "IRA should impose an IPO lock-up on investors.",
    citation: eqtPractice(
      "finra-5131-ira",
      "FINRA Rule 5131 + practice baseline 180-day lock-up",
      "https://www.finra.org/rules-guidance/rulebooks/finra-rules/5131",
    ),
    playbooks: [EQT_PLAYBOOK_IRA],
    missing_title: "IPO market stand-off / lock-up clause missing",
    missing_description: "No IPO market-stand-off clause was found.",
    explanation: "Underwriters require 180-day IPO lock-ups from significant pre-IPO holders.",
    recommendation:
      "Add a 180-day market-stand-off section with the customary underwriter-flexibility clause.",
    present_patterns: [/market\s+stand.?off/i, /lock.up/i, /180\s+days?/i],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-056",
    name: "Termination of rights upon IPO / merger",
    description:
      "Most rights in the IRA terminate on IPO or sale of the company (except registration rights, which terminate later).",
    citation: nvca("ira-termination", "IRA — Termination"),
    playbooks: [EQT_PLAYBOOK_IRA],
    missing_title: "IRA termination clause missing",
    missing_description: "No termination clause was found.",
    explanation:
      "NVCA model terminates information / participation / observer rights on an IPO or sale; registration rights survive for 3–7 years post-IPO.",
    recommendation:
      "Add 'Termination of Covenants' terminating most rights on IPO / sale, with registration rights surviving for a fixed post-IPO term.",
    present_patterns: [
      /termin(ate|ation).{0,80}(ipo|initial\s+public\s+offering|sale\s+of\s+the\s+company)/is,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// C.8 — Voting Agreement. DGCL § 218.
// 7 rules: EQT-057..EQT-063.
// ────────────────────────────────────────────────────────────────────

const VOTING_AGREEMENT_RULES: Rule[] = [
  presence({
    id: "EQT-057",
    name: "Election of directors covenant",
    description:
      "Voting agreement should bind stockholders to vote for the agreed board composition.",
    citation: dgcl("218"),
    playbooks: [EQT_PLAYBOOK_VOTING],
    missing_title: "Election-of-directors covenant missing",
    missing_description:
      "No covenant binding stockholders to vote for designated directors was found.",
    explanation:
      "DGCL § 218(c) permits voting agreements. NVCA model uses one to enforce board designation rights.",
    recommendation:
      "Add 'Election of Directors' binding each stockholder to vote all of its shares to elect the designees per the charter.",
    present_patterns: [/vote\s+(in\s+favor|to\s+elect)/i, /(elect|appoint).{0,40}designees/i],
  }),
  presence({
    id: "EQT-058",
    name: "Drag-along covenant",
    description:
      "Voting agreement typically carries the drag-along covenant requiring stockholders to support an approved sale.",
    citation: nvca("va-drag-along", "Voting Agreement — Drag-Along"),
    playbooks: [EQT_PLAYBOOK_VOTING],
    missing_title: "Drag-along covenant missing",
    missing_description: "No drag-along covenant was found in the voting agreement.",
    explanation:
      "Drag-alongs bind all stockholders to vote for and execute documents for an approved sale of the company.",
    recommendation:
      "Add 'Drag-Along' triggered by requisite preferred / board approval, with standard appraisal-protection carve-out.",
    present_patterns: [/drag.along/i],
  }),
  presence({
    id: "EQT-059",
    name: "Irrevocable proxy",
    description:
      "Voting agreements typically grant an irrevocable proxy to back the voting covenant (DGCL § 212).",
    citation: dgcl("212"),
    playbooks: [EQT_PLAYBOOK_VOTING],
    missing_title: "Irrevocable proxy clause missing",
    missing_description: "No irrevocable proxy was found.",
    explanation:
      "DGCL § 212 permits an irrevocable proxy if coupled with an interest. Without it the voting covenant is hard to enforce in practice.",
    recommendation:
      "Add an 'Irrevocable Proxy' coupled with an interest in favor of the corporation / specified party to vote per the covenants.",
    present_patterns: [/irrevocable\s+proxy/i],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-060",
    name: "Successor / transferee covenant",
    description: "Transferees of shares must agree to be bound by the voting agreement.",
    citation: nvca("va-transferee", "Voting Agreement — Transferee Bound"),
    playbooks: [EQT_PLAYBOOK_VOTING],
    missing_title: "Transferee-bound covenant missing",
    missing_description: "No transferee-bound covenant was found.",
    explanation:
      "Standard pattern: transfers are conditioned on the transferee executing a joinder to the voting agreement.",
    recommendation:
      "Add 'Transferee Joinder' conditioning permitted transfers on the transferee's joinder to the voting agreement.",
    present_patterns: [/transferee.{0,40}(bound|joinder)/is, /joinder/i],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-061",
    name: "Specific performance / equitable remedies",
    description: "Voting agreements should provide for specific performance / injunctive relief.",
    citation: nvca("va-remedies", "Voting Agreement — Remedies"),
    playbooks: [EQT_PLAYBOOK_VOTING],
    missing_title: "Specific-performance clause missing",
    missing_description: "No specific-performance / equitable-relief clause was found.",
    explanation:
      "Damages are usually inadequate for voting-agreement breaches; specific performance is essential.",
    recommendation:
      "Add 'Equitable Remedies' acknowledging irreparable harm and authorizing injunctive / specific-performance relief without bond.",
    present_patterns: [/specific\s+performance/i, /injunctive\s+relief/i, /irreparable/i],
  }),
  presence({
    id: "EQT-062",
    name: "Termination on IPO / sale",
    description: "Voting agreement should terminate on IPO or sale of the company.",
    citation: nvca("va-termination", "Voting Agreement — Termination"),
    playbooks: [EQT_PLAYBOOK_VOTING],
    missing_title: "Voting-agreement termination clause missing",
    missing_description: "No termination clause was found.",
    explanation: "Without an IPO / sale termination, voting controls survive the liquidity event.",
    recommendation:
      "Add 'Termination' ending the agreement upon the earlier of an IPO and a sale of the company.",
    present_patterns: [/termin(ate|ation).{0,80}(ipo|sale\s+of\s+the\s+company)/is],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-063",
    name: "Stock-power-of-attorney for drag-along",
    description:
      "Drag-along enforcement is strengthened by a power-of-attorney in favor of the company / dragging party.",
    citation: nvca("va-poa", "Voting Agreement — POA"),
    playbooks: [EQT_PLAYBOOK_VOTING],
    missing_title: "POA-for-drag-along clause missing",
    missing_description: "No power-of-attorney for drag-along signatures was found.",
    explanation:
      "Practice baseline: stockholders grant a POA so signatures on drag-along sale documents can be obtained even if the holder refuses.",
    recommendation:
      "Add a 'Power of Attorney' coupled with an interest authorizing execution of sale documents on the holder's behalf when drag-along is triggered.",
    present_patterns: [/power\s+of\s+attorney/i, /coupled\s+with\s+an\s+interest/i],
    default_severity: "info",
  }),
];

// ────────────────────────────────────────────────────────────────────
// C.9 — ROFR / Co-Sale Agreement. DGCL § 202.
// 7 rules: EQT-064..EQT-070.
// ────────────────────────────────────────────────────────────────────

const ROFR_RULES: Rule[] = [
  presence({
    id: "EQT-064",
    name: "ROFR — company right",
    description: "Company should have a primary right of first refusal on third-party transfers.",
    citation: dgcl("202"),
    playbooks: [EQT_PLAYBOOK_ROFR],
    missing_title: "Company-ROFR clause missing",
    missing_description: "No company right-of-first-refusal clause was found.",
    explanation: "Standard tier: company has the first right; investors have the secondary right.",
    recommendation:
      "Add 'Company Right of First Refusal' as the primary tier on transfers by founders / common holders.",
    present_patterns: [/(company|corporation).{0,40}right\s+of\s+first\s+refusal/is],
  }),
  presence({
    id: "EQT-065",
    name: "ROFR — investor secondary right",
    description: "Investors get a secondary ROFR to the extent the company does not exercise.",
    citation: nvca("rofr-investor", "ROFR / Co-Sale — Investor Tier"),
    playbooks: [EQT_PLAYBOOK_ROFR],
    missing_title: "Investor secondary ROFR missing",
    missing_description: "No investor secondary ROFR clause was found.",
    explanation:
      "If the company does not exercise its primary ROFR, investors typically have a pro rata secondary right.",
    recommendation: "Add 'Investor Right of First Refusal' as a pro rata secondary tier.",
    present_patterns: [
      /(investor|stockholder).{0,40}right\s+of\s+first\s+refusal/is,
      /secondary\s+(right|tier)/i,
    ],
  }),
  presence({
    id: "EQT-066",
    name: "Co-sale right",
    description:
      "Investors should have a co-sale right to participate pro rata in transfers above thresholds.",
    citation: nvca("rofr-co-sale", "ROFR / Co-Sale — Co-Sale Right"),
    playbooks: [EQT_PLAYBOOK_ROFR],
    missing_title: "Co-sale right clause missing",
    missing_description: "No co-sale clause was found.",
    explanation: "Standard NVCA pattern: investors participate pro rata when founders sell.",
    recommendation:
      "Add 'Co-Sale Right' allowing investors to participate pro rata when transferring stockholder elects to sell.",
    present_patterns: [/co.sale/i, /tag.along/i],
  }),
  presence({
    id: "EQT-067",
    name: "Permitted transfers carve-outs",
    description: "Carve-outs for permitted family / estate-planning / affiliate transfers.",
    citation: nvca("rofr-permitted", "ROFR / Co-Sale — Permitted Transfers"),
    playbooks: [EQT_PLAYBOOK_ROFR],
    missing_title: "Permitted-transfers carve-out missing",
    missing_description: "No permitted-transfers carve-out was found.",
    explanation:
      "Standard carve-outs: transfers to family trusts for estate planning, to affiliates, to controlled entities — subject to joinder.",
    recommendation:
      "Add 'Permitted Transfers' enumerating estate-planning, affiliate, and intra-family transfers subject to joinder.",
    present_patterns: [/permitted\s+transfer/i, /family\s+(member|trust)/i],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-068",
    name: "Notice and election windows",
    description: "ROFR / co-sale need clear notice and election windows.",
    citation: nvca("rofr-mechanics", "ROFR / Co-Sale — Mechanics"),
    playbooks: [EQT_PLAYBOOK_ROFR],
    missing_title: "Notice / election windows missing",
    missing_description: "No notice and election-window mechanics were found.",
    explanation:
      "Mechanics typically: 15 days for company election, 10 days for investor election, with a 60-day sale window if neither exercises.",
    recommendation: "Add explicit notice / election windows for each tier.",
    present_patterns: [
      /(\d{1,3})\s*(day|business\s+day)s?\s+(after|to\s+elect)/i,
      /notice\s+of\s+(intended\s+)?transfer/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-069",
    name: "Termination upon IPO",
    description: "ROFR / co-sale should terminate on IPO.",
    citation: nvca("rofr-termination", "ROFR / Co-Sale — Termination"),
    playbooks: [EQT_PLAYBOOK_ROFR],
    missing_title: "IPO-termination clause missing",
    missing_description: "No IPO-termination clause was found.",
    explanation:
      "Without termination, transfer restrictions survive into the public-company period when they would be inoperable / unenforceable.",
    recommendation:
      "Add 'Termination' ending the agreement on the earlier of an IPO or a qualifying sale.",
    present_patterns: [/termin(ate|ation).{0,80}(ipo|initial\s+public\s+offering)/is],
    default_severity: "warning",
  }),
  presence({
    id: "EQT-070",
    name: "DGCL § 202 noting requirement acknowledged",
    description: "Transfer restrictions must be noted on share records (DGCL § 202).",
    citation: dgcl("202"),
    playbooks: [EQT_PLAYBOOK_ROFR],
    missing_title: "§ 202 noting requirement clause missing",
    missing_description:
      "No clause was found requiring the transfer restrictions to be noted conspicuously on share records.",
    explanation:
      "DGCL § 202(a) makes transfer restrictions enforceable only against parties with notice — typically requiring a legend on the certificate or notation on the book-entry record.",
    recommendation:
      "Add 'Legend on Certificates / Book-Entry Notation' requiring conspicuous notation per DGCL § 202.",
    present_patterns: [/section\s+202/i, /(legend|notation).{0,80}(transfer|restrictions)/is],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate. 70 rules total.
// ────────────────────────────────────────────────────────────────────

export const EQUITY_RULES: Rule[] = [
  ...SAFE_RULES,
  ...CONVERTIBLE_NOTE_RULES,
  ...OPTION_GRANT_RULES,
  ...RSU_RULES,
  ...RSPA_RULES,
  ...ELECTION_83B_RULES,
  ...IRA_RULES,
  ...VOTING_AGREEMENT_RULES,
  ...ROFR_RULES,
];

export {
  SAFE_RULES,
  CONVERTIBLE_NOTE_RULES,
  OPTION_GRANT_RULES,
  RSU_RULES,
  RSPA_RULES,
  ELECTION_83B_RULES,
  IRA_RULES,
  VOTING_AGREEMENT_RULES,
  ROFR_RULES,
};
