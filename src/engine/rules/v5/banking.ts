/**
 * v5 sub-domain L′ — US lending, receivables finance, and consumer
 * credit (spec-v45.md §6.L). Rule ids continue the BNK namespace at 101.
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import {
  agency,
  cfr,
  expressDenial,
  practice,
  standardForm,
  stateLaw,
  ucc,
  usc,
} from "./_helpers.js";

const C = "banking";

const REVOLVER = pack("revolving-credit-agreement", C, [
  {
    id: "BNK-101",
    name: "Commitment, availability, and borrowing base",
    cite: standardForm(
      "LSTA",
      "Model Credit Agreement Provisions — commitment and availability mechanics",
      "https://www.lsta.org/",
    ),
    pat: [
      /(revolving\s+commitment|aggregate\s+commitments?|availability)/i,
      /(borrowing\s+base|eligible\s+(accounts|inventory)|advance\s+rate|reserve)/i,
    ],
    why: "In an asset-based facility the borrowing base, not the commitment, is what the borrower can actually draw. Eligibility criteria and discretionary reserves are where availability disappears without notice.",
    fix: "State the commitment, the borrowing base formula with eligibility criteria and advance rates, the reporting cadence, and any limits on the agent's discretion to impose reserves.",
    sev: "critical",
  },
  {
    id: "BNK-102",
    name: "Interest rate, benchmark, and replacement waterfall",
    cite: usc("15", "1639e", "Adjustable Interest Rate (LIBOR) Act — benchmark replacement"),
    pat: [
      /(sofr|term\s+sofr|base\s+rate|applicable\s+margin)/i,
      /(benchmark\s+replacement|successor\s+rate|conforming\s+changes|credit\s+spread\s+adjustment)/i,
    ],
    why: "Post-LIBOR agreements need a benchmark replacement waterfall with a spread adjustment and conforming-changes authority, or a benchmark cessation leaves the parties without a rate.",
    fix: "State the benchmark, the applicable margin grid, and the full benchmark-replacement waterfall including the spread adjustment and the agent's conforming-changes authority.",
  },
  {
    id: "BNK-103",
    name: "Financial covenants and testing dates",
    cite: practice("financial-covenants", "financial covenant structure in credit agreements"),
    pat: [
      /(financial\s+covenant|leverage\s+ratio|fixed\s+charge\s+coverage|interest\s+coverage|minimum\s+(ebitda|liquidity))/i,
      /(tested|as\s+of\s+the\s+last\s+day\s+of|quarterly|compliance\s+certificate)/i,
    ],
    why: "Covenant levels and the EBITDA definition (particularly the add-backs) are the whole credit negotiation. Springing covenants tied to availability change when the test even applies.",
    fix: "State each covenant, its level and step-downs, the testing dates, any springing trigger, and the EBITDA definition with its permitted add-backs and caps.",
    sev: "critical",
  },
  {
    id: "BNK-104",
    name: "Conditions precedent to each borrowing",
    cite: practice(
      "conditions-precedent",
      "conditions to initial and subsequent extensions of credit",
    ),
    pat: [
      /conditions?\s+precedent/i,
      /(each\s+(borrowing|credit\s+extension)|no\s+default\s+(shall\s+have\s+occurred|exists)|representations?\s+(are|shall\s+be)\s+true)/i,
    ],
    why: "Conditions to each borrowing are what let a lender stop funding when the credit deteriorates. Borrowers need to know that a technical default closes the facility, not merely creates a remedy.",
    fix: "Separate the initial closing conditions from the conditions to each subsequent borrowing, and state the bring-down standard for representations.",
  },
  {
    id: "BNK-105",
    name: "Events of default and cure rights",
    cite: practice("events-of-default", "event of default architecture and equity cure rights"),
    pat: [
      /event\s+of\s+default/i,
      /(cure\s+period|grace\s+period|\d+\s*\)?\s*days\s+after\s+(notice|the\s+earlier)|equity\s+cure|cross-?default)/i,
    ],
    why: "The cross-default threshold and the cure periods determine how much runway a borrower has. An equity cure right, and its frequency limits, is often the difference between a workout and an acceleration.",
    fix: "Enumerate the events of default with notice and cure periods, state the cross-default threshold, and state any equity cure right with its usage and consecutive-quarter limits.",
  },
  {
    id: "BNK-106",
    name: "Collateral and guarantor package",
    cite: ucc("9-203", "Attachment and enforceability of security interest"),
    pat: [
      /(collateral|security\s+interest|guarant)/i,
      /(perfect|ucc-?1|pledge|subsidiar|control\s+agreement|mortgage)/i,
    ],
    why: "The collateral and guarantor package is what the lender relies on in default, and the perfection steps are conditions to closing. Excluded assets and non-guarantor subsidiaries are the negotiated leakage.",
    fix: "Identify the collateral, the excluded assets, the guarantors and the thresholds for adding new ones, and the perfection deliverables (UCC-1s, control agreements, mortgages, IP filings).",
  },
  {
    id: "BNK-107",
    name: "Agent authority, assignment, and participation",
    cite: standardForm(
      "LSTA",
      "Model Credit Agreement Provisions — agency, assignment, and participation",
      "https://www.lsta.org/",
    ),
    pat: [
      /(administrative\s+agent|the\s+agent)/i,
      /(assign|participation|required\s+lenders|consent\s+of\s+the\s+borrower|eligible\s+assignee)/i,
    ],
    why: "Who ends up holding the loan matters to a borrower in distress. Consent rights over assignments, disqualified-lender lists, and the required-lender thresholds for amendments are all negotiated.",
    fix: "State the agent's authority and exculpation, the assignment consent rights and disqualified institution list, and the voting thresholds for amendments and sacred rights.",
  },
  {
    id: "BNK-108",
    name: "Prepayment, fees, and yield protection",
    cite: practice(
      "yield-protection",
      "prepayment, breakage, and yield protection in credit agreements",
    ),
    pat: [
      /(prepay|repay\s+(the\s+)?loans)/i,
      /(commitment\s+fee|unused\s+fee|breakage|increased\s+costs|tax\s+gross-?up|prepayment\s+premium)/i,
    ],
    why: "Prepayment premiums, breakage costs, and increased-costs clauses are where a facility's real cost lives. Tax gross-up and FATCA provisions decide who bears withholding on an offshore lender.",
    fix: "State the voluntary and mandatory prepayment terms and any premium, the fee schedule, and the yield protection, increased costs, and tax gross-up provisions.",
  },
]);

const SBA = pack("sba-loan-agreement", C, [
  {
    id: "BNK-109",
    name: "SBA authorization incorporated",
    cite: agency(
      "US Small Business Administration",
      "SOP 50 10 — Lender and Development Company Loan Programs",
      "https://www.sba.gov/document/sop-50-10-lender-development-company-loan-programs",
    ),
    pat: [
      /(sba\s+authorization|loan\s+authorization|small\s+business\s+administration)/i,
      /(incorporated|attached|conditions\s+of\s+the\s+authorization|sba\s+form)/i,
    ],
    why: "The SBA Authorization sets the conditions on which the guaranty rests. A lender that closes outside the Authorization risks repair or denial of the guaranty, and the borrower inherits the fallout.",
    fix: "Incorporate the SBA Authorization by reference, attach it, and state that its conditions control over inconsistent loan-document terms.",
    sev: "critical",
  },
  {
    id: "BNK-110",
    name: "Use-of-proceeds restrictions",
    cite: agency(
      "US Small Business Administration",
      "SOP 50 10 — eligible and ineligible uses of proceeds",
      "https://www.sba.gov/document/sop-50-10-lender-development-company-loan-programs",
    ),
    pat: [
      /use\s+of\s+proceeds/i,
      /(shall\s+(only\s+)?be\s+used|ineligible|working[-\s]+capital|may\s+not\s+be\s+used\s+(to|for))/i,
    ],
    why: "SBA proceeds may not be used to repay owner debt, fund passive investment, or refinance ineligible obligations. Misuse is a guaranty-repair event and can be a false statement to the government.",
    fix: "State the permitted uses line by line consistent with the Authorization, and prohibit the ineligible uses expressly.",
    sev: "critical",
  },
  {
    id: "BNK-111",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Personal guaranty of twenty-percent owners",
    cite: agency(
      "US Small Business Administration",
      "SOP 50 10 — guaranty requirements for owners of 20% or more",
      "https://www.sba.gov/document/sop-50-10-lender-development-company-loan-programs",
    ),
    pat: [
      /guarant/i,
      /(20%|twenty[-\s]+percent|unconditional\s+guarantee|sba\s+form\s+148|owners?\s+of)/i,
    ],
    why: "SBA requires an unconditional personal guaranty from every owner of 20% or more, on SBA Form 148. A missing guaranty is one of the most common guaranty-repair findings.",
    fix: "Identify every 20%-or-more owner and obtain the SBA-form unconditional guaranty from each, with spousal guaranties where ownership is held jointly.",
    sev: "critical",
  },
  {
    id: "BNK-112",
    name: "Collateral and hazard insurance",
    cite: agency(
      "US Small Business Administration",
      "SOP 50 10 — collateral and insurance requirements",
      "https://www.sba.gov/document/sop-50-10-lender-development-company-loan-programs",
    ),
    pat: [
      /(collateral|security\s+interest|lien)/i,
      /(hazard\s+insurance|flood\s+insurance|loss\s+payee|insurable\s+value)/i,
    ],
    why: "SBA requires collateral to the extent available and hazard insurance on it, with flood insurance where the property is in a special flood hazard area. Absent coverage is a repair event.",
    fix: "Describe the collateral and lien positions, and require hazard insurance naming the lender as loss payee, plus flood insurance where applicable.",
  },
  {
    id: "BNK-113",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Life-insurance assignment where required",
    cite: agency(
      "US Small Business Administration",
      "SOP 50 10 — life insurance requirements for sole-owner and key-person dependent borrowers",
      "https://www.sba.gov/document/sop-50-10-lender-development-company-loan-programs",
    ),
    pat: [
      /life[-\s]+insurance/i,
      /(assign|collateral\s+assignment|key\s+(person|man)|sole\s+(owner|proprietor))/i,
    ],
    why: "SBA requires collateral assignment of life insurance where the business depends on one owner. Closing without it is a documented repair risk.",
    fix: "Require a collateral assignment of life insurance in the required amount where the borrower is owner-dependent, with the carrier's acknowledgment.",
    when: [
      /(life[-\s]+insurance|sole\s+(owner|proprietor|shareholder|member)|key\s+(person|man))/i,
    ],
  },
  {
    id: "BNK-114",
    name: "Prepayment penalties and program limits",
    cite: agency(
      "US Small Business Administration",
      "SOP 50 10 — prepayment and fee limitations",
      "https://www.sba.gov/document/sop-50-10-lender-development-company-loan-programs",
    ),
    pat: [
      /prepay/i,
      /(penalty|subsidy\s+recapture|no\s+prepayment\s+(penalty|premium)|15\s*\)?\s*years|fee)/i,
    ],
    why: "SBA caps prepayment charges (a declining 5/3/1 schedule on loans of 15 years or more) and restricts what fees a lender may charge. Charging outside the program is both a borrower claim and a lender finding.",
    fix: "State the prepayment terms within the SBA schedule and confirm that all lender fees are within program limits.",
  },
]);

const FORBEARANCE = pack("forbearance-agreement", C, [
  {
    id: "BNK-115",
    name: "Existing defaults acknowledged and specified",
    cite: practice(
      "forbearance-defaults",
      "specification of existing defaults in forbearance agreements",
    ),
    pat: [
      /(existing\s+defaults?|specified\s+defaults?)/i,
      /(acknowledg|schedule|listed|section\s+\d+\.\d+\s+of\s+the\s+(credit|loan)\s+agreement)/i,
    ],
    why: "A forbearance that does not identify the defaults it covers can be read to reach later ones, and the borrower's acknowledgment is the lender's protection against a later dispute about whether default occurred at all.",
    fix: "List each existing default by provision and have the borrower acknowledge that each has occurred and is continuing.",
    sev: "critical",
  },
  {
    id: "BNK-116",
    name: "Forbearance period and termination events",
    cite: practice("forbearance-period", "forbearance periods and termination events"),
    pat: [
      /forbearance\s+(period|termination)/i,
      /(expires?|terminat|shall\s+(immediately\s+)?(end|cease)|upon\s+the\s+occurrence)/i,
    ],
    why: "Forbearance is a standstill, not a waiver. When it ends — by date or by a new default — the lender's full remedy set springs back, so the trigger list is the borrower's operating constraint.",
    fix: "State the forbearance end date and enumerate the events that terminate it early, with any notice or grace applicable to each.",
    sev: "critical",
  },
  {
    id: "BNK-117",
    name: "No-waiver and reservation of rights",
    cite: practice("forbearance-no-waiver", "no-waiver clauses in forbearance agreements"),
    pat: [
      /(does\s+not\s+(waive|constitute\s+a\s+waiver)|no\s+waiver)/i,
      /(reserves?\s+all\s+(rights|remedies)|shall\s+not\s+be\s+deemed|course\s+of\s+dealing)/i,
    ],
    why: "Forbearance without an express no-waiver clause risks a course-of-dealing or waiver argument that the lender accepted the defaults. This is the clause that keeps the agreement a standstill.",
    fix: "State that the lender waives nothing, reserves all rights and remedies, and that the forbearance creates no course of dealing or obligation to forbear further.",
    sev: "critical",
  },
  {
    id: "BNK-118",
    name: "Reaffirmation by borrower and guarantors",
    cite: practice("forbearance-reaffirmation", "reaffirmation of loan documents and guaranties"),
    pat: [
      /(reaffirm|ratif)/i,
      /(loan\s+documents|guarant|liens?\s+(remain|continue)|remain\s+in\s+full\s+force)/i,
    ],
    why: "A material modification can discharge a guarantor. Obtaining the guarantors' consent and reaffirmation with each forbearance is what preserves the credit support.",
    fix: "Have the borrower reaffirm the loan documents and liens, and have every guarantor consent to the forbearance and reaffirm its guaranty.",
    sev: "critical",
  },
  {
    id: "BNK-119",
    name: "Borrower release of lender claims",
    cite: practice("forbearance-release", "borrower releases in workout agreements"),
    pat: [
      /releas/i,
      /(lender|its\s+officers,?\s+directors|claims,?\s+known\s+and\s+unknown|1542)/i,
    ],
    why: "The release of lender liability claims is the lender's principal consideration for forbearing, and its enforceability depends on the specificity of the waiver — including a § 1542-type waiver of unknown claims in California.",
    fix: "Include a broad release of the lender and its affiliates from claims through the effective date, with an unknown-claims waiver where the governing state requires one.",
  },
  {
    id: "BNK-120",
    name: "Conditions, milestones, and new consideration",
    cite: practice("forbearance-milestones", "milestones and conditions in forbearance agreements"),
    pat: [
      /(milestone|condition)/i,
      /(by\s+\w+\s+\d{1,2}|deliver|retain\s+(a\s+)?(financial\s+advisor|consultant)|budget|forbearance\s+fee)/i,
    ],
    why: "Forbearance buys the borrower time to execute a plan. Milestones — a retained advisor, a marketing process, a budget with variance limits — are how the lender monitors it, and the fee is the consideration.",
    fix: "State the conditions precedent, the milestones with dates, the reporting and budget variance covenants, and the forbearance fee.",
  },
]);

const FACTORING = pack("factoring-agreement", C, [
  {
    id: "BNK-121",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "True-sale intent and protective security interest",
    cite: ucc("9-109", "Scope — sales of accounts and chattel paper"),
    pat: [
      /(true[-\s]+sale|sale\s+and\s+not\s+(as\s+)?a\s+loan|absolute\s+(sale|assignment))/i,
      /(protective|out\s+of\s+an\s+abundance\s+of\s+caution|grants?\s+a\s+security\s+interest)/i,
    ],
    why: "Article 9 covers outright sales of accounts, so the factor must file to perfect either way. If a court recharacterizes the sale as a loan, the protective security interest is what keeps the factor secured rather than unsecured.",
    fix: "State the parties' intent that the transaction is a true sale, and grant a protective security interest in the accounts in case it is recharacterized.",
    sev: "critical",
  },
  {
    id: "BNK-122",
    name: "Recourse and dispute chargebacks",
    cite: practice("factoring-recourse", "recourse and chargeback mechanics in factoring"),
    pat: [/(recourse|non-?recourse)/i, /(chargeback|repurchase|dispute|credit\s+risk|dilution)/i],
    why: "Non-recourse factoring covers credit risk only — a customer dispute over the goods still comes back to the client. Clients routinely misunderstand this as insurance against non-payment for any reason.",
    fix: "State whether the facility is recourse or non-recourse, define the credit-risk event covered, and enumerate the chargeback triggers (dispute, offset, return, breach of warranty).",
    sev: "critical",
  },
  {
    id: "BNK-123",
    name: "Advance rate, discount fee, and reserve release",
    cite: practice("factoring-economics", "advance rates, fees, and reserve accounts in factoring"),
    pat: [
      /(advance\s+rate|advance\s+percentage)/i,
      /(reserve|discount\s+fee|factoring\s+fee|release\s+of\s+the\s+reserve)/i,
    ],
    why: "The reserve is the client's money held back; when it is released, and against what, determines the facility's real cost and the client's working-capital position.",
    fix: "State the advance rate, the discount or factoring fee and how it accrues, the reserve percentage, and the conditions and timing for reserve release.",
  },
  {
    id: "BNK-124",
    name: "Notification and verification of account debtors",
    cite: ucc("9-406", "Discharge of account debtor; notification of assignment"),
    // The clause names the debtor with a determiner — "authorizes Factor to
    // notify ANY account debtor of the assignment", "shall notify EACH account
    // debtor" — and directs payment without the preposition the second pillar
    // wanted ("directing the account debtor to PAY FACTOR"). A facility whose
    // Section 2 is headed "Notification" and says so in its first sentence
    // matched neither.
    ver: "1.1.0",
    pat: [
      /(notif(y|ies|ication)\s+(of\s+|to\s+)?(any\s+|each\s+|every\s+|all\s+|the\s+)?account\s+debtors?|notice\s+of\s+(the\s+)?assignment|notification\s+facility)/i,
      /(verif|pay\s+(directly\s+)?(to\s+)?(the\s+)?factor\b|lockbox|non-?notification)/i,
    ],
    why: "Under § 9-406 an account debtor is discharged by paying the assignor until it receives notification of the assignment. Non-notification factoring leaves the factor exposed to payments made to the client.",
    fix: "State whether the facility is notification or non-notification, the form of notice to account debtors, verification rights, and the lockbox or payment-direction arrangements.",
  },
  {
    id: "BNK-125",
    name: "UCC-1 filing and lien priority",
    cite: ucc("9-322", "Priorities among conflicting security interests in the same collateral"),
    pat: [
      /(ucc-?1|financing\s+statement)/i,
      /(perfect|priority|first\s+position|subordination|intercreditor|lien\s+search)/i,
    ],
    why: "A factor that does not file first loses to a prior blanket lender with an accounts lien. Subordinations or intercreditor agreements with any existing lender are usually conditions to funding.",
    fix: "Require UCC-1 filing, lien searches, and payoff, release, or subordination from any existing secured party with a competing accounts lien.",
    sev: "critical",
  },
  {
    id: "BNK-126",
    name: "Effective cost-of-funds disclosure",
    cite: stateLaw(
      "commercial-financing-disclosure",
      "state commercial financing disclosure laws requiring APR or estimated APR for small-business finance (California, New York, Utah, Virginia, and others)",
      "https://www.law.cornell.edu/wex/consumer_protection",
    ),
    pat: [
      /(annual\s+percentage\s+rate|apr|effective\s+(annual\s+)?(rate|cost))/i,
      /(total\s+cost|disclosure|estimated)/i,
    ],
    why: "California, New York, Utah, and Virginia now require APR or cost disclosures on commercial financing including factoring above certain thresholds. A facility priced only as a discount rate obscures a cost that may be several times higher annualized.",
    fix: "Provide the state-required commercial financing disclosure with the annualized rate, total dollar cost, and prepayment terms where the transaction is covered.",
  },
]);

const DACA = pack("deposit-account-control-agreement", C, [
  {
    id: "BNK-127",
    name: "Control language satisfying § 9-104(a)(2)",
    cite: ucc("9-104", "Control of deposit account"),
    pat: [
      /control/i,
      /(without\s+further\s+consent\s+(by|of)\s+the\s+(debtor|customer|company)|comply\s+with\s+instructions\s+(originated\s+)?by\s+the\s+secured\s+party|9-104)/i,
    ],
    all: true,
    why: "§ 9-104(a)(2) gives control only where the bank agrees to comply with the secured party's instructions without further consent from the customer. Language requiring the customer's later consent gives no control and no perfection.",
    fix: 'Use the statutory formula: the bank will comply with instructions originated by the secured party directing disposition of the funds "without further consent by the Company."',
    sev: "critical",
  },
  {
    id: "BNK-128",
    name: "Springing versus hard control",
    cite: ucc("9-104", "Control of deposit account — customer access"),
    pat: [
      /(springing|shifting\s+control|blocked\s+account)/i,
      /(notice\s+of\s+exclusive\s+control|until\s+(the\s+bank\s+)?receives|customer\s+may\s+(continue\s+to\s+)?(withdraw|access))/i,
    ],
    why: "Springing control preserves the borrower's use of its own cash until a trigger; hard control blocks it from day one. § 9-104(b) confirms the customer may retain access without defeating control, but the arrangement must be documented.",
    fix: "State whether control is springing or hard, and describe the customer's access rights before a notice of exclusive control is delivered.",
  },
  {
    id: "BNK-129",
    name: "Notice of exclusive control mechanics and timing",
    cite: practice("noce", "notice of exclusive control procedures in control agreements"),
    pat: [
      /notice\s+of\s+exclusive\s+control/i,
      /(business\s+days|form\s+attached|exhibit|shall\s+(comply|honor)\s+within)/i,
    ],
    why: "The value of a springing DACA depends entirely on how fast the bank acts on the notice. Two business days is standard; longer windows let a distressed borrower sweep the account first.",
    fix: "Attach the notice form, state the delivery method, and set the bank's compliance deadline in business days.",
    sev: "critical",
  },
  {
    id: "BNK-130",
    name: "Bank setoff and prior-rights subordination",
    cite: ucc("9-340", "Effectiveness of right of recoupment or set-off against deposit account"),
    pat: [
      /(set-?off|recoupment|banker['’]?s\s+lien)/i,
      /(subordinat|waives?|except\s+for\s+(returned\s+items|fees|chargebacks))/i,
    ],
    why: "Under § 9-340 the bank's setoff rights survive a security interest unless the bank agrees otherwise. A DACA in which the bank does not subordinate leaves the secured party behind the bank for the account's entire balance.",
    fix: "Have the bank subordinate its setoff and lien rights except for returned items, chargebacks, and its customary fees.",
    sev: "critical",
  },
  {
    id: "BNK-131",
    name: "Termination and successor-bank provisions",
    cite: practice(
      "daca-termination",
      "termination and successor arrangements in control agreements",
    ),
    pat: [
      /terminat/i,
      /(\d+\s*\)?\s*days['’]?\s+(prior\s+)?(written\s+)?notice|successor|transfer\s+the\s+account|closes?\s+the\s+account)/i,
    ],
    why: "If the bank can resign or close the account on short notice, the secured party can lose perfection between the notice and the replacement account's DACA.",
    fix: "Require advance notice of termination or account closure to the secured party, and require the customer to establish a replacement account under a new control agreement before the old one closes.",
  },
]);

const CREDIT_CARD = pack("credit-card-agreement", C, [
  {
    id: "BNK-132",
    name: "APR types, ranges, and variable-rate index",
    cite: cfr("12", "1026.6(b)", "Regulation Z — account-opening disclosures for open-end plans"),
    pat: [
      /(annual\s+percentage\s+rate|apr)/i,
      /(purchase|balance\s+transfer|cash\s+advance|variable|index|prime\s+rate)/i,
    ],
    why: "§ 1026.6(b)(2) requires the APR for each feature and, for a variable rate, the index and margin and how the rate is determined. These are the disclosures the account-opening table is built from.",
    fix: "State the APR for purchases, balance transfers, and cash advances, and for variable rates the index, the margin, and the adjustment frequency.",
    sev: "critical",
  },
  {
    id: "BNK-133",
    name: "Fee schedule and penalty pricing",
    cite: cfr("12", "1026.52", "Regulation Z — limitations on fees"),
    pat: [
      /(annual\s+fee|late\s+fee|returned\s+payment|foreign\s+transaction|cash\s+advance\s+fee)/i,
      /(penalty\s+apr|\$\d|percent\s+of\s+the)/i,
    ],
    why: "The CARD Act limits first-year fees to 25% of the credit limit and requires penalty fees to be reasonable and proportional. Penalty APR triggers must be disclosed and are subject to the six-month review rule.",
    fix: "State every fee and its amount, the penalty APR and the conduct that triggers it, and the review that can restore the prior rate.",
  },
  {
    id: "BNK-134",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Grace period and balance-computation method",
    cite: cfr("12", "1026.6(b)(4)", "Regulation Z — grace period and balance computation method"),
    pat: [
      /grace\s+period/i,
      /(balance[-\s]+computation|average\s+daily\s+balance|how\s+we\s+calculate|interest\s+charge)/i,
    ],
    why: "Whether a grace period applies, and what happens to it when a balance is carried, is the single most misunderstood term in a card agreement — and § 1026.6(b)(4) requires the method be explained.",
    fix: "State the grace period and the conditions for keeping it, and name and describe the balance-computation method.",
  },
  {
    id: "BNK-135",
    name: "Forty-five-day advance notice of adverse changes",
    cite: cfr(
      "12",
      "1026.9(c)",
      "Regulation Z — subsequent disclosure requirements, change in terms",
    ),
    pat: [
      /(change\s+in\s+terms|we\s+may\s+change)/i,
      /(45\s*\)?\s*days|forty-?five\s+days|advance\s+(written\s+)?notice|right\s+to\s+reject)/i,
    ],
    why: "The CARD Act requires 45 days' advance notice of significant changes and, for rate increases, a right to reject that closes the account and repays at the old rate. It also generally bars rate increases in the first year.",
    fix: "State the 45-day notice for significant changes, the consumer's right to reject a rate increase, and the first-year rate-increase limitation.",
    sev: "critical",
  },
  {
    id: "BNK-136",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Billing-rights and error-resolution summary",
    cite: usc("15", "1666", "Fair Credit Billing Act — correction of billing errors"),
    pat: [
      /(billing[-\s]+(rights|error)|your\s+rights\s+if\s+you\s+(are\s+dissatisfied|think))/i,
      /(60\s*\)?\s*days|written\s+notice|investigat|resolve)/i,
    ],
    why: "The FCBA long-form billing rights summary must be provided at account opening and annually. It carries the 60-day dispute window and the claims-and-defenses right for disputed purchases.",
    fix: "Include the billing rights summary with the 60-day notice period, the investigation timeline, and the claims-and-defenses provision for purchases.",
  },
  {
    id: "BNK-137",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Payment allocation to highest-APR balances",
    cite: cfr("12", "1026.53", "Regulation Z — allocation of payments"),
    pat: [
      /(payment\s+allocation|how\s+we\s+apply\s+your\s+payments|amounts?\s+in\s+excess\s+of\s+the\s+minimum)/i,
      /(highest[-\s]+(annual\s+percentage\s+rate|apr)|balance\s+with\s+the\s+highest)/i,
    ],
    why: "§ 1026.53 requires amounts above the minimum payment to be allocated first to the highest-APR balance. Agreements describing the pre-CARD Act allocation are both non-compliant and misleading.",
    fix: "State that payments above the minimum are applied first to the balance with the highest APR, and describe the minimum-payment allocation.",
  },
  {
    id: "BNK-138",
    name: "Arbitration clause and opt-out mechanics",
    cite: usc("9", "2", "Federal Arbitration Act — validity of arbitration agreements"),
    pat: [
      /arbitrat/i,
      /(opt\s?-?out|reject\s+(this\s+)?(arbitration|provision)|within\s+\d+\s*\)?\s*days|class\s+action\s+waiver)/i,
    ],
    why: "Card arbitration clauses are enforceable, but they must be conspicuous, and the opt-out window and method are what most courts point to when upholding them. Military Lending Act accounts cannot carry them at all.",
    fix: "Set the arbitration and class-waiver provision in a conspicuous, separately headed section with a stated opt-out window and method, and exclude covered borrowers under the Military Lending Act.",
  },
]);

const EFA = pack("equipment-finance-agreement", C, [
  {
    id: "BNK-139",
    name: "Loan versus true-lease characterization",
    cite: ucc("1-203", "Lease distinguished from security interest"),
    pat: [
      /(security\s+interest|loan|financing)/i,
      /(not\s+a\s+(true\s+)?lease|title\s+(to\s+the\s+equipment\s+)?(passes|vests)\s+(to|in)\s+(the\s+)?(borrower|obligor)|nominal\s+(purchase\s+)?(price|option)|1-203)/i,
    ],
    why: "§ 1-203 makes the characterization a matter of economics, not labels. If the transaction is really a secured loan, the finance party must perfect under Article 9 or it is unsecured in a bankruptcy.",
    fix: "State the intended characterization, and align the terms with it — title vesting in the obligor, a grant of a security interest, and no meaningful reversionary interest.",
    sev: "critical",
  },
  {
    id: "BNK-140",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Security interest grant and UCC-1 filing",
    cite: ucc("9-203", "Attachment and enforceability of security interest"),
    pat: [
      /grants?\s+(to\s+\w+\s+)?a\s+security\s+interest/i,
      /(ucc-?1|financing\s+statement|authorizes?\s+(the\s+)?filing|perfect)/i,
    ],
    why: "§ 9-203 requires a security agreement authenticated by the debtor describing the collateral, and § 9-509 requires authorization for the financing statement. Both are usually in this one document.",
    fix: "Include an express grant of a security interest with a collateral description, and the debtor's authorization to file financing statements.",
    denied: expressDenial(String.raw`UCC[- ]?1(?:\s+financing\s+statement)?|financing\s+statement`),
    sev: "critical",
  },
  {
    id: "BNK-141",
    name: "Payment schedule, rate, and prepayment terms",
    cite: practice("efa-payment", "payment, rate, and prepayment terms in equipment finance"),
    pat: [
      /(payment\s+schedule|monthly\s+(payment|installment))/i,
      /(interest\s+rate|prepay|early\s+(payoff|termination)|balloon)/i,
    ],
    why: "EFAs frequently quote a payment amount without a rate, and a prepayment payoff computed on undiscounted remaining payments can make early payoff cost more than holding the debt.",
    fix: "State the financed amount, the rate, the payment schedule, and the prepayment payoff formula with any discount to present value.",
  },
  {
    id: "BNK-142",
    name: "Insurance and casualty risk",
    cite: practice("efa-insurance", "insurance and casualty allocation in equipment finance"),
    pat: [
      /insur(e|ance)/i,
      /(loss\s+payee|casualty|stipulated\s+loss\s+value|force-?placed|lender['’]?s\s+loss\s+payable)/i,
    ],
    why: "The finance party's collateral can be destroyed in a day. Loss-payee status, a stipulated loss value, and the force-placement remedy are the standard protections.",
    fix: "Require property and liability insurance naming the finance party as loss payee and additional insured, state the casualty payment obligation, and reserve force-placement rights.",
  },
  {
    id: "BNK-143",
    name: "Default, acceleration, and disposition of collateral",
    cite: ucc("9-610", "Disposition of collateral after default"),
    pat: [
      /(default|accelerat)/i,
      /(repossess|dispose\s+of\s+the\s+(equipment|collateral)|commercially\s+reasonable|deficiency)/i,
    ],
    why: "Article 9 Part 6 governs disposition and cannot be waived: notice, commercial reasonableness, and the deficiency calculation apply whatever the contract says.",
    fix: "State the events of default, the acceleration remedy, and the disposition rights, expressly subject to the Article 9 notice and commercial-reasonableness requirements.",
  },
]);

export const V5_BANKING_RULES: readonly Rule[] = [
  ...REVOLVER,
  ...SBA,
  ...FORBEARANCE,
  ...FACTORING,
  ...DACA,
  ...CREDIT_CARD,
  ...EFA,
];
