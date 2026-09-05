/**
 * v5 sub-domain C′ — US equity compensation and secondary transfers
 * (spec-v45.md §6.C). Rule ids continue the EQT namespace at 101.
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { irs, cfr, usc, practice } from "./_helpers.js";

const C = "equity";

const PLAN = pack("equity-incentive-plan", C, [
  {
    id: "EQT-101",
    name: "Share reserve and evergreen mechanics",
    cite: practice(
      "share-reserve",
      "share reserve and evergreen provisions in omnibus equity plans",
    ),
    pat: [
      /(share\s+reserve|shares?\s+(available|reserved)\s+for\s+issuance|maximum\s+(aggregate\s+)?number\s+of\s+shares)/i,
      /(evergreen|automatic(ally)?\s+increase|annual\s+increase)/i,
    ],
    why: "The reserve is the plan's central term and the number every cap table depends on. An evergreen provision is a standing dilution commitment that must be disclosed and, for public companies, is a governance flashpoint.",
    fix: "State the initial share reserve, any evergreen formula with its cap and expiry, and how forfeited, withheld, and net-settled shares return to the reserve.",
    sev: "critical",
  },
  {
    id: "EQT-102",
    name: "ISO $100,000 limit and ten-year term",
    cite: irs("26 U.S.C. § 422(d)", "incentive stock options — $100,000 per year limitation"),
    pat: [
      /(incentive\s+stock\s+option|\bisos?\b)/i,
      /(\$100,000|100,000|ten\s+years|10\s*\)?\s*years|five\s+years|10%\s+(share|stock)holder)/i,
    ],
    why: "§ 422 conditions ISO treatment on a ten-year maximum term, the $100,000 first-exercisable limit, and a five-year term and 110% exercise price for 10% shareholders. A plan that omits them cannot grant valid ISOs.",
    fix: "State the ISO limits: ten-year maximum term, the $100,000 per-calendar-year first-exercisable limit, and the 10%-shareholder five-year / 110% rules.",
    when: [/(incentive\s+stock\s+option|\bisos?\b|section\s+422)/i],
    sev: "critical",
  },
  {
    id: "EQT-103",
    name: "Administrator authority and repricing limits",
    cite: practice(
      "plan-administrator",
      "administrator authority and repricing restrictions in equity plans",
    ),
    pat: [
      /(administrator|the\s+committee\s+((?:shall|will|must)|may)|compensation\s+committee)/i,
      /(reprice|repricing|reduce\s+the\s+exercise\s+price|exchange\s+(of\s+)?(underwater\s+)?options)/i,
    ],
    why: "Exchange listing standards and proxy advisors require shareholder approval for repricing. A plan silent on repricing invites a governance objection at the approval vote.",
    fix: "State the administrator's authority and expressly prohibit repricing, cash buyouts of underwater awards, and option exchanges without shareholder approval.",
  },
  {
    id: "EQT-104",
    name: "Capitalization adjustment provisions",
    cite: practice("plan-adjustment", "anti-dilution adjustment on capitalization changes"),
    pat: [
      /(stock\s+split|recapitali[sz]ation|stock\s+dividend|reorgani[sz]ation)/i,
      /(adjust(ment)?|proportionate(ly)?|equitab(le|ly))/i,
    ],
    why: "Without an adjustment clause a stock split leaves outstanding options economically broken, and for ISOs an adjustment outside § 424(a) is a disqualifying modification.",
    fix: "Provide for equitable adjustment of the reserve, outstanding awards, and exercise prices on splits, dividends, recapitalizations, and similar events, consistent with §§ 424(a) and 409A.",
  },
  {
    id: "EQT-105",
    name: "Change-in-control treatment",
    cite: practice("plan-cic", "change-in-control treatment in equity plans"),
    pat: [
      /change\s+(in|of)\s+control/i,
      /(accelerat|assum(e|ed|ption)|substitut|cash(ed)?\s+out|terminate\s+(the\s+)?awards)/i,
    ],
    why: "The single most negotiated plan term. Silence leaves the administrator with discretion that acquirers, employees, and boards all read differently at the worst possible moment.",
    fix: "State the treatment on a change in control: assumption or substitution, single- or double-trigger acceleration, and cash-out of awards not assumed, with the § 280G interaction addressed.",
  },
  {
    id: "EQT-106",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    //
    // 1.2.0 — written as a synonym OR, but the amendment power and the
    // stockholder-approval trigger are distinct pillars, and `amend` alone is
    // in every amendment clause. The check could not fire on any realistic
    // document.
    ver: "1.2.0",
    name: "Amendment and stockholder-approval triggers",
    cite: irs("26 U.S.C. § 422(b)(1)", "incentive stock options — plan approval by shareholders"),
    pat: [
      /amend(ment)?/i,
      /(stockholder[-\s]+approval|shareholder\s+approval|to\s+the\s+extent\s+required\s+by\s+(applicable\s+law|listing))/i,
    ],
    all: true,
    why: "§ 422 requires shareholder approval within twelve months of adoption, and listing standards require it for material amendments. A plan that does not name the triggers ends up amended invalidly.",
    fix: "State the amendment authority and which amendments require stockholder approval (reserve increases, ISO changes, repricing, and any change listing standards require).",
  },
  {
    id: "EQT-107",
    name: "Clawback policy hook",
    cite: cfr(
      "17",
      "240.10D-1",
      "SEC — listing standards for recovery of erroneously awarded compensation",
    ),
    pat: [
      /clawback|recoupment|recovery\s+policy/i,
      /(subject\s+to\s+(any\s+)?(company\s+)?(clawback|recoupment)|erroneously\s+awarded)/i,
    ],
    why: "Exchange listing standards under Rule 10D-1 require issuers to recover erroneously awarded incentive compensation. The plan must make awards subject to the policy for it to reach them.",
    fix: 'Add: "All Awards are subject to the Company\'s clawback or recoupment policy as in effect from time to time and to any recovery required by applicable law or listing standards."',
  },
]);

const ESPP = pack("employee-stock-purchase-plan", C, [
  {
    id: "EQT-108",
    name: "Section 423 qualification election",
    cite: irs("26 U.S.C. § 423", "employee stock purchase plans"),
    pat: [
      /section\s+423|§\s*423/i,
      /(qualif(y|ied)|intended\s+to\s+(qualify|be)|non-?423\s+component)/i,
    ],
    why: "Only a § 423 plan gives participants the deferral and capital-gain treatment the ESPP is sold on. A plan that does not state the intent, or that mixes a non-423 component without segregating it, risks the qualification for everyone.",
    fix: "State that the plan is intended to qualify under § 423 and, if there is a non-423 component for non-US employees, segregate it expressly.",
    sev: "critical",
  },
  {
    id: "EQT-109",
    name: "Equal-rights and eligibility conditions",
    cite: irs(
      "26 U.S.C. § 423(b)(4)-(5)",
      "employee stock purchase plans — eligibility and equal rights",
    ),
    pat: [
      /(eligib|all\s+employees)/i,
      /(same\s+rights\s+and\s+privileges|equal(ly)?|two\s+years|20\s*\)?\s*hours|five\s+months|highly\s+compensated)/i,
    ],
    why: "§ 423(b)(4)-(5) require that all eligible employees participate on the same terms, with only the statutory exclusions permitted. A discretionary exclusion disqualifies the plan.",
    fix: "State the eligibility rule using only permitted exclusions (service under two years, under 20 hours per week, under five months per year, and highly compensated employees), and confirm equal rights and privileges.",
  },
  {
    id: "EQT-110",
    name: "$25,000 per-calendar-year limit",
    cite: irs("26 U.S.C. § 423(b)(8)", "employee stock purchase plans — $25,000 limitation"),
    pat: [/\$25,000|25,000/i, /(calendar\s+year|per\s+year|accrue|limit)/i],
    why: "The $25,000 limit is measured on grant-date fair market value and accrues per calendar year. Administering without the limit in the plan document produces disqualified purchases that must be unwound.",
    fix: "State that no participant may accrue the right to purchase more than $25,000 of stock (grant-date fair market value) for any calendar year in which the right is outstanding.",
    sev: "critical",
  },
  {
    id: "EQT-111",
    name: "Purchase price floor and lookback",
    cite: irs("26 U.S.C. § 423(b)(6)", "employee stock purchase plans — option price"),
    pat: [
      /(purchase\s+price|option\s+price)/i,
      /(85%|eighty-?five[-\s]+percent|lower\s+of|lookback|offering\s+date)/i,
    ],
    why: "§ 423(b)(6) permits a price no lower than 85% of the fair market value at grant or exercise. The lookback to the lower of the two dates is what makes the discount valuable and must be stated to apply.",
    fix: "State the purchase price as a percentage (not below 85%) of the lower of the fair market value on the offering date and the purchase date.",
  },
  {
    id: "EQT-112",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Five-percent shareholder exclusion",
    cite: irs("26 U.S.C. § 423(b)(3)", "employee stock purchase plans — 5% shareholder exclusion"),
    pat: [
      /(5%|five[-\s]+percent)/i,
      /(shareholder|stockholder|own(s|ing)?\s+(stock\s+)?possessing|attribution)/i,
    ],
    why: "An employee owning 5% or more of the voting power may not be granted an ESPP right at all, applying the § 424(d) attribution rules. Granting to one is a qualification defect.",
    fix: "Exclude any employee who, immediately after the grant, would own stock possessing 5% or more of the total combined voting power, applying § 424(d) attribution.",
  },
  {
    id: "EQT-113",
    name: "Withdrawal and termination-of-employment rules",
    cite: irs("26 U.S.C. § 423(a)(2)", "employee stock purchase plans — employment requirement"),
    pat: [
      /withdraw/i,
      /(terminat(es|ion)\s+of\s+employment|ceases?\s+to\s+be\s+an\s+employee|refund\s+of\s+(the\s+)?contributions)/i,
    ],
    why: "The favorable treatment requires continuous employment from grant through three months before exercise. The plan has to say what happens to accumulated payroll deductions when employment ends mid-period.",
    fix: "State the withdrawal procedure and deadline, and that participation ends on termination with a refund of accumulated contributions without interest.",
  },
]);

const PROFITS_INTEREST = pack("profits-interest-award", C, [
  {
    id: "EQT-114",
    name: "Threshold amount set at grant-date value",
    cite: irs(
      "Rev. Proc. 93-27",
      "safe harbor for receipt of a partnership profits interest for services",
    ),
    pat: [
      /(threshold\s+amount|distribution\s+threshold|hurdle)/i,
      /(fair\s+market\s+value\s+(as\s+of|on)\s+the\s+(grant|award)\s+date|liquidation\s+value)/i,
    ],
    why: "A profits interest is tax-free on receipt only if it has no liquidation value at grant — meaning the threshold equals the entity's value that day. A threshold set below it converts the award into a taxable capital interest.",
    fix: "State the threshold amount, that it equals the amount the holder would receive on a hypothetical liquidation at grant, and how it was determined.",
    sev: "critical",
  },
  {
    id: "EQT-115",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Rev. Proc. 93-27 safe-harbor recitals",
    cite: irs(
      "Rev. Proc. 2001-43",
      "determining the tax consequences of a substantially nonvested profits interest",
    ),
    pat: [
      /(rev\.?\s*proc\.?\s*93-27|revenue\s+procedure\s+93-27|2001-43)/i,
      /(safe[-\s]+harbor|profits\s+interest\s+for\s+services|no\s+(taxable\s+)?income\s+(on|upon)\s+(receipt|grant))/i,
    ],
    why: "The safe harbors require that the interest not relate to a substantially certain income stream, that it not be disposed of within two years, and that the partnership not be a publicly traded partnership. Reciting them documents the intended treatment.",
    fix: "Recite the parties' intent that the award be a profits interest under Rev. Procs. 93-27 and 2001-43, the two-year disposition limitation, and consistent tax reporting by both parties.",
  },
  {
    id: "EQT-116",
    name: "Section 83(b) election direction and deadline",
    cite: irs("26 U.S.C. § 83(b)", "election to include in gross income in year of transfer"),
    pat: [
      /83\(b\)/i,
      /(30\s*\)?\s*days|thirty\s+days|election|file\s+with\s+the\s+internal\s+revenue\s+service)/i,
    ],
    why: "For an unvested profits interest, Rev. Proc. 2001-43 relief and the § 83(b) election are the standard belt-and-braces. The 30-day deadline is jurisdictional and cannot be extended.",
    fix: "Direct the participant to consider filing a § 83(b) election within 30 days of grant, state that the participant is solely responsible for filing, and attach a form.",
    sev: "critical",
  },
  {
    id: "EQT-117",
    name: "Vesting, forfeiture, and repurchase",
    cite: practice("profits-interest-vesting", "vesting and forfeiture of profits interests"),
    pat: [/vest/i, /(forfeit|repurchase|call\s+right|unvested\s+units)/i],
    why: "Forfeiture of a partnership interest raises allocation questions the operating agreement must handle (forfeiture allocations and capital-account restoration), which a bare stock-style vesting schedule does not address.",
    fix: "State the vesting schedule, what happens to unvested and vested units on termination, and the repurchase right with its price and payment terms.",
  },
  {
    id: "EQT-118",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Capital-account and distribution mechanics",
    cite: cfr("26", "1.704-1(b)(2)(iv)", "Treasury regulations — capital account maintenance"),
    pat: [
      /capital[-\s]+account/i,
      /(book-?up|revalu|distribution\s+waterfall|allocations?\s+of\s+(profit|income))/i,
    ],
    why: "A profits interest only works if the operating agreement books up capital accounts at grant and maintains them under the § 704(b) regulations. Without the book-up the holder shares in pre-grant value.",
    fix: "Require a capital-account book-up on issuance, confirm § 704(b)-compliant maintenance, and state where the units sit in the distribution waterfall.",
  },
  {
    id: "EQT-119",
    name: "Partner (not employee) tax treatment warning",
    cite: agency_rev_rul(),
    pat: [
      /(partner\s+for\s+(federal\s+)?tax\s+purposes|no\s+longer\s+(be\s+)?(treated\s+as\s+)?an\s+employee)/i,
      /(self-?employment|k-?1|schedule\s+k-1|estimated\s+tax)/i,
    ],
    why: "Rev. Rul. 69-184 says a partner cannot be an employee of the same partnership. A recipient moves from W-2 to K-1 with self-employment tax and quarterly estimates — a surprise that generates real complaints.",
    fix: "State that the holder becomes a partner for tax purposes, will receive a Schedule K-1 rather than a W-2, and is responsible for self-employment tax and estimated payments.",
    sev: "critical",
  },
]);

const WARRANT = pack("warrant-agreement", C, [
  {
    id: "EQT-120",
    name: "Number of shares, class, and exercise price",
    cite: practice("warrant-terms", "core economic terms of a stock purchase warrant"),
    pat: [
      /(number\s+of\s+(warrant\s+)?shares|shares\s+of\s+(common|preferred)\s+stock)/i,
      /exercise\s+price/i,
    ],
    why: "A warrant with an unfixed share number or price is an option to negotiate. Where the count is formula-based (a coverage percentage on a future round) the formula and its inputs have to be complete.",
    fix: "State the class and number of shares, or the complete formula, and the exercise price or its determination method.",
    sev: "critical",
  },
  {
    id: "EQT-121",
    name: "Cashless or net exercise mechanics",
    cite: practice("net-exercise", "net exercise mechanics in warrants"),
    pat: [
      /(cashless\s+exercise|net\s+exercise|net\s+issue)/i,
      /(formula|fair\s+market\s+value|x\s*=|withhold(ing)?\s+shares)/i,
    ],
    why: "Warrant holders rarely want to write a check at the moment of exercise. Without a net-exercise formula the warrant may expire unexercised despite being deep in the money.",
    fix: "Add a net-exercise election with the share formula and the definition of fair market value used in it.",
  },
  {
    id: "EQT-122",
    name: "Anti-dilution and capitalization adjustments",
    cite: practice("warrant-antidilution", "adjustment provisions in warrants"),
    pat: [
      /(stock\s+split|stock\s+dividend|recapitali[sz]ation|combination)/i,
      /(adjust(ment|ed)?|proportionate)/i,
    ],
    why: "A warrant without adjustment provisions is destroyed by a reverse split or a recapitalization. Whether price-based anti-dilution applies at all is a separate negotiation from structural adjustment.",
    fix: "Provide for structural adjustment on splits, dividends, combinations, and reclassifications, and state whether any price-based anti-dilution applies.",
  },
  {
    id: "EQT-123",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Expiration and automatic-exercise trigger",
    cite: practice("warrant-expiration", "expiration and automatic exercise in warrants"),
    pat: [
      /(expir(e|ation|es)|terminate)/i,
      /(automatic(ally)?[-\s]+exercis|deemed\s+exercised|forfeit)/i,
    ],
    why: "In-the-money warrants expire unexercised more often than any other instrument, usually because the holder was not tracking the date. Automatic net exercise at expiry solves it.",
    fix: "State the expiration date and add automatic net exercise immediately before expiration if the warrant is then in the money.",
  },
  {
    id: "EQT-124",
    // 1.0.1 — written as a synonym OR, but the acquisition trigger and the notice period are distinct pillars; `notice` alone is in every notices clause. The check could not
    // fire on any realistic document.
    ver: "1.0.1",
    name: "Termination on acquisition and notice period",
    cite: practice("warrant-acquisition", "acquisition treatment and notice in warrants"),
    pat: [
      /(acquisition|merger|sale\s+of\s+the\s+company|change\s+of\s+control)/i,
      /(notice|assum(e|ed|ption)|terminate\s+(upon|on)|days\s+(prior|before))/i,
    ],
    all: true,
    why: "Warrants often terminate on an acquisition if not exercised. A holder given no advance notice loses the instrument without an opportunity to act — the most common warrant dispute there is.",
    fix: "State whether the warrant is assumed or terminates on an acquisition, and require the company to give a stated number of days' advance written notice of the closing.",
  },
]);

const SECONDARY = pack("secondary-stock-transfer", C, [
  {
    id: "EQT-125",
    name: "ROFR and co-sale waiver evidence",
    cite: practice("rofr-waiver", "right of first refusal clearance in secondary transfers"),
    pat: [
      /(right\s+of\s+first\s+refusal|rofr|co-?sale)/i,
      /(waiv(e|ed|er)|expired|declined\s+to\s+exercise|notice\s+period\s+has\s+lapsed)/i,
    ],
    why: "A transfer made before the company's and investors' refusal rights have run is void under most stockholders' agreements. The waiver or lapse is the transaction's condition precedent.",
    fix: "Condition closing on written waiver or documented expiration of every right of first refusal, co-sale, and transfer-approval right.",
    sev: "critical",
  },
  {
    id: "EQT-126",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Company consent and transfer-agent instruction",
    cite: practice(
      "transfer-consent",
      "company consent and stock-ledger updates in secondary transfers",
    ),
    pat: [
      /(consent\s+of\s+the\s+company|company['’]?s?\s+(written\s+)?(consent|approval))/i,
      /(transfer[-\s]+agent|stock\s+ledger|book\s+entry|record\s+the\s+transfer)/i,
    ],
    why: "A private company's shares transfer on its books, not by delivery of a certificate. Without the company's consent and ledger entry, the buyer holds nothing enforceable.",
    fix: "Condition closing on the company's written consent and its instruction to record the transfer on the stock ledger or with the transfer agent.",
  },
  {
    id: "EQT-127",
    name: "Securities-law exemption relied on",
    cite: usc("15", "77d", "Securities Act § 4 — exempted transactions"),
    pat: [
      /(rule\s+144|section\s+4\(a\)\(7\)|4\(a\)\(1\)|4\(a\)\(1½\)|regulation\s+d)/i,
      /(exempt|not\s+been\s+registered|private\s+resale)/i,
    ],
    why: "A resale of restricted securities needs its own exemption. § 4(a)(7), Rule 144, and the § 4(a)(1½) practice each carry different conditions, and getting it wrong creates rescission rights.",
    fix: "State the exemption relied on and the conditions satisfied — holding period, information delivery, accredited-purchaser status, and no general solicitation.",
    sev: "critical",
  },
  {
    id: "EQT-128",
    name: "Seller representations on title and liens",
    cite: practice("secondary-title", "title representations in secondary stock sales"),
    pat: [
      /(good\s+and\s+(valid|marketable)\s+title|owns?\s+the\s+shares\s+free\s+and\s+clear)/i,
      /(lien|encumbrance|claim|community\s+property|spousal\s+consent)/i,
    ],
    why: "Shares carry pledges, community-property interests, and forfeiture conditions that only the seller knows. The title representation is the buyer's whole protection in a transaction with no diligence.",
    fix: "Take representations on title, absence of liens, no pledge or option, tax basis, and spousal consent where the seller is in a community-property state.",
  },
  {
    id: "EQT-129",
    ver: "1.1.0",
    name: "Information asymmetry acknowledgment",
    cite: usc("15", "78j", "Securities Exchange Act § 10(b) — manipulative and deceptive devices"),
    // 1.1.0 — the clause is written the other way round, and with the words
    // the market actually uses. A secondary's section 7 reads: "the Company
    // HAS PROVIDED NO INFORMATION to it, … the Seller MAY POSSESS MATERIAL
    // NON-PUBLIC INFORMATION that the Seller is NOT OBLIGED TO DISCLOSE, …
    // the Purchaser irrevocably WAIVES any claim arising from the
    // NON-DISCLOSURE of that information, and acknowledges that this waiver is
    // a MATERIAL INDUCEMENT to the Seller." Neither pillar could read any of
    // it: the first wanted the negation before the verb, and the second wanted
    // "sophisticated" or "independent investigation" from a clause that
    // allocates the risk rather than describing the buyer.
    pat: [
      /(no\s+(representation|information)\s+(has\s+been\s+)?(made|provided)|(?:has|have|having)\s+(?:provided|made)\s+no\s+(?:information|representation)|may\s+(?:possess|have|hold)\s+material\s+non-?public\s+information|information\s+asymmetry|big\s+boy)/i,
      /(sophisticated|independent\s+investigation|own\s+(analysis|due\s+diligence)|material\s+inducement|not\s+(?:obliged|obligated|required)\s+to\s+disclose|waives?[^.]{0,80}?non-?disclosure)/i,
    ],
    why: "The seller may hold material non-public information the buyer does not. A 'big boy' acknowledgment does not waive Rule 10b-5 liability, but it is the market-standard allocation and evidence of non-reliance.",
    fix: "Add mutual acknowledgments of possible information asymmetry, non-reliance, and the parties' sophistication — without purporting to waive federal securities-law liability.",
  },
  {
    id: "EQT-130",
    name: "409A and tax reporting responsibility",
    cite: irs("26 U.S.C. § 409A", "inclusion in gross income of deferred compensation"),
    pat: [
      /(409a|fair\s+market\s+value\s+determination)/i,
      /(tax\s+(reporting|withholding|consequences)|1099|each\s+party\s+is\s+responsible\s+for\s+its\s+own\s+tax)/i,
    ],
    why: "Secondary sales above the 409A price are evidence of value that can affect the company's option pricing, and an employee seller's gain may be compensation income subject to withholding.",
    fix: "State each party's tax reporting responsibility, whether the company will treat any portion as compensation subject to withholding, and the effect on the 409A valuation.",
  },
]);

const VENTURE_SPA = pack("venture-stock-purchase-agreement", C, [
  {
    id: "EQT-131",
    name: "Restated certificate filed as a closing condition",
    cite: practice(
      "restated-certificate",
      "filing the amended and restated certificate of incorporation at a preferred financing closing",
    ),
    pat: [
      /(amended\s+and\s+restated|restated)\s+certificate\s+of\s+incorporation|restated\s+certificate/i,
      /(file[ds]?\s+with\s+the\s+secretary\s+of\s+state|filing\s+of\s+the\s+restated|condition(?:ed)?\s+on[^.]{0,120}?filing)/i,
    ],
    all: true,
    why: "The preferred stock does not exist until the restated certificate is on file — every economic and control term of the round lives in it, not in this agreement. A closing that does not condition on the filing can leave the investors holding shares of a series that has not been created.",
    fix: "Attach the restated certificate as an exhibit and condition each closing on its filing with the Secretary of State.",
    sev: "critical",
  },
  {
    id: "EQT-132",
    name: "Capitalization representation and disclosure schedule",
    cite: practice(
      "capitalization-rep",
      "the capitalization representation and its disclosure schedule in a venture financing",
    ),
    pat: [
      /\bcapitali[sz]ation\b|authori[sz]ed\s+capital|issued\s+and\s+outstanding/i,
      /disclosure\s+schedule|except\s+as\s+set\s+(?:out|forth)\s+on/i,
    ],
    all: true,
    why: "The capitalization representation is the one an investor prices the round on, and the exceptions live on the disclosure schedule. A representation with no schedule is either untrue or incomplete.",
    fix: "State the authorized, issued and outstanding capital by class, list every option, warrant and convertible, and qualify the representation by a disclosure schedule delivered at signing.",
    sev: "critical",
  },
  {
    id: "EQT-133",
    name: "Authorization and valid issuance",
    cite: practice(
      "valid-issuance",
      "the authorization and valid-issuance representations in a preferred financing",
    ),
    pat: [
      /valid(?:ly)?\s+issued|duly\s+authori[sz]ed|corporate\s+action\s+required/i,
      /fully\s+paid|non-?assessable|enforceable\s+in\s+accordance\s+with\s+its\s+terms/i,
    ],
    all: true,
    why: "These are the representations counsel's closing opinion rests on. Without them the investor has no contractual recourse if the board never approved the issuance or the shares were not lawfully authorized.",
    fix: "Represent that all corporate action has been taken, that the shares will be validly issued, fully paid and non-assessable, and that this agreement is enforceable against the company.",
  },
  {
    id: "EQT-134",
    name: "Purchaser private-placement representations",
    cite: cfr(
      "17",
      "230.506",
      "Regulation D — rules governing the limited offer and sale of securities",
    ),
    pat: [
      /accredited\s+investor|regulation\s+d|rule\s+501/i,
      /(own\s+account|not\s+with\s+a\s+view\s+to\s+distribut|restricted\s+securit|general\s+solicitation)/i,
    ],
    all: true,
    why: "The exemption the round relies on is the purchasers' status and intent, and only their written representations establish it. Without them the issuer cannot show the offering was exempt.",
    fix: "Have each purchaser represent that it is an accredited investor, is acquiring for its own account and not with a view to distribution, understands the shares are restricted, and was not solicited generally.",
    sev: "critical",
  },
  {
    id: "EQT-135",
    name: "Ancillary agreements executed at closing",
    cite: practice(
      "ancillary-agreements",
      "the investors' rights, voting, and co-sale agreements as closing deliverables",
    ),
    pat: [
      /investors[’']?\s+rights\s+agreement|voting\s+agreement|co-?sale\s+agreement/i,
      /(condition|deliver\w*|execut\w*|counterpart\s+signature)/i,
    ],
    all: true,
    why: "The governance, registration, and transfer terms of the round are not in this agreement — they are in the three ancillary agreements. A closing that does not condition on their execution leaves the round documented in one document out of four.",
    fix: "Condition each closing on execution of the investors' rights agreement, the voting agreement, and the right of first refusal and co-sale agreement by the company and the requisite holders.",
  },
  {
    id: "EQT-136",
    name: "Survival of the representations",
    cite: practice(
      "rep-survival",
      "survival of representations and warranties in a venture financing",
    ),
    pat: [
      /surviv\w+/i,
      /(representations?\s+and\s+warrant|\bfor\s+(?:a\s+period\s+of\s+)?[a-z-]*\s*\(?\d{1,3}\)?\s*(?:month|year)s?\b|indefinitely)/i,
    ],
    all: true,
    why: "A venture financing has no indemnity and no escrow: survival of the representations is the investor's only post-closing recourse, and its period is the whole of the bargain.",
    fix: "State how long the representations survive the closing, and name any that survive indefinitely.",
  },
]);

/** Rev. Rul. 69-184 — a partner cannot simultaneously be an employee of the partnership. */
function agency_rev_rul() {
  return irs(
    "Rev. Rul. 69-184",
    "a partner in a partnership may not be treated as an employee of that partnership",
  );
}

export const V5_EQUITY_RULES: readonly Rule[] = [
  ...PLAN,
  ...ESPP,
  ...PROFITS_INTEREST,
  ...WARRANT,
  ...SECONDARY,
  ...VENTURE_SPA,
];
