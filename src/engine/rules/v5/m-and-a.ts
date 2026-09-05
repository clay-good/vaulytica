/**
 * v5 sub-domain D′ — US M&A closing deliverables and private-placement
 * investment documents (spec-v45.md §6.D). Rule ids continue the MNA
 * namespace at 101.
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { irs, cfr, ucc, practice } from "./_helpers.js";

const C = "m-and-a";

const MIPA = pack("membership-interest-purchase-agreement", C, [
  {
    id: "MNA-101",
    name: "Interests conveyed and capitalization representation",
    cite: practice(
      "mipa-capitalization",
      "capitalization representations in LLC interest purchases",
    ),
    pat: [
      /(membership\s+interests?|units?)\s+(being\s+)?(sold|purchased|conveyed|transferred)/i,
      /(capitali[sz]ation|all\s+of\s+the\s+(issued\s+and\s+)?outstanding|percentage\s+interest)/i,
    ],
    why: "An LLC has no stock ledger a buyer can rely on. The capitalization representation — that the listed interests are all of them, fully paid, and free of options — is the buyer's only assurance it is buying the whole company.",
    fix: "Describe the interests conveyed and take a capitalization representation covering all outstanding interests, options, and rights to acquire them.",
    sev: "critical",
  },
  {
    id: "MNA-102",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Purchase price and working-capital adjustment",
    cite: practice("working-capital", "working capital adjustments in private acquisitions"),
    pat: [
      /purchase\s+price/i,
      /(working[-\s]+capital|adjustment|estimated\s+closing|true-?up|net\s+debt)/i,
    ],
    why: "Post-closing adjustment disputes are the most common M&A litigation. The target, the accounting principles, and the dispute mechanism have to be complete or the true-up becomes an arbitration.",
    fix: "State the price, the working-capital target and its calculation principles, the estimate-and-true-up timetable, and the independent-accountant dispute procedure.",
  },
  {
    id: "MNA-103",
    name: "Tax treatment and elections",
    cite: irs("Rev. Rul. 99-6", "federal tax treatment of the purchase of all interests in an LLC"),
    pat: [
      /(tax\s+treatment|for\s+(federal\s+)?(income\s+)?tax\s+purposes)/i,
      /(section\s+754|338\(h\)\(10\)|336\(e\)|purchase\s+price\s+allocation|rev\.?\s*rul\.?\s*99-6)/i,
    ],
    why: "Buying all LLC interests is treated as an asset purchase for the buyer under Rev. Rul. 99-6, which changes basis, allocation, and the seller's character of gain. Buying some interests raises a § 754 election.",
    fix: "State the intended tax treatment, any § 754, § 338(h)(10), or § 336(e) election, and the purchase price allocation procedure and its binding effect.",
    sev: "critical",
  },
  {
    id: "MNA-104",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Operating-agreement consents and admission of the buyer",
    cite: practice(
      "llc-admission",
      "member admission and transfer consents under an operating agreement",
    ),
    pat: [
      /(operating[-\s]+agreement|llc\s+agreement)/i,
      /(consent|admit(ted)?\s+as\s+a\s+member|substitute\s+member|amend(ed|ment)\s+to\s+(the\s+)?(operating|llc)\s+agreement)/i,
    ],
    why: "An assignee of an LLC interest gets economic rights only; admission as a member requires the consent the operating agreement specifies. Without it the buyer has bought distributions, not control.",
    fix: "Condition closing on the consents the operating agreement requires and on an amendment or joinder admitting the buyer as a member with voting rights.",
    sev: "critical",
  },
  {
    id: "MNA-105",
    ver: "1.1.0",
    name: "Indemnity, caps, baskets, and survival",
    cite: practice(
      "indemnity-architecture",
      "indemnification architecture in private acquisitions",
    ),
    // `all: true`, and the second pillar carries word boundaries. Joined by an
    // OR, the bare word "cap" matched inside "CAPitalized terms have the
    // meanings given in Section 1" — so the column was satisfied by a purchase
    // agreement's definitions cross-reference, and an APA with no cap, no
    // basket, and no survival period passed it in silence.
    pat: [/indemnif/i, /\b(?:caps?|baskets?|deductibles?|survival|escrows?|de\s+minimis)\b/i],
    all: true,
    why: "The indemnity architecture is the entire post-closing risk allocation. Survival periods that expire before the buyer could discover the breach, or a cap below the deal's real exposure, are where the value leaks.",
    fix: "State survival periods by representation category, the deductible or tipping basket, the de minimis, the cap, and the escrow or holdback securing them.",
  },
  {
    id: "MNA-106",
    // 1.0.1 — both pillars required the verb to sit immediately after the
    // modal, and a sale-of-business covenant states its SCOPE in between:
    // "each Seller shall not, within the states in which the Company
    // conducted business as of the Closing, engage in a business competitive
    // with the Business, or solicit for employment any employee". That is the
    // covenant this rule asks for, drafted the way its own `fix` text says to
    // draft it — with a defined scope and geography — and it was reported as
    // absent. A bounded run now separates the modal from the verb, and the
    // second pillar reads the "or solicit" continuation of the same sentence.
    ver: "1.0.1",
    name: "Seller non-compete and non-solicit",
    cite: practice("seller-noncompete", "sale-of-business restrictive covenants"),
    pat: [
      /(non-?compet|(?:shall|will|must)\s+not[^.]{0,90}?\b(compete|engage\s+in))/i,
      /(non-?solicit|(?:shall|will|must)\s+not[^.]{0,120}?\b(solicit|hire)\b)/i,
    ],
    why: "Sale-of-business covenants get materially more latitude than employment covenants in most states — including California, where § 16601 permits them only in connection with a sale of goodwill. Without one, the buyer has paid for goodwill the seller can rebuild.",
    fix: "Add non-compete and non-solicit covenants tied to the sale of goodwill, with a defined scope, geography, and duration, and allocate consideration to them.",
  },
  {
    id: "MNA-107",
    name: "Closing conditions and deliverables",
    cite: practice("closing-conditions", "conditions precedent and closing deliverables"),
    pat: [
      /(conditions?\s+(precedent|to\s+(the\s+)?(obligation|closing))|closing\s+conditions)/i,
      /(deliver|certificate|resolutions|good\s+standing|lien\s+releases)/i,
    ],
    why: "The deliverables list is the closing checklist. Omissions — lien releases, payoff letters, resignations, consents — are discovered on closing day and delay the wire.",
    fix: "Enumerate the conditions precedent and the closing deliverables for each party, including certificates, resignations, payoff letters, lien releases, and third-party consents.",
  },
]);

const ASSIGNMENT = pack("assignment-and-assumption-agreement", C, [
  {
    id: "MNA-108",
    ver: "1.2.0",
    name: "Schedule of assigned contracts",
    cite: practice("assigned-contracts", "identification of assigned contracts at closing"),
    pat: [
      // The SINGULAR too. An assignment and assumption of one named contract
      // — "that certain Transportation Services Agreement dated May 8, 2023
      // ... (the 'Assigned Contract')" — identifies exactly what moved, which
      // is what this rule exists to require, and the plural-only pattern
      // reported it at `critical` as having no schedule of assigned contracts.
      /(assigned\s+contracts?|(?:schedule|exhibit|annexure|annex|appendix)\s+[a-z0-9]|set\s+forth\s+(on|in)\s+(exhibit|schedule|annexure|annex|appendix))/i,
      // The second pillar keeps the OR — a singly-named "Assigned Contract"
      // identifies what moved just as a schedule does, which is why the first
      // pillar reads the singular — but it may not be satisfied by an ordinary
      // preamble. A bare "identified on" matched "between the parties
      // IDENTIFIED ON the signature page", so an assignment with no
      // identification of any kind passed this column in silence.
      /\b(?:contracts?|agreements?|leases?|assets?|schedules?)\s+(?:listed|identified|described|set\s+forth)\s+(?:on|in)\b/i,
    ],
    why: "A blanket assignment of 'all contracts' does not tell a counterparty, a court, or the buyer's own team which agreements moved. The schedule is the operative list.",
    fix: "Attach a schedule identifying each assigned contract by parties, date, and title, and state that only scheduled contracts are assigned.",
    sev: "critical",
  },
  {
    id: "MNA-109",
    name: "Assumed versus excluded liabilities",
    cite: practice("assumed-liabilities", "assumed and excluded liabilities in asset transactions"),
    pat: [/assumed\s+liabilit/i, /(excluded\s+liabilit|does\s+not\s+assume|retained\s+liabilit)/i],
    why: "The point of an asset structure is that the buyer takes only what it names. Without an express exclusion of everything else, successor-liability arguments have somewhere to land.",
    fix: "State the assumed liabilities specifically and add an express statement that the buyer assumes no other liability of any kind.",
    sev: "critical",
  },
  {
    id: "MNA-110",
    name: "Third-party consent carve-out",
    cite: practice("anti-assignment", "anti-assignment clauses and non-assignable contracts"),
    pat: [
      /(consent\s+(of|from)\s+(the\s+)?(third\s+part|counterpart)|required\s+consent)/i,
      /((?:shall|will)\s+not\s+(constitute|be\s+deemed)\s+an\s+assignment|not\s+(be\s+)?assigned\s+(until|unless)|nothing\s+herein)/i,
    ],
    why: "Assigning a contract that forbids assignment is a breach that can terminate the very contract being bought. The carve-out keeps unconsented contracts out of the assignment until consent arrives.",
    fix: "Exclude contracts whose assignment requires consent until consent is obtained, and add a cooperation and alternative-arrangement clause for the interim.",
  },
  {
    id: "MNA-111",
    name: "Effective time tied to the closing",
    cite: practice("effective-time", "effective time in closing deliverables"),
    pat: [
      /(effective\s+(as\s+of|time)|as\s+of\s+the\s+closing)/i,
      /(12:0[01]|immediately\s+(prior|before|after)|closing\s+date)/i,
    ],
    why: "Assignment documents that recite a date but no time create gaps and overlaps in liability, and tax proration disputes about which day's activity belongs to whom.",
    fix: "State the effective time by reference to the closing (for example, 12:01 a.m. on the Closing Date) and align it with the purchase agreement and the proration schedule.",
  },
  {
    id: "MNA-112",
    name: "Further assurances and power of attorney",
    cite: practice("further-assurances", "further assurances in transfer documents"),
    pat: [
      /further\s+(assurances?|acts)/i,
      /(power\s+of\s+attorney|attorney-?in-?fact|execute\s+(and\s+deliver\s+)?such\s+(other|additional))/i,
    ],
    why: "Some transfers need instruments nobody identified before closing — foreign recordations, agency filings, bank forms. Without further assurances and a limited power of attorney the buyer must chase a seller that has been paid.",
    fix: "Add a further-assurances covenant and a limited power of attorney letting the buyer execute transfer instruments in the seller's name if the seller fails to.",
  },
]);

const BILL_OF_SALE = pack("bill-of-sale", C, [
  {
    id: "MNA-113",
    name: "Assets conveyed with schedule reference",
    cite: ucc("2-401", "Passing of title; reservation for security"),
    pat: [
      /(purchased\s+assets|assets\s+(described|listed|set\s+forth))/i,
      /(schedule|exhibit|annexure|annex|appendix)/i,
    ],
    why: "A bill of sale is the instrument of conveyance for tangible property. Conveying 'the assets' without a schedule leaves the identification to the purchase agreement, which is not what a lender or a court will be handed.",
    fix: "Identify the conveyed assets by schedule reference and incorporate the schedule into the bill of sale itself.",
    sev: "critical",
  },
  {
    id: "MNA-114",
    name: "Title warranty and lien-free recital",
    cite: ucc("2-312", "Warranty of title and against infringement"),
    pat: [
      /(good\s+(and\s+(valid|marketable)\s+)?title|warrants?\s+title)/i,
      /(free\s+and\s+clear|no\s+liens|encumbrance)/i,
    ],
    why: "§ 2-312 supplies a title warranty unless it is specifically excluded. Whether it is given or disclaimed should be a decision, not an accident of drafting.",
    fix: "State the title warranty and the free-and-clear recital with any permitted encumbrances scheduled, or disclaim the warranty in the specific language § 2-312(2) requires.",
  },
  {
    id: "MNA-115",
    name: "As-is disclaimer consistent with the purchase agreement",
    cite: ucc("2-316", "Exclusion or modification of warranties"),
    pat: [
      /(as\s+is|where\s+is|without\s+(any\s+)?(other\s+)?warrant)/i,
      /(disclaim|except\s+as\s+(expressly\s+)?(set\s+forth|provided)\s+in\s+the\s+purchase\s+agreement)/i,
    ],
    why: "A bill of sale that disclaims all warranties can be read to supersede the representations in the purchase agreement. The cross-reference is what keeps the buyer's bargain intact.",
    fix: 'Disclaim implied warranties but add: "except as expressly set forth in the Purchase Agreement, the representations and warranties of which are not superseded by this Bill of Sale."',
    sev: "critical",
  },
  {
    id: "MNA-116",
    ver: "1.1.0",
    name: "Effective time and further assurances",
    cite: practice("bos-effective", "effective time and further assurances in a bill of sale"),
    pat: [
      // A bill of sale states its effective time in the execution clause —
      // "executed this Bill of Sale AS OF October 20, 2026" — which the
      // adjacent "effective as of" / "as of the closing" forms could not
      // read. Conjoining the two pillars without this would have reported a
      // dated instrument as undated.
      /(effective\s+(as\s+of|time)|as\s+of\s+(?:the\s+closing|[A-Z][a-z]+\s+\d|\d)|dated)/i,
      /(further\s+assurances?|execute\s+(and\s+deliver\s+)?such)/i,
    ],
    // Both halves, as the rationale requires: certain assets "need SEPARATE
    // instruments the bill of sale does not effect", so a document with
    // further assurances and no effective time — or an effective time and no
    // further assurances — answers only half the question.
    all: true,
    why: "Certain assets — titled vehicles, registered IP, permits — need separate instruments the bill of sale does not effect. Further assurances is how they get delivered after the wire.",
    fix: "State the effective time and add a further-assurances covenant for assets requiring separate transfer instruments.",
  },
]);

const SUBSCRIPTION = pack("subscription-agreement", C, [
  {
    id: "MNA-117",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Accredited-investor status and verification",
    cite: cfr("17", "230.501", "Regulation D — Rule 501 definitions, accredited investor"),
    pat: [
      /accredited[-\s]+investor/i,
      /(rule\s+501|net\s+worth|income\s+in\s+each\s+of\s+the\s+two\s+most\s+recent|verif)/i,
    ],
    why: "Rule 506(b) permits up to 35 non-accredited purchasers with full disclosure; 506(c) permits general solicitation only if the issuer takes reasonable steps to verify accreditation. The representation alone is not verification under 506(c).",
    fix: "Take an accredited-investor representation with the qualifying category checked, and describe the verification steps if the offering relies on Rule 506(c).",
    sev: "critical",
  },
  {
    id: "MNA-118",
    name: "Exemption relied on",
    cite: cfr("17", "230.506", "Regulation D — Rule 506 exemption for limited offers and sales"),
    pat: [
      /(rule\s+506|regulation\s+d|section\s+4\(a\)\(2\))/i,
      /(exempt(ion)?|not\s+been\s+registered\s+under\s+the\s+securities\s+act)/i,
    ],
    why: "The exemption drives everything else: whether general solicitation is permitted, whether non-accredited investors may participate, what disclosure is required, and what Form D filing is due.",
    fix: "State the exemption relied on (506(b) or 506(c)), and confirm no general solicitation where 506(b) applies.",
    sev: "critical",
  },
  {
    id: "MNA-119",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Investment-intent and no-resale representation",
    cite: cfr("17", "230.502(d)", "Regulation D — limitations on resale"),
    pat: [
      /(investment[-\s]+(intent|purpose)|for\s+(its|his|her|the\s+subscriber['’]?s)\s+own\s+account)/i,
      /(not\s+with\s+a\s+view\s+to\s+(the\s+)?(distribution|resale)|no\s+present\s+intention\s+(to|of)\s+(sell|distribut))/i,
    ],
    why: "Rule 502(d) securities are restricted, and the issuer must take reasonable care to ensure purchasers are not underwriters. The investment-intent representation is the standard evidence of that care.",
    fix: "Take a representation that the subscriber acquires for its own account for investment and not with a view to distribution.",
  },
  {
    id: "MNA-120",
    name: "Restrictive legend and transfer limits",
    cite: cfr("17", "230.144", "Rule 144 — persons deemed not to be engaged in a distribution"),
    pat: [
      /legend/i,
      /(may\s+not\s+be\s+(sold|offered|transferred)|restricted\s+securities|registration\s+statement\s+or\s+an\s+exemption)/i,
    ],
    why: "The legend is what stops a transfer agent from processing an unlawful resale. Its absence undercuts the issuer's reasonable-care defense and complicates every future secondary.",
    fix: "Set out the restrictive legend that will appear on the certificate or book entry, and state the conditions for its removal.",
  },
  {
    id: "MNA-121",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Risk-factor acknowledgment",
    cite: cfr("17", "230.502(b)", "Regulation D — information requirements"),
    pat: [
      /(risk[-\s]+factors?|risks\s+(of|associated\s+with)\s+(the\s+)?investment)/i,
      /(acknowledg|has\s+(reviewed|received)|able\s+to\s+bear\s+the\s+(economic\s+)?(risk|loss))/i,
    ],
    why: "Rule 502(b) requires specified information for non-accredited purchasers, and the anti-fraud rules apply regardless. The acknowledgment is the record that the risk disclosure was delivered and read.",
    fix: "Acknowledge receipt and review of the offering materials and risk factors, and take a representation that the subscriber can bear a total loss of the investment.",
  },
  {
    id: "MNA-122",
    // Also accepts the HYPHENATED spelling of the compound this rule's own
    // name hyphenates — the ordinary spelling when it is used as an
    // adjective (`v5/title-vacuity.test.ts`).
    ver: "1.1.0",
    name: "Bad-actor representations",
    cite: cfr("17", "230.506(d)", "Regulation D — disqualifying events (bad actor)"),
    pat: [
      /(bad[-\s]+actor|rule\s+506\(d\)|disqualif)/i,
      /(covered\s+person|no\s+(disqualifying\s+)?event|felony|injunction|regulatory\s+order)/i,
    ],
    why: "A disqualifying event affecting any covered person destroys the Rule 506 exemption for the entire offering. Issuers must exercise reasonable care to determine no covered person is disqualified.",
    fix: "Take bad-actor representations from the issuer's covered persons and from any purchaser who will own 20% or more of voting power.",
  },
  {
    id: "MNA-123",
    // 1.0.1 — written as a synonym OR, but the acceptance/rejection right and the escrow of funds are distinct pillars. The check could not
    // fire on any realistic document.
    ver: "1.0.1",
    name: "Acceptance, rejection, and escrow of funds",
    cite: practice(
      "subscription-acceptance",
      "acceptance mechanics and escrow in subscription agreements",
    ),
    pat: [
      /(accept(ance)?\s+(of\s+)?(this\s+)?subscription|reject\s+(any\s+)?subscription|in\s+whole\s+or\s+in\s+part)/i,
      /(escrow|held\s+(in|until)|returned\s+without\s+interest|minimum\s+offering)/i,
    ],
    all: true,
    why: "A subscription is an offer until the issuer accepts. Without an acceptance mechanic and a treatment of funds pending acceptance, the issuer holds money on unclear terms.",
    fix: "State that the issuer may accept or reject in whole or in part, when acceptance occurs, and how funds are held and returned if the subscription is rejected or a minimum is not met.",
  },
]);

const SIDE_LETTER = pack("side-letter", C, [
  {
    id: "MNA-124",
    name: "Rights granted beyond the principal documents",
    cite: practice("side-letter-rights", "scoping of investor side-letter rights"),
    pat: [
      /(in\s+addition\s+to|notwithstanding\s+anything\s+to\s+the\s+contrary)/i,
      /(information\s+rights|board\s+observer|pro\s+rata|participation\s+rights|mfn)/i,
    ],
    why: "A side letter is only useful if it says exactly which right it adds. Vague grants — 'reasonable information rights' — are unenforceable in the moment they matter.",
    fix: "Enumerate each right granted, with the cadence, format, and deadline for anything the company must deliver.",
    sev: "critical",
  },
  {
    id: "MNA-125",
    name: "Precedence over the principal agreement",
    cite: practice(
      "side-letter-precedence",
      "order of precedence between side letters and principal documents",
    ),
    // 1.1.0 — the NOTWITHSTANDING form, which is how a side letter usually
    // states its precedence and is at least as common as the conflict clause:
    // "NOTWITHSTANDING ANYTHING TO THE CONTRARY IN the Purchase Agreement or
    // the IRA, the Company agrees as follows", closed at the end by "EXCEPT AS
    // EXPRESSLY PROVIDED HERE, the Purchase Agreement and the IRA REMAIN IN
    // FULL FORCE AND EFFECT". Together those two sentences say exactly what
    // this check asks for — the letter controls where it speaks, the principal
    // agreements control everywhere else — and a venture side letter carrying
    // both drew a `critical` for stating no precedence at all.
    //
    // The named principal agreement is required in the same clause, so a
    // "notwithstanding anything to the contrary herein" that points at the
    // letter's OWN terms is not mistaken for an order of precedence.
    ver: "1.1.0",
    pat: [
      /(in\s+the\s+event\s+of\s+(any\s+)?conflict|to\s+the\s+extent\s+(of\s+any\s+)?inconsisten)/i,
      /(this\s+letter\s+((?:shall|will)\s+)?(control|govern|prevail)|the\s+purchase\s+agreement\s+((?:shall|will)\s+)?(control|govern))/i,
      /notwithstanding\s+anything\s+(?:to\s+the\s+contrary\s+)?(?:contained\s+)?in\s+(?:the\s+)[^.]{0,80}?\b(?:Agreement|IRA|Purchase\s+Agreement|Charter|Certificate)\b/i,
      /except\s+as\s+(?:expressly\s+)?(?:provided|set\s+forth|modified)\s+(?:here|herein|in\s+this\s+letter)[^.]{0,120}?\bremains?\s+in\s+full\s+force\b/i,
    ],
    why: "Two documents signed the same day with inconsistent terms is a construction problem no court enjoys. The precedence clause is what makes the side letter operative rather than ambiguous.",
    fix: "State expressly that this letter controls over inconsistent provisions of the named principal agreement, or that it does not.",
    sev: "critical",
  },
  {
    id: "MNA-126",
    name: "MFN scope and disclosure obligation",
    cite: practice("mfn", "most-favored-nation clauses in investor side letters"),
    pat: [
      /most\s+favored\s+nation|mfn/i,
      /(disclose|provide\s+copies\s+of\s+(all\s+)?side\s+letters|elect\s+to\s+(adopt|receive))/i,
    ],
    why: "An MFN without a disclosure duty is unenforceable in practice: the investor cannot elect rights it never learns about. The company also needs the scope bounded or the MFN cascades across the whole round.",
    fix: "State the MFN scope (which investors and which rights), require the company to disclose other side letters within a stated period, and set the election deadline.",
    when: [/most\s+favored\s+nation|mfn/i],
  },
  {
    id: "MNA-127",
    name: "Termination on IPO, transfer, or threshold drop",
    cite: practice("side-letter-termination", "termination triggers for side-letter rights"),
    pat: [
      /(terminat|(?:shall|will)\s+(cease|expire)|no\s+longer\s+(apply|be\s+in\s+effect))/i,
      /(initial\s+public\s+offering|ipo|transfers?\s+(all|its)|falls?\s+below|ceases?\s+to\s+hold)/i,
    ],
    why: "Side-letter rights that survive an IPO or follow a transferee create Regulation FD and governance problems for a public company, and give a departed investor rights it no longer pays for.",
    fix: "Terminate the rights on a qualified IPO, on transfer of the investor's shares, and if holdings fall below a stated threshold.",
  },
  {
    id: "MNA-128",
    // 1.0.1 — written as a synonym OR, but the amendment mechanics and the other-investor consent are distinct pillars; `amend` alone is in every amendment clause. The check could not
    // fire on any realistic document.
    //
    // 1.0.2 — the second pillar then wanted "only BY a writing", and the
    // standard drafting is "amended only IN a writing SIGNED BY the Company
    // and Kestrel". A side letter with the clause was told it had none.
    ver: "1.0.2",
    name: "Amendment mechanics and other-investor consent",
    cite: practice(
      "side-letter-amendment",
      "amendment of side letters relative to the principal agreement",
    ),
    pat: [
      /amend(ed|ment)?/i,
      // NOT "written AGREEMENT signed" — that is the entire-agreement
      // boilerplate every document carries, and admitting it makes the check
      // unable to fire (`boilerplate-reachability` proves as much).
      /(?:written\s+(?:instrument|consent)\s+signed|(?:writing|instrument)\s+signed\s+by|only\s+(?:by|in)\s+(?:a\s+)?writing|requisite\s+(?:holders|investors))/i,
    ],
    all: true,
    why: "If the principal agreement can be amended by a majority of holders, an amendment can gut a side-letter right the minority investor bargained for — unless the side letter says otherwise.",
    fix: "State that this letter may be amended only by the signatories, and whether an amendment of the principal agreement affects the rights granted here.",
  },
]);

export const V5_M_AND_A_RULES: readonly Rule[] = [
  ...MIPA,
  ...ASSIGNMENT,
  ...BILL_OF_SALE,
  ...SUBSCRIPTION,
  ...SIDE_LETTER,
];
