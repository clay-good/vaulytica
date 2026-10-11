/**
 * v7 — tranche B, the practice-only types (spec-v49.md §4, Step 312).
 *
 * Four documents the second probe found falling to the generic fallback: a
 * standalone software support and maintenance agreement, a buy-sell
 * agreement among the owners of a closely held company, a board observer
 * agreement, and a commercial power purchase agreement. No statute or rule
 * lists what any of them must say — I.R.C. § 2703(b), often cited for buy-sell
 * pricing, is a test applied to the facts, not a list of clauses — so every
 * check is cited as customary practice and none reports above a warning.
 */

import type { Rule } from "../../finding.js";
import { pack } from "../v5/_pack.js";
import { practice } from "../v5/_helpers.js";
import { PERIOD_COUNT } from "../../../extract/counts.js";
import { AMOUNT_IN_WORDS, CURRENCY_TOKEN } from "../../../extract/amounts.js";

const SUM = String.raw`(?:(?:${CURRENCY_TOKEN})\s?\d|${AMOUNT_IN_WORDS})`;
const PERCENT = String.raw`\d+(?:\.\d+)?\s?(?:%|percent)`;

// ── Software support and maintenance agreement ──────────────────────
const SUPPORT = pack("support-maintenance-agreement", "commercial", [
  {
    id: "SUP-001",
    name: "Support hours and how to reach support",
    cite: practice("support-hours", "when support is open, and by what channel"),
    pat: [
      /\b(business\s+hours|24\s?[x×/]\s?7|twenty-four\s+hours|\d{1,2}(:\d{2})?\s?(am|pm|a\.m\.|p\.m\.)\b[^.]{0,40}?\b(to|through|until)\b|support\s+hours|hours\s+of\s+(support|coverage))\b/i,
    ],
    why: "Support that is 'available' means nothing until the agreement says when and how: the hours, the time zone, and whether a request goes by telephone, email or a ticket portal. An outage at 6:00 pm is covered or not depending on a sentence.",
    fix: "State the hours and days support is available, the time zone, and the channels for opening a request.",
  },
  {
    id: "SUP-002",
    name: "Response and resolution times by severity",
    cite: practice("support-response-times", "how fast, for how serious a problem"),
    all: true,
    pat: [
      /\b(severity|priority|critical|urgent|p1|sev(erity)?\s?1)\b/i,
      new RegExp(
        String.raw`\b(respond\w*|response|resolv\w+|resolution|workaround|acknowledg\w+)\b[^.]{0,120}?\bwithin\s+${PERIOD_COUNT}\s+(business\s+)?(minutes?|hours?|days?)\b`,
        "i",
      ),
    ],
    why: "A support agreement is bought for the bad day. Without severity levels and a time for each — to respond, and to fix or work around — the vendor's only promise is to answer eventually.",
    fix: "Define severity levels, and for each state the time to respond and the target time to resolve or provide a workaround.",
  },
  {
    id: "SUP-003",
    name: "Updates, upgrades and new releases",
    cite: practice("support-updates", "what the maintenance fee buys"),
    pat: [
      /\b(updates?|upgrades?|new\s+(releases?|versions?)|patch(es)?|bug\s+fix(es)?|error\s+corrections?|maintenance\s+releases?)\b/i,
    ],
    why: "Maintenance is the right to the software's fixes and new versions. Whether a major new version is included or sold separately is the commonest surprise at renewal.",
    fix: "State that error corrections, patches and updates are included, and say whether major new versions are included or licensed separately.",
  },
  {
    id: "SUP-004",
    name: "Which versions are supported, and for how long",
    cite: practice("support-versions", "end of life for an old version"),
    pat: [
      /\b(supported\s+versions?|current\s+(and\s+)?(the\s+)?(prior|previous|preceding)|prior\s+(major\s+)?(release|version)|end[-\s]of[-\s](life|support)|sunset\w*|discontinu\w+)\b/i,
    ],
    why: "Vendors stop supporting old versions. A customer that cannot upgrade on the vendor's schedule needs to know how long the version it runs will be supported and how much notice it gets before that ends.",
    fix: "State which versions are supported — for example, the current release and the one before it — and the notice the vendor gives before ending support for a version.",
  },
  {
    id: "SUP-005",
    name: "The support fee, and how it can rise",
    cite: practice("support-fee", "the annual fee and a limit on increases"),
    all: true,
    pat: [
      new RegExp(String.raw`\b(fees?|charges?|price)\b[^.]{0,160}?(${SUM}|${PERCENT})`, "i"),
      /\b(increas\w+|adjust\w+|escalat\w+|rais\w+|fixed\s+for|will\s+not\s+(increase|change)|shall\s+not\s+(increase|change)|must\s+not\s+(increase|change)|no\s+increase)\b/i,
    ],
    why: "Support fees are usually a percentage of the license fee and rise at renewal. A customer locked into the software has little leverage then, so the limit on increases has to be agreed now.",
    fix: "State the annual support fee and how it is calculated, and cap the increase at each renewal — for example, at a stated percentage or the change in a named price index.",
  },
  {
    id: "SUP-006",
    name: "What support does not cover",
    cite: practice("support-exclusions", "the problems the vendor will not fix for the fee"),
    pat: [
      /\b(exclud\w+|exclusions?|does\s+not\s+(include|cover)|not\s+(included|covered)|outside\s+the\s+scope|not\s+obligated\s+to\s+(support|provide))\b/i,
    ],
    why: "Vendors exclude problems caused by the customer's changes, unsupported hardware, third-party software and old versions. If the exclusions are not listed, each one is argued when a ticket is refused.",
    fix: "List what support does not cover, and say whether the vendor will work on an excluded problem at its hourly rates.",
  },
]);

// ── Buy-sell agreement ──────────────────────────────────────────────
const BUY_SELL = pack("buy-sell-agreement", "governance", [
  {
    id: "BSA-001",
    name: "The events that trigger a purchase",
    cite: practice("buy-sell-triggers", "death, disability, departure, divorce, insolvency"),
    pat: [
      /\b(death|dies|deceased|disabilit(y|ies)|incapacit\w+|retire\w*|terminat\w+\s+of\s+employment|divorce|dissolution\s+of\s+marriage|bankrupt\w+|insolven\w+)\b/i,
    ],
    why: "A buy-sell agreement exists to say what happens to an owner's interest when that owner dies, becomes disabled, leaves, divorces or goes bankrupt. Any of those events left out is one where a stranger — an heir, a former spouse, a creditor — may end up an owner.",
    fix: "List each event that triggers a purchase: death, disability, retirement or the end of employment, divorce, bankruptcy, and an attempted transfer to an outsider.",
  },
  {
    id: "BSA-002",
    name: "Whether the purchase is required or optional",
    cite: practice("buy-sell-obligation", "an obligation to buy, or only a right"),
    pat: [
      /\b(shall|will|must|is\s+obligated\s+to|are\s+obligated\s+to|agrees?\s+to)\s+(purchase|buy|redeem|sell)\b/i,
      /\b(option|right)\s+to\s+(purchase|buy|redeem)\b|\bright\s+of\s+first\s+(refusal|offer)\b/i,
    ],
    why: "An estate that must sell to a company that need not buy has a restriction and no market. Whether each side is bound — the company or the other owners to buy, the departing owner or the estate to sell — decides whether the agreement gives anyone certainty.",
    fix: "For each triggering event, state whether the company or the remaining owners must buy or only may, and whether the departing owner or the estate must sell.",
  },
  {
    id: "BSA-003",
    name: "How the price is set",
    cite: practice("buy-sell-price", "an agreed value, a formula, or an appraisal"),
    pat: [
      /\b(purchase\s+price|price|value|valuation)\b[^.]{0,200}?\b(apprais\w+|formula|book\s+value|fair\s+market\s+value|agreed\s+value|certificate\s+of\s+(agreed\s+)?value|multiple\s+of|determined\s+by)\b/i,
      /\b(apprais\w+|fair\s+market\s+value|book\s+value|agreed\s+value)\b[^.]{0,200}?\b(purchase\s+price|price)\b/i,
    ],
    why: "The price term is where buy-sell agreements fail. A fixed price goes stale, a formula can miss what the business has become, and 'a price to be agreed' is no price when the parties are an estate and a surviving owner. The method, and a fallback when it produces no answer, have to be written before anyone knows which side they will be on.",
    fix: "State how the price is set — an agreed value updated each year, a formula, or an appraisal — and the fallback if the agreed value is out of date or the parties cannot agree on an appraiser.",
  },
  {
    id: "BSA-004",
    name: "How the purchase is funded",
    cite: practice("buy-sell-funding", "life insurance, or the buyer's own money"),
    pat: [
      /\b(life\s+insurance|disability\s+(buy-?out\s+)?insurance|insurance\s+(policy|policies|proceeds)|sinking\s+fund|fund\w*\s+(the|its|their)\s+(purchase|obligation))\b/i,
    ],
    why: "An obligation to buy an owner's interest is worth what the buyer can pay. Life insurance funds a purchase at death; nothing funds one at retirement or divorce unless the agreement says what does. An unfunded obligation can sink the company it was meant to protect.",
    fix: "State how each purchase will be funded — insurance on each owner's life for a purchase at death, and the company's or the buyers' own funds, paid in installments, for the others.",
  },
  {
    id: "BSA-005",
    name: "How the price is paid",
    cite: practice(
      "buy-sell-payment",
      "cash at closing, or installments with interest and security",
    ),
    pat: [
      /\b(instal?lments?|promissory\s+note|down\s+payment|payable\s+(in|over)|paid\s+(in\s+(cash|full)|over|at\s+(the\s+)?closing)|lump\s+sum)\b/i,
    ],
    why: "Few closely held companies can pay for an owner's interest at once. Whether the price is paid in cash or over years, at what interest, and with what security for the unpaid part, matters as much to a departing owner as the price itself.",
    fix: "State whether the price is paid at closing or in installments, and for installments the term, the interest rate and the security for the unpaid balance.",
  },
  {
    id: "BSA-006",
    name: "Restriction on transfers to outsiders",
    cite: practice(
      "buy-sell-transfer-restriction",
      "no sale outside the group without an offer to it first",
    ),
    pat: [
      /\b(no|not|may\s+not|shall\s+not|will\s+not|must\s+not)\b[^.]{0,80}?\b(transfer|sell|assign|pledge|encumber)\b/i,
      /\bright\s+of\s+first\s+(refusal|offer)\b/i,
    ],
    why: "The agreement works only if an owner cannot simply sell to someone else. The restriction, and the right of the company or the other owners to buy first on the same terms, is what keeps ownership within the group that signed.",
    fix: "State that no owner may transfer an interest except as the agreement allows, and give the company and the other owners a right of first refusal on any proposed sale.",
  },
]);

// ── Board observer agreement ────────────────────────────────────────
const OBSERVER = pack("board-observer-agreement", "governance", [
  {
    id: "OBS-001",
    name: "The right to attend, without a vote",
    cite: practice("observer-attendance", "attendance at board meetings in a non-voting capacity"),
    all: true,
    pat: [
      /\battend\w*\b[^.]{0,160}?\b(meetings?|sessions?)\b/i,
      /\bnon-?voting\b|\b(no|not|without)\b[^.]{0,40}?\b(vote|voting)\b/i,
    ],
    why: "An observer attends and listens; a director votes and owes duties. The agreement has to say which this is, and which meetings — the full board only, or its committees too — the observer may attend.",
    fix: "State that the observer may attend all meetings of the board, and say whether that includes committees, in a non-voting capacity.",
  },
  {
    id: "OBS-002",
    name: "Notice and board materials",
    cite: practice("observer-materials", "the same notice and papers the directors get"),
    pat: [
      /\b(materials|notices?|minutes|consents|information|documents)\b[^.]{0,160}?\b(directors?|board)\b/i,
    ],
    why: "A right to attend is hollow without notice of the meeting and the papers circulated for it. The usual term gives the observer what the directors receive, at the same time.",
    fix: "State that the company will give the observer notice of each meeting and copies of all materials provided to the directors, at the same time and in the same manner.",
  },
  {
    id: "OBS-003",
    name: "The grounds on which the observer can be excluded",
    cite: practice(
      "observer-exclusion",
      "privilege, conflict of interest, competitive information",
    ),
    pat: [
      /\b(exclud\w+|withhold\w*|recus\w+)\b[^.]{0,240}?\b(privilege\w*|conflicts?\s+of\s+interest|trade\s+secrets?|competit\w+|highly\s+confidential)\b/i,
    ],
    why: "An observer is not a director, so sharing legal advice with the observer can waive the company's attorney-client privilege. The company needs the right to exclude the observer for that reason and for a conflict of interest; the investor needs those to be the only reasons.",
    fix: "State that the company may exclude the observer from a meeting, or withhold materials, only as reasonably needed to preserve attorney-client privilege, avoid a conflict of interest, or protect trade secrets from a competitor.",
  },
  {
    id: "OBS-004",
    name: "Confidentiality of what the observer learns",
    cite: practice(
      "observer-confidentiality",
      "the observer is bound, and so is whoever sent the observer",
    ),
    pat: [/\bconfidential\w*\b/i, /\bnon-?disclosure\b/i],
    why: "A director is bound to confidence by duty; an observer is bound only by contract. The agreement is the whole of the obligation, and it should reach the investor that appointed the observer as well as the person in the room.",
    fix: "Bind the observer, and the investor that designated the observer, to keep board information confidential and to use it only to monitor the investment.",
  },
  {
    id: "OBS-005",
    name: "The events that end the observer right",
    cite: practice("observer-termination", "a shareholding floor, a public offering, a sale"),
    ver: "1.0.0",
    pat: [
      /\b(terminat\w+|expires?|ceases?|ends?|no\s+longer)\b[^.]{0,240}?\b(public\s+offering|IPO|initial\s+public|holds?\s+(fewer|less)|ceases?\s+to\s+(hold|own)|shares|percent|%|change\s+of\s+control|sale\s+of\s+the\s+company|acquisition|merger)\b/i,
    ],
    why: "An observer seat granted to an early investor can outlast the investment that justified it. The usual limits are a minimum shareholding, the company's public offering, and its sale.",
    fix: "State that the observer right ends when the investor holds fewer than a stated number of shares, on the company's initial public offering, or on a sale of the company.",
  },
]);

// ── Commercial power purchase agreement ─────────────────────────────
const POWER_PURCHASE = pack("commercial-power-purchase-agreement", "commercial", [
  {
    id: "PPA-001",
    name: "The term, and the date it starts running",
    cite: practice("ppa-term", "years from the commercial operation date"),
    all: true,
    pat: [
      new RegExp(String.raw`${PERIOD_COUNT}[-\s]+(years?|months?)\b`, "i"),
      /\b(commercial\s+operation(s)?\s+date|COD|in-?service\s+date|commenc\w+|effective\s+date)\b/i,
    ],
    why: "A power purchase agreement runs for ten to twenty-five years from the day the facility starts commercial operation, not the day it is signed. Both the length and the starting event have to be stated, with a date by which the facility must be operating.",
    fix: "State the length of the term, that it runs from the commercial operation date, and the latest date by which commercial operation must occur.",
  },
  {
    id: "PPA-002",
    name: "The price, and how it changes",
    cite: practice("ppa-price", "a price per unit of energy and its escalator"),
    pat: [
      new RegExp(
        String.raw`${SUM}[\d,.]*\s*(per|/|a)\s*(megawatt[-\s]?hours?|kilowatt[-\s]?hours?|MWh|kWh)\b`,
        "i",
      ),
      /\b(contract\s+price|energy\s+price|price)\b[^.]{0,160}?\b(megawatt[-\s]?hours?|kilowatt[-\s]?hours?|MWh|kWh)\b/i,
    ],
    why: "The price per megawatt-hour, and whether it is fixed or rises each year, is the whole economic bargain over a term measured in decades.",
    fix: "State the price per megawatt-hour or kilowatt-hour, and whether it is fixed for the term or escalates at a stated rate each year.",
  },
  {
    id: "PPA-003",
    name: "The delivery point, and who bears losses before it",
    cite: practice("ppa-delivery-point", "the point where title and risk pass"),
    pat: [
      /\b(delivery\s+point|point\s+of\s+(delivery|interconnection)|interconnection\s+point|busbar|point\s+of\s+receipt)\b/i,
    ],
    why: "Title, risk of loss and the cost of transmission all change hands at the delivery point. Energy priced at the facility and energy priced at the buyer's meter are different products.",
    fix: "Name the delivery point, and state that title and risk of loss pass there and which party bears transmission costs and losses on each side of it.",
  },
  {
    id: "PPA-004",
    name: "Who gets the renewable energy credits",
    cite: practice(
      "ppa-environmental-attributes",
      "credits, certificates and other environmental attributes",
    ),
    pat: [
      /\b(renewable\s+energy\s+(credits?|certificates?)|RECs?|environmental\s+attributes?|green\s+attributes?|carbon\s+(credits?|offsets?))\b/,
    ],
    why: "A buyer that pays a premium for renewable power and does not receive the credits cannot claim to use renewable energy; the seller can sell them to someone who then makes that claim. The contract has to say who owns them.",
    fix: "State whether the renewable energy credits and other environmental attributes are transferred to the buyer with the energy, and how they are delivered and tracked.",
  },
  {
    id: "PPA-005",
    name: "A commitment on output, and what curtailment costs",
    cite: practice("ppa-output", "guaranteed production, availability, or payment when curtailed"),
    pat: [
      /\b(guarant\w+|minimum|expected|committed)\b[^.]{0,120}?\b(output|production|generation|energy|availability|megawatt[-\s]?hours?|MWh)\b/i,
      /\bcurtail\w+/i,
    ],
    why: "A promise to sell 'all the energy the facility produces' promises no quantity. The buyer plans around an expected output, and the seller's revenue depends on not being curtailed; the contract should say what happens when either falls short.",
    fix: "State the output or availability the seller guarantees and the remedy for a shortfall, and who bears the cost when the buyer or the grid operator curtails delivery.",
  },
  {
    id: "PPA-006",
    name: "Security for each party's performance",
    cite: practice("ppa-credit-support", "a guaranty, a letter of credit, or a deposit"),
    pat: [
      /\b(letter\s+of\s+credit|credit\s+support|performance\s+(security|assurance|bond)|parent\s+guarant\w+|guarant(y|ee)\b|security\s+deposit|collateral)\b/i,
    ],
    why: "A project company with one asset is selling for twenty years to a buyer whose credit may change. Each side's ability to pay damages, and the seller's ability to finance the project at all, rests on the credit support the contract requires.",
    fix: "State the credit support each party must post — a parent guaranty, a letter of credit or a deposit — its amount, and the events that require more.",
  },
]);

export const TRANCHE_B_RULES: readonly Rule[] = [
  ...SUPPORT,
  ...BUY_SELL,
  ...OBSERVER,
  ...POWER_PURCHASE,
];
