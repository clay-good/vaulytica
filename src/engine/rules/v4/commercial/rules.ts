/**
 * v4 Commercial-agreements ruleset — spec-v4.md §6.A additions.
 *
 * Landed sub-domains:
 *   A.10 — Manufacturing / Supply agreement (COMM-001..COMM-007), UCC
 *          Article 2: quantity (§ 2-306), delivery (§ 2-309),
 *          specifications / warranty (§ 2-313/2-314), price (§ 2-305),
 *          inspection / acceptance (§ 2-513/2-606), force majeure
 *          (§ 2-615), and the § 2-306(2) best-efforts obligation.
 *   A.8  — Reseller / Distribution agreement (COMM-008..COMM-013): the
 *          appointment / territory / exclusivity, minimum purchase, resale
 *          pricing (Leegin), term & termination (dealer statutes),
 *          trademark license & quality control, and post-termination
 *          inventory / cease-use.
 *   A.9  — Channel partner / Referral agreement (COMM-014..COMM-018):
 *          qualified-referral definition, referral-fee terms, RESPA § 8
 *          compliance for settlement-service referrals, independent-
 *          contractor status, and an anti-bribery representation.
 *
 * Rule ids are flat `COMM-NNN`.
 */

import type { Rule } from "../../../finding.js";
import { buildV4PresenceRule, type V4PresenceSpec } from "../_helpers.js";
import {
  COMM_PLAYBOOK_MANUFACTURING,
  COMM_PLAYBOOK_DISTRIBUTION,
  COMM_PLAYBOOK_REFERRAL,
  ucc,
  sherman,
  lanham,
  respa,
  commPractice,
} from "./_helpers.js";

const CATEGORY = "commercial";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// A.10 — Manufacturing / Supply agreement. 7 rules: COMM-001..COMM-007.
// ────────────────────────────────────────────────────────────────────

const MANUFACTURING_SUPPLY_RULES: Rule[] = [
  presence({
    id: "COMM-001",
    name: "Quantity term — requirements / output / firm quantity",
    description:
      "A supply agreement must state a quantity term: a firm quantity, a requirements/output measure, or a binding forecast.",
    citation: ucc("2-306", "Output, requirements and exclusive dealings"),
    playbooks: [COMM_PLAYBOOK_MANUFACTURING],
    missing_title: "Quantity term missing",
    missing_description:
      "No quantity term (firm quantity, requirements / output measure, or binding forecast) was found.",
    explanation:
      "UCC § 2-306 measures an output or requirements contract by the party's actual good-faith output or requirements; a supply agreement with no quantity term at all risks being unenforceable for indefiniteness or illusory for want of a measured obligation.",
    recommendation:
      "State the quantity as a firm amount, as Buyer's requirements / Seller's output, or as a binding forecast with a commitment percentage and a not-unreasonably-disproportionate cap.",
    present_patterns: [
      /\brequirements\b|\boutput\b/i,
      /(firm|minimum|committed|annual|monthly)\s+(quantity|volume|amount|order)/i,
      /(binding\s+)?forecast/i,
      /(quantity|volume)\s+(of\s+)?(goods|products|units)/i,
    ],
  }),
  presence({
    id: "COMM-002",
    name: "Delivery schedule / lead time",
    description:
      "A supply agreement should state delivery timing — a schedule, lead time, or Incoterms delivery point.",
    citation: ucc("2-309", "Absence of specific time provisions; notice of termination"),
    playbooks: [COMM_PLAYBOOK_MANUFACTURING],
    missing_title: "Delivery schedule / lead time missing",
    missing_description: "No delivery schedule, lead time, or delivery point was found.",
    explanation:
      "UCC § 2-309 fills a missing delivery time with a 'reasonable time', which invites dispute. A stated schedule, lead time, or Incoterms delivery point fixes the parties' expectations and the point of risk-of-loss transfer.",
    recommendation:
      "Add a 'Delivery' clause stating the schedule or lead time, the delivery point / Incoterms, and the risk-of-loss transfer.",
    present_patterns: [
      /delivery\s+(schedule|date|time|term|point)/i,
      /lead\s+time/i,
      /\b(fob|f\.o\.b\.|ex\s+works|exw|ddp|dap|cif|incoterms)\b/i,
      /(ship|deliver)\w*\s+within\s+\d/i,
    ],
  }),
  presence({
    id: "COMM-003",
    name: "Specifications / conformance and warranty",
    description: "The goods must be tied to specifications and an express warranty of conformance.",
    citation: ucc("2-313", "Express warranties by affirmation, promise, description, sample"),
    playbooks: [COMM_PLAYBOOK_MANUFACTURING],
    missing_title: "Specifications / warranty clause missing",
    missing_description:
      "No specifications, conformance standard, or warranty of conformance was found.",
    explanation:
      "UCC § 2-313 makes a description of the goods or a sample an express warranty. Without stated specifications and a conformance warranty, the buyer's remedy for defective goods rests only on the implied warranties (§ 2-314/2-315), which sellers routinely disclaim.",
    recommendation:
      "Add 'Specifications' (or reference an attached spec sheet) and a warranty that the goods will conform to those specifications and be free from defects in material and workmanship.",
    present_patterns: [
      /specifications?\b|spec\s+sheet/i,
      /conform\w*\s+(to|with)/i,
      /warrant\w*\s+that\s+the\s+(goods|products)/i,
      /free\s+from\s+defects/i,
    ],
  }),
  presence({
    id: "COMM-004",
    name: "Price or price-adjustment mechanism",
    description:
      "A supply agreement should state the price or a mechanism for setting / adjusting it.",
    citation: ucc("2-305", "Open price term"),
    playbooks: [COMM_PLAYBOOK_MANUFACTURING],
    missing_title: "Price / price-mechanism clause missing",
    missing_description: "No price or price-adjustment mechanism was found.",
    explanation:
      "UCC § 2-305 lets a contract stand with an open price set at a 'reasonable price' in good faith, but a long-term supply relationship should fix the price or a mechanism (index, cost-plus, most-favored-customer, annual re-open) to avoid a good-faith-pricing dispute.",
    recommendation:
      "Add 'Price' stating the unit price or a pricing mechanism (index-linked, cost-plus, or scheduled re-open) and any price-adjustment triggers.",
    present_patterns: [
      /(unit\s+price|purchase\s+price|price\s+(per|schedule|list))/i,
      /price\s+adjustment|repric\w*/i,
      /(index|cost.?plus|most.?favored)/i,
      /\bpricing\b/i,
    ],
  }),
  presence({
    id: "COMM-005",
    name: "Inspection, acceptance, and rejection",
    description:
      "Buyer should have a stated right to inspect, accept, and reject nonconforming goods.",
    citation: ucc("2-513", "Buyer's right to inspection of goods"),
    playbooks: [COMM_PLAYBOOK_MANUFACTURING],
    missing_title: "Inspection / acceptance clause missing",
    missing_description:
      "No inspection, acceptance, or rejection-of-nonconforming-goods clause was found.",
    explanation:
      "UCC § 2-513 gives the buyer a right to inspect before payment, and § 2-606 deems goods accepted if not seasonably rejected. A stated inspection window and rejection procedure preserves the buyer's remedies for nonconforming deliveries.",
    recommendation:
      "Add an 'Inspection and Acceptance' clause with an inspection window, an acceptance standard, and a rejection / cure procedure for nonconforming goods.",
    present_patterns: [
      /inspect\w*/i,
      /(accept|reject)\w*\s+.{0,40}(goods|products|delivery|shipment)/is,
      /non.?conform\w*/i,
      /right\s+to\s+(reject|return)/i,
    ],
  }),
  presence({
    id: "COMM-006",
    name: "Force majeure / excuse for supervening events",
    description:
      "A supply agreement should allocate the risk of supervening events that prevent performance.",
    citation: ucc("2-615", "Excuse by failure of presupposed conditions"),
    playbooks: [COMM_PLAYBOOK_MANUFACTURING],
    missing_title: "Force-majeure / excuse clause missing",
    missing_description: "No force-majeure or commercial-impracticability clause was found.",
    explanation:
      "UCC § 2-615 excuses a seller only for a contingency whose non-occurrence was a basic assumption of the contract — a high, uncertain bar. An express force-majeure clause defines the excused events, the notice duty, and any allocation / termination right, allocating supply-chain risk deliberately.",
    recommendation:
      "Add 'Force Majeure' listing the excused events, the notice obligation, the allocation of available supply, and a termination right if the event continues beyond a stated period.",
    present_patterns: [
      /force\s+majeure/i,
      /(commercial\s+)?impracticab\w*/i,
      /act\s+of\s+god/i,
      /beyond\s+(its|the|a\s+party.s)\s+(reasonable\s+)?control/i,
    ],
  }),
  presence({
    id: "COMM-007",
    name: "Best-efforts obligation for a requirements / exclusive arrangement",
    description:
      "A requirements / output or exclusive-dealing supply arrangement must carry the § 2-306(2) best-efforts obligation.",
    citation: ucc("2-306(2)", "Best efforts in exclusive dealing"),
    playbooks: [COMM_PLAYBOOK_MANUFACTURING],
    // Only relevant where the arrangement is a requirements / output or
    // exclusive one — otherwise § 2-306(2) does not apply and its absence is
    // not a defect.
    applicable_if: [/\brequirements\b|\boutput\b|\bexclusiv\w*/i],
    missing_title: "Best-efforts obligation missing (exclusive dealing)",
    missing_description:
      "The arrangement is a requirements / output or exclusive one but no best-efforts / commercially-reasonable-efforts obligation was found.",
    explanation:
      "UCC § 2-306(2) implies, in an exclusive-dealing contract, an obligation on the seller to use best efforts to supply and on the buyer to use best efforts to promote their sale. Stating the standard expressly (and any minimums) forecloses the classic Wood v. Lucy dispute over what the exclusive party actually owes.",
    recommendation:
      "Add a 'Best Efforts' clause stating the supply / promotion effort standard (best or commercially reasonable efforts) and any minimum purchase / stocking commitments.",
    present_patterns: [
      /best\s+efforts|best\s+endeavou?rs/i,
      /commercially\s+reasonable\s+efforts/i,
      /(diligent|reasonable)\s+efforts/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// A.8 — Reseller / Distribution agreement. 6 rules: COMM-008..COMM-013.
// ────────────────────────────────────────────────────────────────────

const DISTRIBUTION_RULES: Rule[] = [
  presence({
    id: "COMM-008",
    name: "Appointment, territory, and exclusivity",
    description:
      "A distribution agreement must define the appointment: the territory / customer scope and whether it is exclusive or non-exclusive.",
    citation: sherman("Vertical territorial restraints — rule of reason (GTE Sylvania)"),
    playbooks: [COMM_PLAYBOOK_DISTRIBUTION],
    missing_title: "Appointment / territory clause missing",
    missing_description:
      "No clause defining the appointment, territory / customer scope, or exclusivity was found.",
    explanation:
      "Vertical territorial and customer restraints are judged under the rule of reason (Continental T.V. v. GTE Sylvania); the appointment must state the territory / field and whether it is exclusive so the parties — and a reviewing court — can assess the competitive scope of the restraint.",
    recommendation:
      "Add an 'Appointment' clause naming the products, the territory / customer scope, and whether the distributor is exclusive, sole, or non-exclusive.",
    present_patterns: [
      /appoint\w*/i,
      /\bterritory\b|\bterritories\b/i,
      /(exclusive|non.?exclusive|sole)\s+(distributor|reseller|right)/i,
      /(distributor|reseller)\b/i,
    ],
  }),
  presence({
    id: "COMM-009",
    name: "Minimum purchase / performance requirements",
    description:
      "A distribution agreement should set minimum purchase or performance requirements that measure the distributor's commitment.",
    citation: commPractice(
      "distribution-minimums",
      "Distribution-agreement minimum-performance baseline (ABA Antitrust Section)",
      "https://www.americanbar.org/groups/antitrust_law/",
    ),
    playbooks: [COMM_PLAYBOOK_DISTRIBUTION],
    missing_title: "Minimum-purchase / performance clause missing",
    missing_description: "No minimum-purchase or performance-requirement clause was found.",
    explanation:
      "Without a stated minimum purchase or performance quota, an exclusive appointment gives the distributor the territory with no measurable obligation — the supplier cannot police under-performance or justify terminating a passive distributor.",
    recommendation:
      "Add 'Minimum Purchases' or 'Performance Requirements' with an annual minimum (units or dollars) and the consequence of a shortfall (loss of exclusivity or termination).",
    present_patterns: [
      /minimum\s+(purchase|order|quantity|volume|amount)/i,
      /(annual|quarterly)\s+(minimum|quota|target)/i,
      /performance\s+(requirement|quota|target|obligation)/i,
      /\bquota\b/i,
    ],
  }),
  presence({
    id: "COMM-010",
    name: "Resale-pricing freedom / MAP policy",
    description:
      "A distribution agreement should leave the distributor free to set resale prices, or set pricing only through a lawful MAP policy.",
    citation: sherman("Resale price maintenance — rule of reason (Leegin)"),
    playbooks: [COMM_PLAYBOOK_DISTRIBUTION],
    // Only relevant where the agreement actually addresses RESALE pricing — a
    // distribution agreement silent on price has no resale-price-maintenance
    // problem (the distributor is implicitly free). Gate on a resale-pricing
    // context, not on the bare word "reseller".
    applicable_if: [
      /(resale|re-?sale|advertised)\s+price|\bmap\s+(policy|price)|price\s+(floor|maintenance|restriction)|minimum\s+(resale|advertised)\s+price/i,
    ],
    missing_title: "Resale-pricing freedom / MAP clause missing",
    missing_description:
      "The agreement addresses pricing but no resale-pricing-freedom statement or MAP policy was found.",
    explanation:
      "Minimum resale price maintenance is judged under the rule of reason (Leegin Creative Leather Prods. v. PSKS), and several states still treat it as per se unlawful. A distribution agreement should state that the distributor is free to set its own resale prices, or confine any pricing control to a lawful minimum-advertised-price (MAP) policy.",
    recommendation:
      "State that the distributor determines its own resale prices, or replace any minimum-resale-price term with a unilateral minimum-advertised-price (MAP) policy.",
    present_patterns: [
      /(distributor|reseller)\s+(may|shall)\s+(determine|set|establish).{0,30}(resale\s+)?price/is,
      /free\s+to\s+(determine|set)\s+.{0,20}price/is,
      /minimum\s+advertised\s+price|\bmap\s+policy\b/i,
      /own\s+resale\s+prices/i,
    ],
  }),
  presence({
    id: "COMM-011",
    name: "Term and termination — good cause and notice",
    description:
      "A distribution agreement should state the term and a termination standard with a notice / cure period.",
    citation: commPractice(
      "dealer-termination",
      "State dealer / distributor-protection statutes (e.g., Wisconsin Fair Dealership Law, Wis. Stat. ch. 135)",
      "https://docs.legis.wisconsin.gov/statutes/statutes/135",
    ),
    playbooks: [COMM_PLAYBOOK_DISTRIBUTION],
    missing_title: "Term / termination clause missing",
    missing_description:
      "No term, termination standard, or notice / cure period for termination was found.",
    explanation:
      "Many states protect a distributor or dealer from termination except for good cause and on notice (e.g., the Wisconsin Fair Dealership Law and analogous dealer statutes). Stating the term, a good-cause / for-convenience standard, and a notice / cure period aligns the agreement with those protections and avoids a wrongful-termination claim.",
    recommendation:
      "Add 'Term and Termination' stating the term, the termination grounds (for cause with a cure period, and any for-convenience right with notice), and the required notice period.",
    present_patterns: [
      /terminat\w*[\s\S]{0,60}(for\s+cause|good\s+cause|material\s+breach|convenience)/is,
      /(notice|cure)\s+period/i,
      /\d+\s+days.{0,20}(notice|prior\s+written\s+notice)/is,
      /\bterm\s+of\s+(this\s+)?agreement\b/i,
    ],
  }),
  presence({
    id: "COMM-012",
    name: "Trademark license and quality control",
    description:
      "A distribution agreement that lets the distributor use the supplier's marks must grant a license and reserve quality control.",
    citation: lanham("45", "Naked license — abandonment"),
    playbooks: [COMM_PLAYBOOK_DISTRIBUTION],
    // Only relevant where the agreement references the supplier's trademarks /
    // brand — a pure commodity-resale deal that never uses the marks does not
    // need a trademark-license clause.
    applicable_if: [/trademark|\bmarks?\b|brand|logo|trade\s+name/i],
    missing_title: "Trademark-license / quality-control clause missing",
    missing_description:
      "The agreement references the supplier's marks but no trademark license with quality control was found.",
    explanation:
      "A licensor that lets a distributor use its marks without controlling the quality of the goods or services risks a 'naked license' and abandonment of the marks (Lanham Act § 45). The agreement should grant a limited license and reserve the supplier's right to set and inspect quality standards.",
    recommendation:
      "Add a 'Trademark License' granting a limited, revocable license to use the marks in the territory, subject to the supplier's quality standards and right to inspect / approve use.",
    present_patterns: [
      /trademark\s+license|licens\w+\s+to\s+use\s+the\s+(marks?|trademarks?)/i,
      /quality\s+(control|standards)/i,
      /right\s+to\s+(inspect|approve)/i,
      /brand\s+(guidelines|standards)/i,
    ],
  }),
  presence({
    id: "COMM-013",
    name: "Post-termination — inventory repurchase and cease use",
    description:
      "A distribution agreement should address post-termination inventory repurchase / sell-off and cessation of use of the supplier's marks.",
    citation: commPractice(
      "dealer-repurchase",
      "State dealer inventory-repurchase statutes (equipment / dealer acts)",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_DISTRIBUTION],
    missing_title: "Post-termination inventory / cease-use clause missing",
    missing_description:
      "No post-termination inventory-repurchase / sell-off or cease-use-of-marks clause was found.",
    explanation:
      "On termination the distributor is left holding branded inventory and may keep using the supplier's marks. Many state dealer statutes require the supplier to repurchase unsold inventory; the agreement should also require the distributor to stop using the marks and return branded materials.",
    recommendation:
      "Add a 'Post-Termination' clause covering repurchase or an orderly sell-off of remaining inventory, cessation of use of the marks, and return of samples / branded materials.",
    present_patterns: [
      /repurchas\w*|buy.?back/i,
      /sell.?off|sell-through|dispose\s+of\s+.{0,20}inventory/is,
      /(cease|discontinue|stop)\s+(using|use\s+of).{0,30}(marks?|trademarks?|name)/is,
      /return\s+.{0,30}(materials|samples|inventory|marks)/is,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// A.9 — Channel partner / Referral agreement. 5 rules: COMM-014..COMM-018.
// ────────────────────────────────────────────────────────────────────

const REFERRAL_RULES: Rule[] = [
  presence({
    id: "COMM-014",
    name: "Qualified-referral / lead definition",
    description:
      "A referral agreement must define what counts as a qualified referral or lead that earns a fee.",
    citation: commPractice(
      "referral-qualification",
      "Channel / referral-agreement qualification baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_REFERRAL],
    missing_title: "Qualified-referral definition missing",
    missing_description:
      "No definition of a qualified referral / lead (the fee-triggering event) was found.",
    explanation:
      "Without a definition of what constitutes a qualified referral — introduction, accepted lead, or closed sale — the parties will dispute which introductions earn a fee. Tying the fee to a defined, verifiable event is the core of an enforceable referral arrangement.",
    recommendation:
      "Define 'Qualified Referral' / 'Lead' (e.g., a prospect the Partner introduces who is not already known and who executes an order) and the point at which the fee is earned.",
    present_patterns: [
      /(qualified\s+(referral|lead)|referral\s+fee)/i,
      /\blead\b[\s\S]{0,40}(defin|qualif|accept)/is,
      /introduc\w+[\s\S]{0,40}(customer|prospect|client)/is,
      /\breferral\b[\s\S]{0,40}(defin|means|qualif)/is,
    ],
  }),
  presence({
    id: "COMM-015",
    name: "Referral-fee amount and payment terms",
    description:
      "A referral agreement should state the fee amount / rate and when and how it is paid.",
    citation: commPractice(
      "referral-compensation",
      "Referral-fee compensation baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_REFERRAL],
    missing_title: "Referral-fee / payment-terms clause missing",
    missing_description: "No referral-fee amount / rate or payment-terms clause was found.",
    explanation:
      "The fee amount (flat, percentage of contract value, or tiered), the trigger for payment (on close, on collection), and the payment schedule are the economic core of the deal; their absence leaves the compensation indefinite.",
    recommendation:
      "State the fee as a flat amount or a percentage of the referred contract's value, the event that triggers payment, and the payment schedule and any clawback on refund / cancellation.",
    present_patterns: [
      /(referral|finder.?s?)\s+fee/i,
      /\d+\s*%|\bpercent\b|percentage\s+of/i,
      /(paid|payable)[\s\S]{0,40}(within|upon|after)\s+\d/is,
      /commission\s+(of|rate|schedule)/i,
    ],
  }),
  presence({
    id: "COMM-016",
    name: "RESPA § 8 compliance for settlement-service referrals",
    description:
      "A referral fee tied to real-estate settlement services must comply with the RESPA § 8 anti-kickback prohibition.",
    citation: respa("Prohibition against kickbacks and unearned fees"),
    playbooks: [COMM_PLAYBOOK_REFERRAL],
    // Only relevant where the referrals involve real-estate settlement services
    // — RESPA § 8 does not reach ordinary commercial referrals.
    applicable_if: [
      /\brespa\b|settlement\s+service|mortgage|real\s+estate|title\s+(insurance|company)|escrow|loan\s+origin/i,
    ],
    missing_title: "RESPA § 8 compliance clause missing (settlement-service referral)",
    missing_description:
      "The referrals involve real-estate settlement services but no RESPA § 8 compliance clause was found.",
    explanation:
      "RESPA § 8 (12 U.S.C. § 2607) makes it unlawful to pay a fee for the mere referral of real-estate settlement-service business; a fee is permissible only for services actually performed at their reasonable market value, or within an affiliated-business or other safe harbor. A referral fee for settlement services without a compliance statement risks a per-violation penalty.",
    recommendation:
      "Add a RESPA-compliance clause confirming the fee is for services actually performed (or fits a § 8(c) safe harbor), with the required affiliated-business-arrangement disclosure where applicable.",
    present_patterns: [
      /\brespa\b|12\s+u\.?s\.?c\.?\s+§?\s*2607|section\s+8/i,
      /services\s+actually\s+(performed|rendered)/i,
      /affiliated\s+business\s+(arrangement|disclosure)/i,
      /reasonable\s+(market\s+)?value\s+of\s+.{0,20}services/is,
    ],
  }),
  presence({
    id: "COMM-017",
    name: "Independent contractor — no authority to bind",
    description:
      "A referral / channel partner must be an independent contractor with no authority to bind the principal.",
    citation: commPractice(
      "referral-agency",
      "Referral-agreement agency-disclaimer baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_REFERRAL],
    missing_title: "Independent-contractor / no-authority clause missing",
    missing_description:
      "No independent-contractor status or no-authority-to-bind clause was found.",
    explanation:
      "If the referral partner appears to act as the principal's agent, the principal can be bound by the partner's representations and liable for the partner's conduct. Stating independent-contractor status and disclaiming authority to bind, quote, or make representations forecloses apparent-authority and vicarious-liability claims.",
    recommendation:
      "Add an 'Independent Contractor' clause stating the Partner is not an agent, employee, or joint venturer and has no authority to bind, quote prices, or make representations on the Company's behalf.",
    present_patterns: [
      /independent\s+contractor/i,
      /no\s+authority\s+to\s+bind/i,
      /(not|nor)\s+(an?\s+)?(agent|employee|partner|joint\s+venturer?)/i,
      /shall\s+not\s+.{0,30}(bind|obligate|make\s+.{0,10}representations)/is,
    ],
  }),
  presence({
    id: "COMM-018",
    name: "Anti-kickback / anti-bribery representation",
    description:
      "A referral arrangement should carry an anti-bribery / no-improper-payments representation.",
    citation: commPractice(
      "referral-anti-bribery",
      "FCPA / anti-bribery compliance baseline (15 U.S.C. §§ 78dd-1 et seq.)",
      "https://www.justice.gov/criminal-fraud/foreign-corrupt-practices-act",
    ),
    playbooks: [COMM_PLAYBOOK_REFERRAL],
    missing_title: "Anti-bribery / anti-kickback clause missing",
    missing_description: "No anti-bribery / no-improper-payments representation was found.",
    explanation:
      "Referral and finder arrangements are a classic channel for improper payments; a fee routed to a government-linked introducer or paid to secure business can trigger FCPA or commercial-bribery liability for the principal. An anti-bribery representation and a right to terminate for a violation allocate that risk.",
    recommendation:
      "Add an 'Anti-Bribery' clause requiring the Partner to comply with the FCPA and applicable anti-corruption laws, to make no improper payments, and to permit termination on a violation.",
    present_patterns: [
      /anti.?bribery|anti.?corruption/i,
      /\bfcpa\b|foreign\s+corrupt\s+practices/i,
      /improper\s+payment|\bkickback/i,
      /comply\s+with[\s\S]{0,40}(anti.?corruption|bribery)\s+laws/is,
    ],
  }),
];

export const COMMERCIAL_V4_RULES: readonly Rule[] = [
  ...MANUFACTURING_SUPPLY_RULES,
  ...DISTRIBUTION_RULES,
  ...REFERRAL_RULES,
];

export { MANUFACTURING_SUPPLY_RULES, DISTRIBUTION_RULES, REFERRAL_RULES };
