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
 *
 * Rule ids are flat `COMM-NNN`.
 */

import type { Rule } from "../../../finding.js";
import { buildV4PresenceRule, type V4PresenceSpec } from "../_helpers.js";
import {
  COMM_PLAYBOOK_MANUFACTURING,
  COMM_PLAYBOOK_DISTRIBUTION,
  ucc,
  sherman,
  lanham,
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

export const COMMERCIAL_V4_RULES: readonly Rule[] = [
  ...MANUFACTURING_SUPPLY_RULES,
  ...DISTRIBUTION_RULES,
];

export { MANUFACTURING_SUPPLY_RULES, DISTRIBUTION_RULES };
