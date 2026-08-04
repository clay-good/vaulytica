/**
 * v4 Commercial-agreements ruleset — spec-v4.md §6.A additions.
 *
 * First landed sub-domain: A.10 — Manufacturing / Supply agreement
 * (COMM-001..COMM-007). A supply agreement for goods is governed by UCC
 * Article 2; the rules check the terms whose absence most often defeats
 * enforceability or leaves a material risk unallocated: the quantity
 * term (§ 2-306), delivery timing (§ 2-309), conformance to
 * specifications (§ 2-313/2-314), price or a price mechanism (§ 2-305),
 * inspection / acceptance (§ 2-513/2-606), excuse for supervening events
 * (§ 2-615), and — for a requirements / output or exclusive arrangement —
 * the § 2-306(2) best-efforts obligation.
 *
 * Rule ids are flat `COMM-NNN`.
 */

import type { Rule } from "../../../finding.js";
import { buildV4PresenceRule, type V4PresenceSpec } from "../_helpers.js";
import { COMM_PLAYBOOK_MANUFACTURING, ucc } from "./_helpers.js";

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

export const COMMERCIAL_V4_RULES: readonly Rule[] = [...MANUFACTURING_SUPPLY_RULES];

export { MANUFACTURING_SUPPLY_RULES };
