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
 *   A.11 — Marketing services agreement (COMM-019..COMM-023): scope /
 *          deliverables, FTC endorsement-disclosure (16 C.F.R. Part 255),
 *          CAN-SPAM compliance for email, ownership of deliverables, and
 *          advertising-claims substantiation (FTC Act § 5).
 *
 * Rule ids are flat `COMM-NNN` (COMM-001..023 core; COMM-024..031 the
 * second-wave additions toward the spec's ~10-rules-per-playbook target —
 * supply title/remedies (§ 2-312 / 2-719), distribution competing-products
 * & product-liability, referral confidentiality & non-circumvention, and
 * marketing consumer-data privacy & client-approval rights).
 */

import type { Rule } from "../../../finding.js";
import { buildV4PresenceRule, type V4PresenceSpec } from "../_helpers.js";
import {
  COMM_PLAYBOOK_MANUFACTURING,
  COMM_PLAYBOOK_DISTRIBUTION,
  COMM_PLAYBOOK_REFERRAL,
  COMM_PLAYBOOK_MARKETING,
  ucc,
  sherman,
  lanham,
  respa,
  ftc,
  canSpam,
  tcpa,
  commPractice,
} from "./_helpers.js";

const CATEGORY = "commercial";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// A.10 — Manufacturing / Supply agreement. COMM-001..COMM-007 core;
// COMM-024..025, COMM-040 the second-wave additions.
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
    version: "1.1.0",
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
      // "deliver/ship … within N days" routinely names the goods between the
      // verb and "within" ("deliver THE PRODUCTS within 15 days") and spells the
      // count with a parenthetical ("within fifteen (15) days") — the original
      // rigid "deliver within <digit>" missed both.
      /(?:ship|deliver)\w*\b[^.]{0,40}?\bwithin\s+[^.]{0,12}?\(?\d{1,3}\)?\s*(?:business\s+|calendar\s+)?(?:days?|weeks?|months?|hours?)/i,
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
  presence({
    id: "COMM-024",
    name: "Warranty of title and against infringement",
    description:
      "Seller should warrant good title to the Goods, free of liens, and that the Goods do not infringe third-party rights.",
    citation: ucc("2-312", "Warranty of title and against infringement"),
    playbooks: [COMM_PLAYBOOK_MANUFACTURING],
    missing_title: "Title / non-infringement warranty missing",
    missing_description:
      "No warranty of good title, freedom from liens, or non-infringement of the Goods was found.",
    explanation:
      "UCC § 2-312 implies a warranty of good title and, from a merchant seller, a warranty that the Goods are delivered free of any rightful third-party infringement claim. Stating it expressly — and allocating an infringement indemnity — protects the buyer against a lien or a patent claim on the goods it resells.",
    recommendation:
      "Add a warranty that Seller conveys good title free of liens and that the Goods do not infringe any third-party patent, trademark, or copyright, with an infringement indemnity.",
    present_patterns: [
      /(good\s+title|title\s+to\s+the\s+(goods|products))/i,
      /free\s+(and\s+clear\s+)?of\s+(all\s+)?(liens|encumbrances)/i,
      /(not|non).{0,15}infring\w*/is,
      /infringement\s+indemn\w*/i,
    ],
  }),
  presence({
    id: "COMM-025",
    name: "Limitation of remedies / exclusive remedy",
    description:
      "A supply agreement should state the buyer's exclusive remedy for nonconforming Goods (repair, replace, or refund).",
    citation: ucc("2-719", "Contractual modification or limitation of remedy"),
    playbooks: [COMM_PLAYBOOK_MANUFACTURING],
    missing_title: "Limitation-of-remedies clause missing",
    missing_description:
      "No exclusive-remedy (repair / replace / refund) or remedies-limitation clause was found.",
    explanation:
      "UCC § 2-719 lets the parties agree to an exclusive remedy — typically repair, replacement, or refund — and to exclude consequential damages, but a remedy that 'fails of its essential purpose' reopens the full UCC remedy set. A stated exclusive remedy with a fallback avoids that failure and fixes the seller's exposure per defect.",
    recommendation:
      "Add a 'Remedies' clause making repair / replacement / refund the buyer's exclusive remedy, with a fallback if that remedy fails of its essential purpose, and the treatment of consequential damages.",
    present_patterns: [
      /(sole|exclusive)\s+remed\w+/i,
      /(repair|replace\w*|refund)[\s\S]{0,60}(sole|exclusive|only)\s+remed/is,
      /essential\s+purpose/i,
      /limitation\s+of\s+remed\w+/i,
    ],
  }),
  presence({
    id: "COMM-040",
    name: "Implied warranty of merchantability / fitness — granted or disclaimed",
    description:
      "A supply agreement should address the UCC implied warranties — either affirm them or conspicuously disclaim them.",
    citation: ucc("2-316", "Exclusion or modification of warranties"),
    playbooks: [COMM_PLAYBOOK_MANUFACTURING],
    missing_title: "Implied-warranty (merchantability / fitness) clause missing",
    missing_description:
      "The agreement does not address the UCC implied warranties of merchantability or fitness (neither granted nor disclaimed).",
    explanation:
      "UCC § 2-314 implies a warranty of merchantability in a sale by a merchant, and § 2-315 a warranty of fitness for a particular purpose, unless § 2-316 excludes them by a conspicuous disclaimer (mentioning merchantability, or an 'as is' sale). A supply agreement silent on implied warranties leaves the merchantability warranty in place by default, often contrary to the parties' intent; the agreement should either affirm or disclaim it.",
    recommendation:
      "Add a warranty clause that either affirms or conspicuously disclaims the implied warranties of merchantability and fitness for a particular purpose (e.g., an 'AS IS' / 'NO IMPLIED WARRANTIES' disclaimer or an express grant), per UCC § 2-316.",
    present_patterns: [
      /merchantab\w+/i,
      /fitness\s+for\s+(a\s+)?(particular|specific)\s+purpose/i,
      /implied\s+warrant\w+/i,
      /\bas\s+is\b|no\s+(other\s+)?warrant\w+/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// A.8 — Reseller / Distribution agreement. COMM-008..COMM-013 core;
// COMM-026..027, COMM-038..039 the second-wave additions.
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
    version: "1.1.0",
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
      // "shall purchase a minimum OF 10,000 units" is as common as "minimum
      // purchase/quantity" — the noun-only pattern missed the "minimum of
      // <number>" form.
      /minimum\s+(purchase|order|quantity|volume|amount|commitment|of\s+[\d,]+)/i,
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
  presence({
    id: "COMM-026",
    name: "Competing-products restriction (exclusive dealing)",
    description:
      "A distribution agreement should address whether the Distributor may carry competing products.",
    citation: sherman("Exclusive dealing — rule of reason (Tampa Electric)"),
    playbooks: [COMM_PLAYBOOK_DISTRIBUTION],
    // Only relevant where the agreement actually addresses exclusivity or
    // competing products — a plain non-exclusive appointment need not restrict
    // the Distributor's line card.
    applicable_if: [/(?<!non[\s-]?)exclusiv\w*|competing\s+(product|line|brand)|non.?compet\w*/i],
    missing_title: "Competing-products / exclusive-dealing clause missing",
    missing_description:
      "The appointment is exclusive but no competing-products / exclusive-dealing term was found.",
    explanation:
      "An exclusive appointment usually carries a reciprocal restriction on the Distributor carrying competing lines. Exclusive-dealing restraints are judged under the rule of reason (Tampa Electric v. Nashville Coal) by their market foreclosure; stating the restriction and its scope both allocates the obligation and frames the antitrust analysis.",
    recommendation:
      "Add a 'Competing Products' clause stating whether and to what extent the Distributor may carry competing products, and for how long after termination.",
    present_patterns: [
      /competing\s+(product|line|brand|goods)/i,
      /shall\s+not\s+(carry|sell|distribute|promote)[\s\S]{0,40}(competing|competitive)/is,
      /non.?compet\w*/i,
      /exclusiv\w*[\s\S]{0,40}(carry|handle|line)/is,
    ],
  }),
  presence({
    id: "COMM-027",
    name: "Product liability, recall, and indemnity allocation",
    description:
      "A distribution agreement should allocate product-liability, recall, and indemnity responsibility between Supplier and Distributor.",
    citation: commPractice(
      "distribution-product-liability",
      "Product-liability / recall allocation baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_DISTRIBUTION],
    missing_title: "Product-liability / recall clause missing",
    missing_description:
      "No product-liability indemnity or recall-responsibility clause was found.",
    explanation:
      "As the party in the chain of distribution, the Distributor faces strict product-liability exposure for defects it did not create. The agreement should have the Supplier indemnify the Distributor for defect and design claims and allocate the cost and conduct of any recall.",
    recommendation:
      "Add a 'Product Liability' clause with a Supplier indemnity for defect / design / warning claims and a 'Recall' clause allocating who initiates, conducts, and pays for a recall.",
    present_patterns: [
      /product\s+liability/i,
      /\brecall\b/i,
      /indemnif\w*[\s\S]{0,50}(defect|design|product|warning)/is,
      /(defect|design)[\s\S]{0,40}indemnif/is,
    ],
  }),
  presence({
    id: "COMM-038",
    name: "Inventory / stocking and forecasting",
    description:
      "A distribution agreement should require the Distributor to maintain adequate inventory and provide demand forecasts.",
    citation: commPractice(
      "distribution-inventory",
      "Distribution inventory / stocking and forecasting baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_DISTRIBUTION],
    missing_title: "Inventory / forecasting clause missing",
    missing_description: "No inventory-maintenance or demand-forecasting obligation was found.",
    explanation:
      "A stocking distributor is expected to hold enough inventory to serve the Territory and to give the Supplier rolling demand forecasts so the Supplier can plan production. Silence on stocking and forecasting invites stock-outs and over-production disputes; the agreement should set the stocking level and the forecast cadence.",
    recommendation:
      "Add an 'Inventory' clause setting a minimum stocking level and a 'Forecasting' clause requiring periodic (e.g., rolling 90-day) non-binding demand forecasts.",
    present_patterns: [
      /(maintain|carry|hold|stock)[\s\S]{0,40}(inventory|stock)/is,
      /(inventory|stocking)\s+(level|requirement|obligation)/i,
      /forecast\w*/i,
      /safety\s+stock|reorder\s+point/i,
    ],
  }),
  presence({
    id: "COMM-039",
    version: "1.1.0",
    name: "Warranty pass-through and warranty-claim administration",
    description:
      "A distribution agreement should state how the Supplier's product warranty reaches end customers and who administers warranty claims and returns.",
    citation: commPractice(
      "distribution-warranty-passthrough",
      "Distribution warranty pass-through / RMA baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_DISTRIBUTION],
    missing_title: "Warranty pass-through / claim-administration clause missing",
    missing_description:
      "No clause states whether the Supplier's warranty passes through to end customers or who handles warranty claims and returns.",
    explanation:
      "The Distributor sits between the Supplier's product warranty and the end customer. Without a pass-through and administration clause, it is unclear whether the Distributor may extend the Supplier's warranty, who honors a defective-unit claim, and how returns (RMAs) and warranty costs are settled between Supplier and Distributor.",
    recommendation:
      "Add a clause stating that the Supplier's warranty passes through to end customers, and allocating who administers warranty claims, returns / RMAs, and the associated cost.",
    present_patterns: [
      /(pass|flow)(ed|es|s)?[\s-]?(through|to)[\s\S]{0,30}(warrant|end\s+(customer|user))/is,
      /warrant\w*[\s\S]{0,40}(pass|extend|assign)\w*[\s\S]{0,30}(customer|end\s+user)/is,
      /\brma\b|return\s+material\s+authoriz\w+/i,
      /warranty\s+claim\w*[\s\S]{0,40}(administ|handl|process|honor)/is,
    ],
    // Express-denial guard: a refusal names the same pass-through the
    // obligation does. Without it the distributor carries warranty exposure to
    // its own customers with no recourse upstream.
    denied_if: [
      /\b(?:does|do|shall|will)\s+not\s+(?:pass|flow|extend|assign)\b[^.]{0,60}?\bwarrant\w*/i,
      /\bno\s+warrant\w*\s+(?:is|are|shall\s+be)\s+(?:passed|flowed|extended|assigned)/i,
      /\bwarrant\w*\b[^.]{0,40}?\b(?:is|are)\s+not\s+passed\s+through/i,
    ],
    denied_title: "Warranty pass-through expressly refused",
    denied_description:
      "The agreement states that no manufacturer warranty passes through to the distributor or its customers. The distributor then carries warranty exposure downstream with no recourse upstream — worse than a contract silent on the point, where the position is at least arguable.",
  }),
];

// ────────────────────────────────────────────────────────────────────
// A.9 — Channel partner / Referral agreement. COMM-014..COMM-018 core;
// COMM-028..029, COMM-032..034 the second-wave additions.
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
  presence({
    id: "COMM-028",
    name: "Confidentiality of leads and customer information",
    description:
      "A referral agreement should protect the confidentiality of referred leads and each party's customer information.",
    citation: commPractice(
      "referral-confidentiality",
      "Referral-agreement confidentiality baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_REFERRAL],
    missing_title: "Confidentiality clause missing",
    missing_description:
      "No confidentiality clause protecting referred leads / customer information was found.",
    explanation:
      "A referral relationship exchanges prospect and customer data — commercially sensitive information whose misuse harms both parties and can trigger privacy-law exposure. A confidentiality clause covering leads, customer lists, and each party's confidential information is a baseline protection.",
    recommendation:
      "Add a 'Confidentiality' clause covering referred leads, customer lists, pricing, and each party's confidential information, with use limited to the referral relationship.",
    present_patterns: [
      /confidential\w*/i,
      /non.?disclosure|\bnda\b/i,
      /(customer|prospect|lead)\s+(list|data|information)[\s\S]{0,40}(confidential|proprietary)/is,
      /proprietary\s+information/i,
    ],
  }),
  presence({
    id: "COMM-029",
    name: "Non-circumvention",
    description:
      "A referral agreement should bar the Partner from circumventing the Company to deal directly with a referred customer.",
    citation: commPractice(
      "referral-non-circumvention",
      "Finder / referral non-circumvention baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_REFERRAL],
    missing_title: "Non-circumvention clause missing",
    missing_description: "No non-circumvention clause was found.",
    explanation:
      "Without a non-circumvention term, a party can take an introduced relationship outside the agreement to avoid paying the fee or to compete for the account directly. A non-circumvention clause preserves the economic bargain that the introduction created.",
    recommendation:
      "Add a 'Non-Circumvention' clause barring each party, for a stated period, from bypassing the other to transact directly with a relationship introduced under the Agreement.",
    present_patterns: [
      /non.?circumvent\w*|circumvent\w*/i,
      /shall\s+not\s+(bypass|circumvent|solicit\s+directly)/i,
      /not\s+.{0,20}(deal|transact)\s+directly\s+with/is,
    ],
  }),
  presence({
    id: "COMM-032",
    name: "Effect of termination on accrued and pipeline referral fees",
    description:
      "A referral agreement should state whether fees remain payable on referrals introduced before termination that close afterward (the 'tail').",
    citation: commPractice(
      "referral-tail",
      "Referral / finder trailing-fee (tail) baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_REFERRAL],
    missing_title: "Post-termination (tail) referral-fee clause missing",
    missing_description:
      "No clause states whether referral fees survive termination for referrals introduced beforehand.",
    explanation:
      "The most common referral-fee dispute is whether the Partner is paid for a referral introduced during the term that closes after termination. Silence leaves the trailing 'tail' open to argument; a clause fixing whether and for how long post-termination closings still earn the fee resolves it in advance.",
    recommendation:
      "Add a clause stating whether referral fees are payable on referrals introduced before termination that convert afterward, and for how long the tail period runs.",
    present_patterns: [
      /(survive|surviving|continue|remain\s+payable)[\s\S]{0,60}(termination|expiration)/is,
      /(termination|expiration)[\s\S]{0,80}(referral\s+fee|fee\s+shall\s+(still\s+)?be\s+(paid|payable)|earned\s+prior)/is,
      /\btail\b[\s\S]{0,30}(period|fee)|trailing\s+(fee|commission)/i,
      /referrals?\s+(introduced|made|submitted)[\s\S]{0,60}(prior\s+to|before)[\s\S]{0,40}(terminat|expir)/is,
    ],
  }),
  presence({
    id: "COMM-033",
    name: "Restriction on Partner representations about the Company",
    description:
      "A referral agreement should bar the Partner from making representations about the Company or its products beyond Company-approved materials.",
    citation: lanham("43(a)", "false or misleading representation of fact"),
    playbooks: [COMM_PLAYBOOK_REFERRAL],
    missing_title: "Partner-representations restriction missing",
    missing_description:
      "No clause limits the Partner to Company-approved statements about the Company or its products.",
    explanation:
      "A referral partner who makes its own claims about the Company's products can create Lanham Act § 43(a) false-advertising exposure and apparent-authority risk for the Company. Limiting the Partner to approved materials and barring unauthorized warranties contains that exposure.",
    recommendation:
      "Add a clause requiring the Partner to use only Company-approved marketing materials and to make no representations, warranties, or guarantees about the Company or its products beyond those materials.",
    present_patterns: [
      /(approved|authorized)\s+(marketing\s+)?materials/i,
      /(no|not\s+make\s+any)\s+(representation|warrant|guarantee)\w*[\s\S]{0,40}(product|service|company)/is,
      /shall\s+not\s+.{0,40}(misrepresent|make\s+false)/is,
      /only\s+.{0,30}(materials|statements)\s+(provided|approved)\s+by/is,
    ],
  }),
  presence({
    id: "COMM-034",
    name: "Telemarketing / anti-spam compliance for Partner outreach",
    description:
      "Where the Partner solicits referrals by call, text, or email, the agreement should require TCPA / CAN-SPAM compliance.",
    citation: tcpa("consent for telemarketing calls and texts"),
    playbooks: [COMM_PLAYBOOK_REFERRAL],
    // Only relevant where the Partner conducts outbound solicitation — a
    // passive introduction / word-of-mouth referral does not implicate the
    // telemarketing or anti-spam statutes.
    applicable_if: [
      /cold\s+call|telemarket\w*|outbound|robocall|auto.?dial\w*|text\s+message|\bsms\b|email\s+(blast|campaign|solicit)|mass\s+email/i,
    ],
    missing_title: "Telemarketing / anti-spam compliance clause missing",
    missing_description:
      "The Partner conducts outbound solicitation but no TCPA / CAN-SPAM compliance clause was found.",
    explanation:
      "A partner who solicits referrals through calls, texts, or bulk email triggers the TCPA (47 U.S.C. § 227 — prior express consent for autodialed / prerecorded calls and texts) and CAN-SPAM (15 U.S.C. § 7704). Because the Company can face vicarious TCPA liability for a partner acting on its behalf, the agreement should require the Partner to comply and to indemnify for violations.",
    recommendation:
      "Add a clause requiring the Partner to comply with the TCPA, CAN-SPAM, and applicable state telemarketing laws (consent, do-not-call, unsubscribe) and to indemnify the Company for violations.",
    present_patterns: [
      /\btcpa\b|telephone\s+consumer\s+protection\s+act/i,
      /can.?spam/i,
      /do.?not.?call|prior\s+express\s+(written\s+)?consent/i,
      /comply\s+with[\s\S]{0,40}(telemarketing|anti.?spam|solicitation)\s+laws/is,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// A.11 — Marketing services agreement. 5 rules: COMM-019..COMM-023;
// COMM-030..031, COMM-035..037 the second-wave additions.
// ────────────────────────────────────────────────────────────────────

const MARKETING_RULES: Rule[] = [
  presence({
    id: "COMM-019",
    name: "Scope of services / deliverables / campaign",
    description:
      "A marketing services agreement must define the scope of services, deliverables, or the campaign.",
    citation: commPractice(
      "marketing-scope",
      "Marketing-services scope-of-work baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_MARKETING],
    missing_title: "Scope-of-services / deliverables clause missing",
    missing_description: "No scope of services, deliverables, or campaign definition was found.",
    explanation:
      "The scope of services, the deliverables, and the campaign definition are the operative core of a marketing engagement; their absence leaves the agency's obligations indefinite and invites scope-creep and payment disputes.",
    recommendation:
      "Add a 'Services' / 'Scope of Work' clause (or reference an SOW) describing the services, the deliverables, the channels, and the campaign timeline.",
    present_patterns: [
      /(scope\s+of\s+(services|work)|statement\s+of\s+work|\bsow\b)/i,
      /\bdeliverables?\b/i,
      /marketing\s+services|\bcampaign\b/i,
      /services\s+to\s+be\s+(provided|performed)/i,
    ],
  }),
  presence({
    id: "COMM-020",
    version: "1.0.1",
    name: "FTC endorsement / testimonial disclosure",
    description:
      "Marketing that uses endorsements, influencers, or testimonials must require the FTC-mandated material-connection disclosures.",
    citation: ftc(
      "16 C.F.R. Part 255",
      "Guides Concerning the Use of Endorsements and Testimonials",
    ),
    playbooks: [COMM_PLAYBOOK_MARKETING],
    // Only relevant where the campaign uses endorsements / influencers /
    // testimonials / reviews — a plain media-buy campaign does not implicate
    // the endorsement guides.
    applicable_if: [
      /endorse\w*|influencer|testimonial|\breview(s|er)?\b|sponsored\s+(post|content)/i,
    ],
    missing_title: "FTC endorsement-disclosure clause missing",
    missing_description:
      "The campaign uses endorsements / influencers / testimonials but no FTC material-connection disclosure requirement was found.",
    explanation:
      "The FTC Endorsement Guides (16 C.F.R. Part 255) require clear and conspicuous disclosure of any material connection between an advertiser and an endorser. An agency running influencer / testimonial content without contractually requiring #ad-style disclosures exposes the advertiser to a § 5 deception claim.",
    recommendation:
      "Add a clause requiring all endorsers / influencers to clearly and conspicuously disclose the material connection (e.g., '#ad' / 'paid partnership') and to make only substantiated claims, per 16 C.F.R. Part 255.",
    // Detect the DISCLOSURE REQUIREMENT, not the campaign type — a bare
    // "sponsored" matches "sponsored posts" (a description of the campaign),
    // so require actual disclosure language: a material-connection / clear-and-
    // conspicuous-disclosure obligation, an "#ad" / "paid partnership" label, or
    // a citation to the endorsement guides.
    present_patterns: [
      /material\s+connection/i,
      /clear\w*\s+and\s+conspicuous\w*\s+disclos\w*/i,
      /#ad\b|paid\s+partnership/i,
      /disclos\w+[\s\S]{0,40}(endorse\w*|sponsor\w*|material\s+connection|paid)/is,
      /endorsement\s+guides|16\s+c\.?f\.?r\.?\s+.{0,6}255/i,
    ],
  }),
  presence({
    id: "COMM-021",
    name: "CAN-SPAM compliance for email marketing",
    description:
      "Email-marketing services must require CAN-SPAM compliance: accurate headers, an opt-out, and a physical address.",
    citation: canSpam("Commercial-email requirements"),
    playbooks: [COMM_PLAYBOOK_MARKETING],
    // Only relevant where the campaign includes email / electronic messaging.
    applicable_if: [
      /\bemail\b|e-?mail|electronic\s+(mail|message)|newsletter|\bsms\b|text\s+message/i,
    ],
    missing_title: "CAN-SPAM compliance clause missing (email marketing)",
    missing_description:
      "The campaign includes email marketing but no CAN-SPAM compliance clause was found.",
    explanation:
      "The CAN-SPAM Act (15 U.S.C. § 7704) requires commercial email to use accurate 'from' / subject headers, to offer a working opt-out honored within 10 business days, and to include a valid physical postal address. Non-compliance carries per-email civil penalties for which the advertiser can be liable.",
    recommendation:
      "Add a CAN-SPAM clause requiring accurate header / subject lines, a functioning unsubscribe honored within 10 business days, and a valid physical postal address in every commercial email.",
    present_patterns: [
      /can.?spam/i,
      /(unsubscribe|opt.?out)\b/i,
      /physical\s+(postal\s+)?address/i,
      /accurate\s+(header|subject|from)/i,
    ],
  }),
  presence({
    id: "COMM-022",
    name: "Ownership of deliverables / work product",
    description:
      "A marketing services agreement should state who owns the creative deliverables and work product.",
    citation: commPractice(
      "marketing-ip",
      "Marketing-services work-product ownership baseline",
      "https://www.americanbar.org/groups/intellectual_property_law/",
    ),
    playbooks: [COMM_PLAYBOOK_MARKETING],
    missing_title: "Deliverables-ownership clause missing",
    missing_description:
      "No clause allocating ownership of the creative deliverables / work product was found.",
    explanation:
      "Creative work an agency produces is owned by the agency by default unless assigned; without an ownership / work-made-for-hire or assignment clause the client may not own the very campaign assets it paid for, and any embedded third-party or stock content is unlicensed.",
    recommendation:
      "Add an 'Ownership' clause assigning the deliverables (or a work-made-for-hire recital plus a backstop assignment) to the client on payment, and warranting that third-party materials are licensed for the intended use.",
    present_patterns: [
      /works?\s+(made\s+)?for\s+hire/i,
      /(assign\w*|own\w*|vest\w*)\s+.{0,50}(deliverables?|work\s+product|all\s+(right|title)|materials)/is,
      /(deliverables?|work\s+product)\s+.{0,50}(owned\s+by|shall\s+be\s+owned|belong|are\s+owned|vest)/is,
      /intellectual\s+property\s+.{0,30}(assign|owned|vest|belong)/is,
    ],
  }),
  presence({
    id: "COMM-023",
    name: "Advertising-claims substantiation",
    description:
      "A marketing services agreement should require that advertising claims be truthful and substantiated.",
    citation: ftc("15 U.S.C. § 45", "FTC Act § 5 — unfair or deceptive acts; claim substantiation"),
    playbooks: [COMM_PLAYBOOK_MARKETING],
    missing_title: "Claims-substantiation clause missing",
    missing_description:
      "No advertising-claims substantiation / truthful-advertising clause was found.",
    explanation:
      "FTC Act § 5 (15 U.S.C. § 45) bars unfair or deceptive advertising, and the FTC requires a reasonable basis for objective claims before they are made. Allocating who substantiates claims — and requiring the agency to run only substantiated, non-deceptive claims — protects the advertiser from a deception action.",
    recommendation:
      "Add a clause requiring all advertising claims to be truthful, non-deceptive, and substantiated before use, and allocating responsibility for maintaining the substantiation file.",
    present_patterns: [
      /substantiat\w*/i,
      /(truthful|not\s+(false|deceptive|misleading))\s+.{0,20}(advertis|claims?)/is,
      /reasonable\s+basis\s+for\s+.{0,20}claims?/is,
      /comply\s+with[\s\S]{0,40}(ftc|advertising)\s+(act|law|regulations)/is,
    ],
  }),
  presence({
    id: "COMM-030",
    name: "Consumer-data privacy compliance",
    description:
      "A marketing agreement under which the Agency handles consumer data should require privacy-law compliance and a data-processing term.",
    citation: commPractice(
      "marketing-data-privacy",
      "State consumer-privacy acts (CCPA/CPRA, VCDPA, CPA) and GDPR baseline",
      "https://oag.ca.gov/privacy/ccpa",
    ),
    playbooks: [COMM_PLAYBOOK_MARKETING],
    // Only relevant where the engagement actually involves consumer / personal
    // data — a pure media-placement buy with no audience data does not need a
    // data-processing term.
    applicable_if: [
      /personal\s+(data|information)|consumer\s+data|\bpii\b|email\s+list|audience\s+data|customer\s+(data|list)|retargeting/i,
    ],
    missing_title: "Consumer-data privacy / data-processing clause missing",
    missing_description:
      "The engagement handles consumer / personal data but no privacy-compliance or data-processing clause was found.",
    explanation:
      "A marketing agency that collects or processes consumer data (email lists, audience segments, retargeting pixels) acts as a service provider / processor under CCPA/CPRA, the other state privacy acts, and the GDPR. The agreement should require the Agency to process the data only on the Client's instructions and to comply with applicable privacy laws.",
    recommendation:
      "Add a data-processing / privacy clause limiting the Agency's use of personal data to the Client's instructions, requiring privacy-law compliance and appropriate safeguards, and a deletion / return obligation.",
    present_patterns: [
      /data\s+processing\s+(agreement|addendum|terms)|\bdpa\b/i,
      /(ccpa|cpra|gdpr|service\s+provider|data\s+processor)/i,
      /comply\s+with[\s\S]{0,40}(privacy|data\s+protection)\s+laws/is,
      /(process|use)\s+.{0,30}personal\s+(data|information)[\s\S]{0,40}(instruction|behalf)/is,
    ],
  }),
  presence({
    id: "COMM-031",
    name: "Client approval rights over creative and claims",
    description:
      "A marketing agreement should reserve the Client's right to review and approve creative and public claims before release.",
    citation: commPractice(
      "marketing-approval",
      "Marketing-services approval-rights baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_MARKETING],
    missing_title: "Client-approval clause missing",
    missing_description:
      "No Client review / approval right over creative or public claims was found.",
    explanation:
      "Because the Client bears the FTC and brand risk of what the Agency publishes in its name, the Client should control what goes out. An approval clause — creative and claims reviewed and approved before release — keeps the Client from being bound by an unvetted advertisement or an unsubstantiated claim.",
    recommendation:
      "Add an 'Approvals' clause requiring the Client's prior written approval of creative, media plans, and public claims before publication, with a defined review turnaround.",
    present_patterns: [
      /(client|company)['’]?s?\s+(prior\s+)?(written\s+)?approval/i,
      /(review|approve)[\s\S]{0,40}(creative|advertis\w*|claims?|materials)/is,
      /(creative|materials|claims?)[\s\S]{0,40}(subject\s+to|require)[\s\S]{0,20}approval/is,
      /right\s+to\s+(review|approve|reject)/i,
    ],
  }),
  presence({
    id: "COMM-035",
    version: "1.1.0",
    name: "Third-party rights clearance and non-infringement of deliverables",
    description:
      "A marketing agreement should require the Agency to clear all third-party rights in the deliverables and warrant non-infringement.",
    citation: lanham("43(a)", "unauthorized use of a mark / infringing advertising"),
    playbooks: [COMM_PLAYBOOK_MARKETING],
    missing_title: "Third-party rights-clearance / non-infringement clause missing",
    missing_description:
      "No clause requires the Agency to clear third-party rights (stock, music, talent) or warrant the deliverables do not infringe.",
    explanation:
      "Marketing deliverables routinely embed third-party materials — stock imagery, licensed music, fonts, and on-camera talent. Without a clearance warranty and non-infringement covenant, the Client inherits copyright, trademark, and right-of-publicity exposure for content the Agency assembled. Ownership of the deliverable (a separate clause) does not by itself clear the inputs.",
    recommendation:
      "Add a clause requiring the Agency to obtain all licenses, releases, and clearances for third-party materials (stock, music, fonts, talent / model releases) and to warrant that the deliverables do not infringe any third-party intellectual-property or publicity right.",
    present_patterns: [
      /(clear\w*|obtain\w*|secur\w*)[\s\S]{0,40}(rights|licenses?|releases?|clearances?|permissions?)/is,
      /(talent|model|appearance)\s+releases?/i,
      /(stock|licensed|third.?party)\s+(imagery|images|music|footage|content|material)/i,
      /(warrant|represent)\w*[\s\S]{0,60}(deliverables?|work\s+product|materials)[\s\S]{0,40}(not\s+infring|do\s+not\s+infring|non.?infring)/is,
    ],
    // Express-denial guard: a disclaimer names the same clearances the
    // obligation does, so an agency that refuses to clear third-party rights —
    // leaving the client to be sued over stock imagery, music, or talent it
    // paid the agency to clear — scored clean.
    denied_if: [
      /\b(?:does|do|shall|will)\s+not\s+(?:obtain|secure|clear)\b[^.]{0,60}?\b(?:rights|licen[cs]es?|releases?|clearances?|permissions?)/i,
      /\b(?:makes?|gives?|provides?)\s+no\b[^.]{0,40}?\bnon.?infringement\b/i,
      /\bno\s+(?:clearance|rights?.clearance)\s+(?:is|are|shall\s+be)\s+(?:obtained|provided|required)/i,
    ],
    denied_title: "Third-party rights clearance expressly disclaimed",
    denied_description:
      "The agreement states that the agency does NOT clear third-party rights or warrant non-infringement. The client is then exposed on the stock imagery, music, fonts, and talent it engaged the agency to clear — the exact risk this clause exists to place.",
  }),
  presence({
    id: "COMM-036",
    version: "1.1.0",
    name: "Confidentiality of Client information",
    description:
      "A marketing agreement should require the Agency to keep the Client's non-public business information confidential.",
    citation: commPractice(
      "marketing-confidentiality",
      "Marketing-services confidentiality baseline",
      "https://www.americanbar.org/groups/business_law/",
    ),
    playbooks: [COMM_PLAYBOOK_MARKETING],
    missing_title: "Confidentiality clause missing",
    missing_description: "No clause protects the Client's confidential business information.",
    explanation:
      "An agency is exposed to the Client's launch plans, budgets, customer data, and unreleased products. A confidentiality clause obliging the Agency to protect that non-public information — and to use it only for the engagement — is standard and its absence is a real gap. This is distinct from consumer-data privacy, which governs end-user personal data.",
    recommendation:
      "Add a 'Confidentiality' clause requiring the Agency to protect the Client's confidential information, use it only to perform the services, and return or destroy it on termination.",
    present_patterns: [
      /confidential\s+information/i,
      /(keep|hold|treat|maintain)[\s\S]{0,30}(in\s+)?confiden\w*/is,
      /non.?disclosure|\bnda\b/i,
      /shall\s+not\s+(disclose|use)[\s\S]{0,40}confiden\w*/is,
    ],
    // Express-denial guard. Note this rule already carries a NEGATED present
    // pattern ("shall not disclose") because that is the compliant drafting —
    // which makes the denial harder to separate, not easier. The frames below
    // therefore key on the obligation being refused ("not be required to keep
    // … confidential", "no confidentiality obligation"), never on a bare
    // "shall not", so the compliant "shall not disclose" is untouched.
    denied_if: [
      /\bnot\s+(?:be\s+)?(?:required|obligated|obliged)\s+to\s+(?:keep|hold|treat|maintain)\b[^.]{0,60}?\bconfiden\w*/i,
      /\bno\s+(?:duty|obligation)\s+of\s+confidentiality/i,
      /\bno\s+confidentiality\s+obligations?\b/i,
      /\bconfidentiality\s+obligations?\b[^.]{0,40}?\b(?:do|does|shall)\s+not\s+apply\s+to\s+(?:this\s+)?(?:agreement|the\s+parties)/i,
    ],
    denied_title: "Confidentiality obligation expressly disclaimed",
    denied_description:
      "The agreement states that the recipient is NOT required to keep the client's confidential information in confidence. The client's material is then unprotected — the opposite of the clause this rule looks for, and worse than leaving it out.",
  }),
  presence({
    id: "COMM-037",
    name: "Subcontractor and influencer responsibility (flow-down)",
    description:
      "Where the Agency engages subcontractors or influencers, the agreement should make the Agency responsible for them and flow down its obligations.",
    citation: ftc("16 C.F.R. Part 255", "advertiser responsibility for endorsers it engages"),
    playbooks: [COMM_PLAYBOOK_MARKETING],
    // Only relevant where the engagement actually uses subcontractors,
    // freelancers, or influencers — a fully in-house agency need not address
    // flow-down.
    applicable_if: [
      /subcontractor|sub.?contract\w*|freelanc\w*|influencer|third.?party\s+(vendor|provider|contractor)/i,
    ],
    missing_title: "Subcontractor / influencer flow-down clause missing",
    missing_description:
      "The Agency uses subcontractors or influencers but no clause makes it responsible for them or flows down its obligations.",
    explanation:
      "When an agency engages subcontractors or influencers, the Client needs the Agency to remain responsible for their acts and to flow down the material obligations — FTC disclosure, confidentiality, IP assignment, and compliance. Otherwise a disclosure or infringement failure by a downstream influencer leaves a gap in the chain that reaches the Client.",
    recommendation:
      "Add a clause making the Agency responsible for its subcontractors and influencers and requiring it to bind them in writing to the material obligations (FTC disclosure, confidentiality, IP assignment, compliance).",
    present_patterns: [
      /(remain\w*|be)\s+(fully\s+)?responsible\s+for[\s\S]{0,40}(subcontractor|influencer|freelanc|third.?party)/is,
      /flow(ed|s)?[\s-]?down|pass(ed|es)?[\s-]?through/i,
      /(bind|require)[\s\S]{0,40}(subcontractor|influencer)[\s\S]{0,40}(same|equivalent|written)/is,
      /(subcontractor|influencer)s?[\s\S]{0,40}(shall\s+)?(comply|be\s+bound|agree)/is,
    ],
  }),
];

export const COMMERCIAL_V4_RULES: readonly Rule[] = [
  ...MANUFACTURING_SUPPLY_RULES,
  ...DISTRIBUTION_RULES,
  ...REFERRAL_RULES,
  ...MARKETING_RULES,
];

export { MANUFACTURING_SUPPLY_RULES, DISTRIBUTION_RULES, REFERRAL_RULES, MARKETING_RULES };
