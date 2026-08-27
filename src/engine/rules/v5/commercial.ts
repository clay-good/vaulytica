/**
 * v5 sub-domain A′ — US commercial families (spec-v45.md §6.A).
 *
 * Sixteen families v4's commercial pack did not reach, all of them US
 * transactions whose governing text is the UCC as the states enacted it,
 * an FTC trade regulation rule, the FAR, or a federal transportation
 * statute. Rule ids continue the COMM namespace at 101, disjoint from the
 * v4 range (COMM-001..040).
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { cfr, expressDenial, practice, standardForm, stateLaw, ucc, usc } from "./_helpers.js";

const C = "commercial";

// ── Purchase order terms ────────────────────────────────────────────
const PURCHASE_ORDER = pack("purchase-order-terms", C, [
  {
    id: "COMM-101",
    name: "Acceptance limited to the terms of this purchase order",
    cite: ucc("2-207", "Additional terms in acceptance or confirmation"),
    pat: [
      /(expressly\s+limited\s+to\s+(the\s+)?terms|acceptance\s+is\s+(expressly\s+)?(limited|conditioned))/i,
      /(additional\s+or\s+different\s+terms|any\s+additional\s+terms\s+are\s+(hereby\s+)?rejected)/i,
      /objects?\s+to\s+any\s+(additional|different)\s+terms/i,
    ],
    why: "Under U.C.C. § 2-207 a seller's acknowledgment carrying different terms can supply them to the contract unless the buyer's offer expressly limits acceptance to its own terms. Without that limiting language the buyer's form loses the battle of the forms by default.",
    fix: 'Add: "Acceptance of this Purchase Order is expressly limited to its terms. Any additional or different terms proposed by Seller are rejected unless accepted in a signed writing."',
    sev: "critical",
  },
  {
    id: "COMM-102",
    name: "Price and payment terms",
    cite: ucc("2-305", "Open price term"),
    pat: [
      /(unit\s+price|the\s+price\s+(stated|set\s+forth))/i,
      /(payment\s+terms|net\s+\d{2}|invoice)/i,
    ],
    why: "An order with no stated price falls to a § 2-305 reasonable price at delivery — a term the parties will dispute later. Payment timing also fixes when interest, offset, and prompt-pay rights begin.",
    fix: "State the unit price, extended price, currency, and payment terms (e.g. net 30 from receipt of a conforming invoice).",
  },
  {
    id: "COMM-103",
    name: "Delivery, title, and risk of loss",
    cite: ucc("2-509", "Risk of loss in the absence of breach"),
    pat: [
      /(f\.?o\.?b\.?|delivery\s+terms|incoterms)/i,
      /(risk\s+of\s+loss|title\s+(shall\s+)?pass)/i,
    ],
    why: "§ 2-509 allocates risk of loss by shipment terms, so an order that names no F.O.B. point leaves the loss on whichever party the default rule happens to reach — usually not the one the parties assumed.",
    fix: "State the F.O.B. or Incoterms point, the delivery date or window, and when title and risk of loss pass.",
  },
  {
    id: "COMM-104",
    name: "Warranty, inspection, and rejection",
    cite: ucc("2-602", "Manner and effect of rightful rejection"),
    pat: [
      /(warrant(s|y|ies)|merchantab|fit(ness)?\s+for\s+a\s+particular\s+purpose)/i,
      /(inspect|rejection|nonconforming|revoke\s+acceptance)/i,
    ],
    why: "§ 2-602 requires rejection within a reasonable time after delivery and notice to the seller; § 2-607(3)(a) bars any remedy if the buyer fails to notify of breach after acceptance. A form that sets no inspection period leaves both deadlines to argument.",
    fix: "Add express warranties, a stated inspection period, and the buyer's rejection/revocation rights and remedies for nonconforming goods.",
  },
  {
    id: "COMM-105",
    name: "Cancellation and change rights",
    cite: ucc("2-106", "Cancellation"),
    pat: [
      /(cancel|terminate)\s+(this\s+)?(purchase\s+)?order/i,
      /(change\s+order|modif(y|ication)\s+of\s+(the\s+)?order)/i,
    ],
    why: "Buyer forms customarily reserve cancellation for convenience with a stated settlement of costs incurred. Without it, cancellation is a breach and the seller's remedy is § 2-708 lost profit.",
    fix: "Add a cancellation-for-convenience right with the cost settlement formula, and a change-order procedure with price and schedule adjustment.",
  },
]);

// ── Master purchase agreement ───────────────────────────────────────
const MASTER_PURCHASE = pack("master-purchase-agreement", C, [
  {
    id: "COMM-106",
    name: "Quantity or requirements commitment",
    cite: ucc("2-306", "Output, requirements and exclusive dealings"),
    pat: [
      /(minimum\s+(purchase\s+)?(commitment|quantity|volume)|requirements\s+of\s+the\s+buyer)/i,
      /(estimated\s+annual\s+(volume|quantity)|forecast)/i,
      /(no\s+minimum\s+(purchase\s+)?commitment|purchases\s+are\s+non-?binding)/i,
    ],
    why: "A master agreement with no quantity term risks failing the § 2-201 statute of frauds, which is enforceable only up to the quantity shown. § 2-306 supplies a good-faith requirements measure only when the agreement is written as a requirements contract.",
    fix: "State the quantity: a firm minimum, a requirements or output commitment, or an express statement that orders are non-binding forecasts.",
    sev: "critical",
  },
  {
    id: "COMM-107",
    name: "Price, price adjustment, and payment",
    cite: ucc("2-305", "Open price term"),
    pat: [
      /(price\s+(list|schedule)|pricing\s+set\s+forth)/i,
      /(price\s+adjustment|indexed|most\s+favored)/i,
    ],
    why: "Multi-year goods agreements need an adjustment mechanism; without one the price is either frozen against input inflation or open under § 2-305 and set by a good-faith standard neither side can predict.",
    fix: "Attach a price schedule and state the adjustment mechanism (index, cost pass-through, or annual negotiation with a cap) and payment terms.",
  },
  {
    id: "COMM-108",
    name: "F.O.B. point, title, and risk of loss",
    cite: ucc("2-509", "Risk of loss in the absence of breach"),
    pat: [
      /(f\.?o\.?b\.?|incoterms|delivery\s+point)/i,
      /(risk\s+of\s+loss|title\s+(shall\s+)?pass)/i,
    ],
    why: "The F.O.B. point drives risk of loss, insurable interest, freight responsibility, and often revenue recognition. § 2-509 fills the gap unpredictably when the agreement is silent.",
    fix: "State the F.O.B. or Incoterms 2020 point and when title and risk of loss pass to the buyer.",
  },
  {
    id: "COMM-109",
    name: "Express warranty and disclaimer form",
    cite: ucc("2-316", "Exclusion or modification of warranties"),
    pat: [
      /(warrants?\s+that\s+the\s+goods|express\s+warrant)/i,
      /(merchantab|fitness\s+for\s+a\s+particular\s+purpose)/i,
    ],
    why: "§ 2-316(2) makes a merchantability disclaimer effective only if it mentions merchantability and, in writing, is conspicuous; a fitness disclaimer must be in writing and conspicuous. A disclaimer that misses the form is ineffective and the implied warranties survive.",
    fix: "State the express warranty, its period, and — if implied warranties are disclaimed — use conspicuous § 2-316 form language naming merchantability.",
  },
  {
    id: "COMM-110",
    name: "Inspection, rejection, and revocation of acceptance",
    cite: ucc("2-608", "Revocation of acceptance in whole or in part"),
    pat: [
      /(inspect(ion)?\s+period|right\s+to\s+inspect)/i,
      /(reject|revoke\s+acceptance|nonconform)/i,
    ],
    why: "§ 2-607(3)(a) bars the buyer from any remedy for a defect it fails to notify within a reasonable time after acceptance. Setting the period by contract turns a factual fight into a date.",
    fix: "Set an inspection period, the manner of rejection notice, and the buyer's revocation rights, cure obligations, and remedies.",
  },
  {
    id: "COMM-111",
    name: "Excuse and force majeure",
    cite: ucc("2-615", "Excuse by failure of presupposed conditions"),
    pat: [
      /force\s+majeure/i,
      /(commercial(ly)?\s+impracticab|excuse(d)?\s+(from\s+)?performance)/i,
    ],
    why: "§ 2-615 excuses a seller only for impracticability caused by an unforeseen contingency, and requires allocation among customers and prompt notice. Buyers routinely need a longer list, a notice deadline, and a termination right the statute does not supply.",
    fix: "Add a force majeure clause with the covered events, a notice deadline, an allocation rule, a mitigation duty, and a termination right after a stated outage.",
  },
]);

// ── Equipment lease (UCC 2A) ────────────────────────────────────────
const EQUIPMENT_LEASE = pack("equipment-lease", C, [
  {
    id: "COMM-112",
    name: "Finance-lease designation and hell-or-high-water covenant",
    cite: ucc("2A-407", "Irrevocable promises: finance leases"),
    pat: [
      /(finance\s+lease|hell\s+or\s+high\s+water)/i,
      /(lessee'?s?\s+obligations?\s+(are|shall\s+be)\s+absolute\s+and\s+unconditional)/i,
    ],
    why: "§ 2A-407 makes the lessee's promises irrevocable and independent only in a finance lease of goods that is not a consumer lease. Without the designation and the supporting language, the lessee keeps setoff and abatement rights the lessor's pricing assumed away.",
    fix: 'Designate the transaction a finance lease under § 2A-103(1)(g) and add: "Lessee\'s obligation to pay Rent is absolute and unconditional and is not subject to abatement, setoff, or counterclaim."',
    sev: "critical",
  },
  {
    id: "COMM-113",
    name: "Rent, term, and end-of-term options",
    cite: ucc("2A-103", "Definitions — lease"),
    pat: [
      /(rent|lease\s+payments?)/i,
      /(end\s+of\s+(the\s+)?term|purchase\s+option|renewal\s+option|fair\s+market\s+value)/i,
    ],
    why: "The end-of-term structure — $1 buyout, FMV purchase, renewal, or return — decides whether the transaction is a true lease or a disguised security interest under § 1-203, which changes the tax, accounting, and priority analysis entirely.",
    fix: "State rent, term, and the end-of-term options (return / renew / purchase at FMV or a stated price), and confirm the intended characterization.",
  },
  {
    id: "COMM-114",
    name: "Maintenance, insurance, and casualty risk",
    cite: ucc("2A-219", "Risk of loss"),
    pat: [
      /(maintain|maintenance|service\s+the\s+equipment)/i,
      /(insur(e|ance)|casualty|loss\s+or\s+damage)/i,
    ],
    why: "§ 2A-219(1) leaves risk of loss with the lessor except in a finance lease, where it passes to the lessee. Insurance limits, loss-payee status, and stipulated-loss values need to be stated or the lessor is unsecured after a total loss.",
    fix: "Require the lessee to maintain the equipment, carry property and liability insurance naming the lessor as loss payee and additional insured, and pay the stipulated loss value on a casualty.",
  },
  {
    id: "COMM-115",
    name: "Warranty pass-through or disclaimer",
    cite: ucc("2A-209", "Lessee under finance lease as beneficiary of supply contract"),
    pat: [/(supply\s+contract|manufacturer'?s?\s+warrant)/i, /(disclaim|as\s+is|no\s+warrant)/i],
    why: "In a finance lease the lessor gives no warranties, and § 2A-209 extends the supplier's warranties to the lessee. If the lease disclaims without passing the supply-contract warranties through, the lessee has paid for equipment it cannot make a warranty claim on.",
    fix: "Disclaim lessor warranties in conspicuous form and expressly assign or pass through the supplier's warranties under § 2A-209.",
  },
  {
    id: "COMM-116",
    name: "Default and remedies",
    cite: ucc("2A-523", "Lessor's remedies"),
    pat: [
      /(event\s+of\s+default|default\s+by\s+lessee)/i,
      /(remedies|accelerat|repossess|dispose\s+of\s+the\s+equipment)/i,
    ],
    why: "§§ 2A-523 to 2A-532 supply lessor remedies, but the measure of damages and any liquidated formula must satisfy § 2A-504's reasonableness test or it is unenforceable as a penalty.",
    fix: "Enumerate events of default with cure periods, and state the remedies including acceleration, repossession, and a § 2A-504-compliant liquidated damages formula.",
  },
  {
    id: "COMM-117",
    name: "Return condition and location",
    cite: practice("equipment-return", "return-condition standards in equipment leasing"),
    pat: [
      /(return\s+(the\s+)?equipment|surrender\s+the\s+equipment)/i,
      /(condition|ordinary\s+wear\s+and\s+tear|de-?install)/i,
    ],
    why: "Return conditions are the most-litigated term in equipment leasing: without a stated standard, location, and packing/freight allocation, the lessor bills restoration costs the lessee never priced.",
    fix: "State the return location, the required condition (with an ordinary wear-and-tear carve-out), de-installation and freight responsibility, and any certification requirement.",
  },
]);

// ── Freight / transportation ────────────────────────────────────────
const FREIGHT = pack("freight-transportation-agreement", C, [
  {
    id: "COMM-118",
    name: "Carmack cargo-liability standard and limitation",
    cite: usc(
      "49",
      "14706",
      "Liability of carriers under receipts and bills of lading (Carmack Amendment)",
    ),
    pat: [
      /(carmack|49\s+u\.?s\.?c\.?\s*§?\s*14706)/i,
      /(cargo\s+liability|liability\s+for\s+loss\s+or\s+damage\s+to\s+the\s+(cargo|freight|shipment))/i,
    ],
    why: "The Carmack Amendment preempts state-law cargo claims against interstate motor carriers and makes the carrier liable for actual loss. A limitation of liability binds the shipper only if the carrier gave a fair opportunity to choose between levels of liability and rates.",
    fix: "State the cargo-liability standard, any released-value limitation with the alternative full-value rate offered, and the excepted causes.",
    sev: "critical",
  },
  {
    id: "COMM-119",
    name: "Bill of lading terms and order of precedence",
    cite: usc("49", "80103", "Negotiable and nonnegotiable bills of lading"),
    pat: [
      /bill\s+of\s+lading/i,
      /(shall\s+(control|govern)|order\s+of\s+precedence|conflict\s+between)/i,
    ],
    why: "Every shipment generates a bill of lading whose preprinted terms will otherwise compete with the master agreement. Which document governs must be stated or each claim starts with a document fight.",
    fix: "State that the master agreement controls over inconsistent bill of lading terms except as to the description of goods and delivery instructions.",
  },
  {
    id: "COMM-120",
    name: "Insurance and certificates",
    cite: cfr("49", "387", "Minimum levels of financial responsibility for motor carriers"),
    pat: [
      /(insur(e|ance)|certificate\s+of\s+insurance)/i,
      /(auto\s+liability|cargo\s+(insurance|coverage)|general\s+liability)/i,
    ],
    why: "49 C.F.R. Part 387 sets minimum public-liability limits for for-hire motor carriers, but cargo coverage is a contract matter. A shipper that does not require and verify coverage is unsecured against an uninsured carrier.",
    fix: "Require auto liability, general liability, cargo, and workers' compensation at stated limits, with certificates, additional-insured status, and notice of cancellation.",
  },
  {
    id: "COMM-121",
    name: "Freight charges, accessorials, and payment",
    cite: usc("49", "13706", "Liability for payment of rates"),
    pat: [
      /(freight\s+charges|rates\s+set\s+forth|rate\s+schedule)/i,
      /(accessorial|detention|demurrage|fuel\s+surcharge)/i,
    ],
    why: "§ 13706 makes a shipper liable for freight charges to a carrier unless the bill of lading is marked non-recourse and the charges are prepaid. Accessorial exposure — detention, layover, redelivery — is where the disputes actually are.",
    fix: "Attach the rate schedule, enumerate accessorial charges with the conditions that trigger them, and state payment terms and the non-recourse election.",
  },
  {
    id: "COMM-122",
    name: "Indemnity and independent-contractor status",
    cite: practice("carrier-status", "independent-contractor status in motor-carrier agreements"),
    pat: [/independent\s+contractor/i, /indemnif/i],
    why: "Shippers are increasingly named in negligent-selection and vicarious-liability suits after catastrophic accidents. The independent-contractor recital and a broad carrier indemnity are the shipper's principal contractual defenses.",
    fix: "State that the carrier is an independent contractor with exclusive control over drivers and equipment, and require indemnity for bodily injury and property damage arising from the carrier's operations.",
  },
  {
    id: "COMM-123",
    name: "Claims filing and suit deadlines",
    cite: cfr(
      "49",
      "370",
      "Principles and practices for the investigation and voluntary disposition of loss and damage claims",
    ),
    pat: [
      /(claim\s+(must|shall)\s+be\s+filed|filing\s+of\s+claims)/i,
      /(nine\s+months|9\s+months|two\s+years|limitation\s+period)/i,
    ],
    why: "Carmack permits a minimum nine-month claim-filing period and a two-year suit limitation. Agreements routinely shorten these below the statutory floor, which makes the shortened term unenforceable and leaves neither party sure of the real deadline.",
    fix: "State the claim-filing period (no less than nine months from delivery) and the suit limitation (no less than two years from claim disallowance), and the required claim contents.",
  },
]);

// ── Warehousing / 3PL ───────────────────────────────────────────────
const WAREHOUSING = pack("warehousing-3pl-agreement", C, [
  {
    id: "COMM-124",
    name: "Warehouse receipt and documents of title",
    cite: ucc("7-202", "Form of warehouse receipt"),
    pat: [
      /warehouse\s+receipt/i,
      /(documents?\s+of\s+title|non-?negotiable|negotiable\s+receipt)/i,
    ],
    why: "§ 7-202 fixes the required contents of a warehouse receipt and § 7-204 the warehouse's liability. Whether receipts are negotiable determines whether the goods can be financed or transferred while stored.",
    fix: "State whether warehouse receipts will be issued, whether they are negotiable, and the required contents under § 7-202.",
  },
  {
    id: "COMM-125",
    name: "Standard of care and liability limitation",
    cite: ucc("7-204", "Duty of care; contractual limitation of warehouse's liability"),
    pat: [
      /(reasonable\s+care|standard\s+of\s+care|due\s+care)/i,
      /(limitation\s+of\s+liability|liability\s+(is\s+)?limited|per\s+(pound|package|unit))/i,
    ],
    why: "§ 7-204(b) allows a warehouse to limit liability per item or unit of weight, but only if the bailor is given the option of a higher limit for an increased rate. A limitation without that option is vulnerable.",
    fix: "State the reasonable-care standard, any per-unit liability limit, and the bailor's option to declare a higher value at a stated increased rate.",
  },
  {
    id: "COMM-126",
    name: "Warehouse lien and enforcement",
    cite: ucc("7-209", "Lien of warehouse"),
    pat: [
      /warehouse\s+lien|lien\s+(on|against)\s+the\s+(stored\s+)?goods/i,
      /(enforce\s+the\s+lien|sale\s+of\s+the\s+goods|§?\s*7-210)/i,
    ],
    why: "§ 7-209 gives the warehouse a lien for storage charges, and § 7-210 sets the enforcement procedure. The lien's scope — this lot only, or all goods of the depositor — must be stated in the receipt or agreement.",
    fix: "State the lien's scope, the charges it secures, and that enforcement follows the § 7-210 commercially reasonable sale procedure.",
  },
  {
    id: "COMM-127",
    name: "Inventory accuracy and shrinkage allowance",
    cite: practice("3pl-shrinkage", "inventory accuracy standards in third-party logistics"),
    pat: [
      /(inventory\s+accuracy|cycle\s+count|physical\s+inventory)/i,
      /(shrink(age)?|loss\s+allowance|tolerance)/i,
    ],
    why: "3PL disputes are overwhelmingly about counts. Without an accuracy standard, a shrink allowance, and a reconciliation cadence, every variance becomes an unresolvable claim.",
    fix: "Set an inventory accuracy percentage, a shrinkage allowance, cycle-count and annual physical-inventory cadence, and the chargeback formula for variances beyond tolerance.",
  },
  {
    id: "COMM-128",
    name: "Insurance and risk of loss",
    cite: practice("3pl-insurance", "insurance allocation in warehousing agreements"),
    pat: [/insur(e|ance)/i, /(risk\s+of\s+loss|warehouse\s+legal\s+liability|all\s+risk)/i],
    why: "A warehouse's legal-liability policy covers only what it is legally liable for — which the liability limitation has just reduced. The bailor usually must carry its own all-risk stock coverage or absorb the gap.",
    fix: "Require warehouse legal liability coverage at stated limits, state who carries all-risk coverage on the stored goods, and add waivers of subrogation.",
  },
]);

// ── Staffing ────────────────────────────────────────────────────────
const STAFFING = pack("staffing-services-agreement", C, [
  {
    id: "COMM-129",
    name: "Employer-of-record allocation",
    cite: practice("co-employment", "co-employment allocation in staffing agreements"),
    pat: [
      /employer\s+of\s+record/i,
      /(sole\s+employer|the\s+agency\s+is\s+the\s+employer|co-?employment)/i,
    ],
    why: "Joint-employer findings under the FLSA, Title VII, and the NLRA follow control, not labels — but the allocation of who hires, pays, disciplines, and terminates is the first thing an agency or plaintiff reads.",
    fix: "State that the agency is the employer of record with responsibility for hiring, payroll, discipline, and termination, and describe the client's limited direction of day-to-day work.",
    sev: "critical",
  },
  {
    id: "COMM-130",
    name: "Wage, hour, and benefits responsibility",
    cite: usc("29", "206", "Fair Labor Standards Act — minimum wage"),
    pat: [/(wages|payroll|overtime)/i, /(benefits|workers'?\s+compensation|withhold)/i],
    why: "Under the FLSA a joint employer is jointly and severally liable for unpaid wages regardless of which entity ran payroll. The client needs the agency's express undertaking and an indemnity behind it.",
    fix: "Assign responsibility for wages, overtime, payroll taxes, and benefits to the agency, with an indemnity for wage-and-hour claims arising from the agency's payroll practices.",
  },
  {
    id: "COMM-131",
    name: "Conversion or buyout fee",
    cite: practice("staffing-conversion", "conversion fees in contingent-labor agreements"),
    pat: [
      /(conversion\s+fee|buy-?out\s+fee|direct\s+hire\s+fee)/i,
      /(hire\s+(the\s+)?assigned\s+(employee|worker)|convert\s+to\s+a\s+direct\s+hire)/i,
    ],
    why: "Conversion fees are the agency's principal economics on a long assignment. An unbounded fee — no decay by hours worked, no expiry after the assignment ends — is a restraint the client did not price.",
    fix: "State the conversion fee, how it decays with hours worked, and how long after the assignment ends it survives.",
  },
  {
    id: "COMM-132",
    name: "Workers' compensation and insurance",
    cite: stateLaw(
      "workers-compensation",
      "exclusive-remedy and coverage requirements for staffing arrangements",
      "https://www.law.cornell.edu/wex/workers_compensation",
    ),
    pat: [
      /workers'?\s+compensation/i,
      /(certificate\s+of\s+insurance|general\s+liability|alternate\s+employer\s+endorsement)/i,
    ],
    why: "The workers' compensation exclusive remedy protects the client only if the client qualifies as a special or statutory employer in that state. An alternate employer endorsement is the usual contractual bridge.",
    fix: "Require statutory workers' compensation, an alternate employer endorsement naming the client, employer's liability, and general liability, evidenced by certificates.",
  },
  {
    id: "COMM-133",
    name: "Background check and screening consents",
    cite: usc(
      "15",
      "1681b",
      "Fair Credit Reporting Act — permissible purposes of consumer reports",
    ),
    pat: [
      /background\s+(check|screen)/i,
      /(drug\s+(test|screen)|consent|authorization|fair\s+credit\s+reporting)/i,
    ],
    why: "When the agency runs consumer reports it is the FCRA user and owes the § 604(b) stand-alone disclosure and the adverse-action sequence. A client that specifies the screens without allocating those duties inherits the risk.",
    fix: "State the required screens, who conducts them, and that the conducting party will satisfy FCRA disclosure, authorization, and adverse-action obligations.",
  },
]);

// ── Franchise agreement ─────────────────────────────────────────────
const FRANCHISE = pack("franchise-agreement", C, [
  {
    id: "COMM-134",
    name: "Grant, territory, and exclusivity",
    cite: cfr("16", "436.5(l)", "FTC Franchise Rule — Item 12, territory"),
    pat: [
      /(grants?\s+(to\s+)?franchisee|the\s+franchise\s+is\s+granted)/i,
      /(territory|protected\s+area|exclusive\s+area|no\s+exclusive\s+territory)/i,
    ],
    why: "Item 12 of the FDD must describe the territory and whether it is exclusive. The agreement has to match: encroachment claims turn on whether the franchisor reserved alternative channels the disclosure did not describe.",
    fix: "Define the territory, state whether it is exclusive, and enumerate the franchisor's reserved rights (company outlets, alternative channels, e-commerce, non-traditional venues).",
    sev: "critical",
  },
  {
    id: "COMM-135",
    name: "Initial fee, royalty, and advertising fund",
    cite: cfr("16", "436.5(e)", "FTC Franchise Rule — Item 5/6, fees"),
    pat: [
      /(initial\s+franchise\s+fee|franchise\s+fee)/i,
      /(royalt|advertising\s+fund|marketing\s+contribution|brand\s+fund)/i,
    ],
    why: "Fees must match FDD Items 5 and 6, including how advertising-fund contributions may be spent and whether the franchisor must account for them.",
    fix: "State the initial fee, the royalty rate and base, the advertising contribution, and the franchisor's accounting obligations for the fund.",
  },
  {
    id: "COMM-136",
    name: "System standards and manual compliance",
    cite: cfr(
      "16",
      "436.5(o)",
      "FTC Franchise Rule — Item 11, franchisor assistance and operating manual",
    ),
    pat: [
      /(operations?\s+manual|system\s+standards|brand\s+standards)/i,
      /(comply\s+with|as\s+the\s+franchisor\s+may\s+(specify|prescribe))/i,
    ],
    why: "The manual is incorporated by reference and unilaterally amendable — which is the point of a system, and also the franchisee's largest uncapped cost exposure (remodels, technology mandates, required suppliers).",
    fix: "Incorporate the manual, state the amendment right, and bound the franchisee's mandatory capital expenditure (remodel frequency, notice, and cost caps).",
  },
  {
    id: "COMM-137",
    name: "Term, renewal, and transfer",
    cite: cfr(
      "16",
      "436.5(q)",
      "FTC Franchise Rule — Item 17, renewal, termination, transfer and dispute resolution",
    ),
    pat: [
      /(initial\s+term|term\s+of\s+this\s+agreement)/i,
      /(renew(al)?|transfer\s+of\s+the\s+franchise|assignment\s+by\s+franchisee)/i,
    ],
    why: "Item 17 requires the FDD to summarize renewal and transfer conditions. Renewal on the then-current form — a materially different contract — is standard and must be disclosed rather than discovered.",
    fix: "State the term, renewal conditions (notice, general release, then-current form, renewal fee, remodel), and the transfer conditions and franchisor consent standard.",
  },
  {
    id: "COMM-138",
    name: "Termination and post-term covenants",
    cite: stateLaw(
      "franchise-relationship",
      "good cause, notice, and cure requirements for franchise termination",
      "https://www.law.cornell.edu/wex/franchise",
    ),
    pat: [
      /(terminat(e|ion)\s+(of\s+)?this\s+agreement|default\s+by\s+franchisee)/i,
      /(post-?term|de-?identif|covenant\s+not\s+to\s+compete)/i,
    ],
    why: "About twenty states impose good-cause, notice, and cure requirements on franchise termination and non-renewal that override the contract. Post-term covenants are separately limited by state non-compete law.",
    fix: "Enumerate termination grounds with notice and cure periods, and state the de-identification obligations and the scope and duration of post-term covenants.",
  },
  {
    id: "COMM-139",
    name: "State franchise-relationship law overrides",
    cite: stateLaw(
      "franchise-registration",
      "registration and relationship statutes in the franchise registration states",
      "https://www.law.cornell.edu/wex/franchise",
    ),
    pat: [
      /(state\s+(specific\s+)?(addend|amendment|rider))/i,
      /(to\s+the\s+extent\s+required\s+by\s+(applicable\s+)?state\s+law|state\s+franchise\s+(law|act))/i,
    ],
    why: "Registration and relationship states (CA, IL, MD, MN, NY, WA and others) require state addenda that override choice of law, jury waivers, releases, and limitation periods. Their absence is the most common defect in a national form.",
    fix: "Attach the state-specific addenda for every registration or relationship state where the franchise will be sold, and add a savings clause deferring to those states' statutes.",
  },
]);

// ── FDD ─────────────────────────────────────────────────────────────
const FDD = pack("franchise-disclosure-document", C, [
  {
    id: "COMM-140",
    name: "Items 1-5 — franchisor, litigation, bankruptcy, and fees",
    cite: cfr("16", "436.5(a)", "FTC Franchise Rule — Items 1 through 5"),
    pat: [/item\s+1/i, /(litigation|bankruptcy|initial\s+fees?)/i],
    why: "§ 436.5 prescribes 23 items in fixed order. Items 3 and 4 (litigation and bankruptcy) are the disclosures rescission claims are built on, and omissions are the classic Franchise Rule violation.",
    fix: "Include Items 1-5 in the prescribed order: the franchisor and its predecessors, business experience, litigation, bankruptcy, and initial fees.",
    sev: "critical",
  },
  {
    id: "COMM-141",
    name: "Item 7 — estimated initial investment",
    cite: cfr("16", "436.5(g)", "FTC Franchise Rule — Item 7, estimated initial investment"),
    pat: [
      /item\s+7/i,
      /(estimated\s+initial\s+investment|total\s+estimated\s+initial\s+investment)/i,
    ],
    why: "Item 7 must show a low-to-high range for every category of pre-opening expense plus additional funds for an initial phase. Understated ranges are the most frequently litigated FDD disclosure.",
    fix: "Include the Item 7 table with low/high amounts, method of payment, when due, and to whom paid, for every required category.",
  },
  {
    id: "COMM-142",
    name: "Item 19 — financial performance representation",
    cite: cfr(
      "16",
      "436.5(s)",
      "FTC Franchise Rule — Item 19, financial performance representations",
    ),
    pat: [
      /item\s+19/i,
      /(financial\s+performance\s+representation|we\s+do\s+not\s+make\s+any\s+(representations?|financial\s+performance))/i,
    ],
    why: "A franchisor may make earnings claims only in Item 19, with a reasonable basis and written substantiation available. Making them outside Item 19 — or omitting the negative disclosure — is a per se violation.",
    fix: "Include Item 19 either with a compliant FPR (basis, assumptions, substantiation offer) or with the prescribed negative disclosure that no financial performance representation is made.",
    sev: "critical",
  },
  {
    id: "COMM-143",
    name: "Item 20 — outlet and franchisee information tables",
    cite: cfr("16", "436.5(t)", "FTC Franchise Rule — Item 20, outlets and franchisee information"),
    pat: [
      /item\s+20/i,
      /(systemwide\s+outlet\s+summary|outlets?\s+and\s+franchisee\s+information|transfers?\s+by\s+state)/i,
    ],
    why: "Item 20's five tables — including three years of terminations, non-renewals, and reacquisitions by state — are where a prospective franchisee sees turnover the narrative omits. Current and former franchisee contact lists are required.",
    fix: "Include all five Item 20 tables plus the current and former franchisee contact lists, and any confidentiality-clause disclosure.",
  },
  {
    id: "COMM-144",
    name: "Item 21 — audited financial statements",
    cite: cfr("16", "436.5(u)", "FTC Franchise Rule — Item 21, financial statements"),
    pat: [
      /item\s+21/i,
      /(audited\s+financial\s+statements|balance\s+sheet|statements?\s+of\s+operations)/i,
    ],
    why: "Three years of audited financials are required (with phase-in relief for start-up franchisors). Unaudited statements outside the phase-in are a disqualifying defect in every registration state.",
    fix: "Attach audited financial statements for the last three fiscal years, or the phase-in schedule with the required unaudited opening balance sheet.",
  },
  {
    id: "COMM-145",
    name: "Receipt page and 14-day disclosure timing",
    cite: cfr("16", "436.2", "FTC Franchise Rule — obligation to furnish documents"),
    pat: [/receipt/i, /(14\s+calendar\s+days|fourteen\s+\(?14\)?\s+days|at\s+least\s+14\s+days)/i],
    why: "§ 436.2(a) requires delivery at least 14 calendar days before signing or payment. The dual receipt pages are the franchisor's only proof of timing, and their absence defeats the defense.",
    fix: "Include both copies of the Item 23 receipt with the issuance date, the franchise seller's identity, and the 14-day statement.",
    sev: "critical",
  },
]);

// ── Joint venture ───────────────────────────────────────────────────
const JOINT_VENTURE = pack("joint-venture-agreement", C, [
  {
    id: "COMM-146",
    name: "Scope and exclusivity of the venture",
    cite: practice("jv-scope", "scope and exclusivity definition in joint ventures"),
    pat: [
      /(purpose\s+of\s+the\s+(venture|jv)|scope\s+of\s+the\s+venture|business\s+of\s+the\s+venture)/i,
      /(exclusiv|shall\s+not\s+(compete|engage)|outside\s+the\s+scope)/i,
    ],
    why: "A venture with no scope boundary makes every adjacent opportunity a corporate-opportunity dispute between the members, and an unbounded exclusivity is an antitrust exposure between competitors.",
    fix: "Define the venture's business, its geographic and field boundaries, what each member may do outside it, and any corporate-opportunity waiver.",
    sev: "critical",
  },
  {
    id: "COMM-147",
    name: "Capital contributions and funding calls",
    cite: practice("jv-capital", "capital contribution and dilution mechanics in joint ventures"),
    pat: [
      /(capital\s+contribution|initial\s+contribution)/i,
      /(additional\s+(capital|funding)|capital\s+call|dilut)/i,
    ],
    why: "Deadlocked ventures usually fail at the second funding round. The consequence of a member declining a call — dilution, member loan, or default — is the term that decides who controls the venture in year three.",
    fix: "State initial contributions, the procedure for additional calls, and the consequence of a failure to fund (dilution formula, member loan terms, or forced transfer).",
  },
  {
    id: "COMM-148",
    name: "Governance, reserved matters, and deadlock",
    cite: practice("jv-deadlock", "deadlock resolution in 50/50 joint ventures"),
    pat: [
      /(board|management\s+committee|steering\s+committee)/i,
      /(reserved\s+matters|supermajority|deadlock|unanimous\s+(consent|approval))/i,
    ],
    why: "A 50/50 venture with reserved matters and no deadlock breaker is a dissolution petition waiting to be filed. The escalation-then-exit ladder is the whole governance design.",
    fix: "State board composition, the list of reserved matters, and a deadlock ladder: executive escalation, then mediation, then a buy-sell or dissolution trigger.",
  },
  {
    id: "COMM-149",
    name: "Profit and loss allocation",
    cite: practice("jv-allocation", "profit and loss allocation in joint ventures"),
    pat: [
      /(profits?\s+and\s+losses|allocation\s+of\s+(profits|income))/i,
      /(distribut|tax\s+distribution)/i,
    ],
    why: "Allocation and distribution are different decisions; a member allocated taxable income with no distribution to pay the tax on it has a real grievance from year one.",
    fix: "State the profit and loss sharing ratios, the distribution policy, and a mandatory tax distribution sufficient to cover allocated income.",
  },
  {
    id: "COMM-150",
    name: "Transfer restrictions and exit or buy-sell",
    cite: practice("jv-exit", "transfer restrictions and buy-sell mechanics in joint ventures"),
    pat: [
      /(transfer\s+(of\s+)?(interests?|units?|shares?)|right\s+of\s+first\s+refusal)/i,
      /(buy-?sell|put\s+(option|right)|call\s+(option|right)|exit)/i,
    ],
    why: "Without a priced exit, a minority member in a private venture holds an illiquid interest with no way out short of litigation. A buy-sell converts the dispute into a transaction.",
    fix: "Add transfer restrictions with a ROFR, and an exit mechanism — Texas shootout, Dutch auction, or appraised put/call — with a stated valuation method and payment terms.",
  },
  {
    id: "COMM-151",
    name: "IP ownership and background IP",
    cite: practice("jv-ip", "background and foreground IP allocation in joint ventures"),
    pat: [
      /(background\s+(ip|intellectual\s+property)|pre-?existing\s+intellectual\s+property)/i,
      /(developed\s+by\s+the\s+venture|foreground|jointly\s+developed|ownership\s+of\s+intellectual\s+property)/i,
    ],
    why: "Each member arrives with IP the venture needs and leaves wanting rights to what the venture built. Silence produces joint ownership, whose default rules (each owner may license without accounting) rarely match the deal.",
    fix: "Identify background IP and the license granted to the venture, state who owns venture-developed IP, and set license-back rights on dissolution.",
  },
]);

// ── Teaming agreement ───────────────────────────────────────────────
const TEAMING = pack("teaming-agreement", C, [
  {
    id: "COMM-152",
    name: "Identified program or solicitation",
    cite: cfr("48", "9.601", "FAR — contractor team arrangements"),
    pat: [
      /(solicitation\s+(no|number)|rfp\s+(no|number)|the\s+program)/i,
      /(agency|contracting\s+activity|opportunity)/i,
    ],
    why: "FAR 9.6 recognizes team arrangements but says nothing about enforceability. A teaming agreement that does not identify the specific procurement is an agreement to agree about nothing in particular.",
    fix: "Identify the agency, solicitation number, program name, and anticipated award vehicle the team is pursuing.",
  },
  {
    id: "COMM-153",
    name: "Workshare and scope commitment",
    cite: cfr("48", "9.603", "FAR — policy on contractor team arrangements"),
    pat: [
      /(workshare|work\s+share|scope\s+of\s+work\s+to\s+be\s+performed\s+by)/i,
      /(percent(age)?|statement\s+of\s+work|the\s+subcontract\s+scope)/i,
    ],
    why: "Most teaming agreements fail as unenforceable agreements to negotiate precisely because the subcontract scope is left for later. A defined workshare with an attached SOW is what makes the promise specific enough to enforce.",
    fix: "Attach the subcontractor's statement of work and state the workshare percentage or defined scope the prime commits to subcontract on award.",
    sev: "critical",
  },
  {
    id: "COMM-154",
    name: "Exclusivity and duration",
    cite: practice(
      "teaming-exclusivity",
      "exclusivity in government-contracting teaming agreements",
    ),
    pat: [
      /exclusiv/i,
      /(shall\s+not\s+(team|participate)\s+with|other\s+offerors?|competing\s+team)/i,
    ],
    why: "Exclusivity is the consideration the team member gives up. Its scope — this solicitation only, and for how long — needs a boundary, or the member is locked out of a recompete it was never promised work on.",
    fix: "State the exclusivity scope, that it is limited to this procurement, and the date or event on which it ends.",
  },
  {
    id: "COMM-155",
    name: "Enforceability recital and duty to negotiate",
    cite: practice(
      "teaming-enforceability",
      "the agreement-to-agree problem in teaming agreements",
    ),
    pat: [
      /(good\s+faith\s+(negotiat|efforts)|negotiate\s+in\s+good\s+faith)/i,
      /(binding|not\s+binding|agreement\s+to\s+agree|unenforceable)/i,
    ],
    why: "Courts in Virginia and elsewhere have held teaming agreements unenforceable as agreements to agree where material subcontract terms were left open. Saying which obligations are binding now is the only cure available at signature.",
    fix: "State which provisions are presently binding (exclusivity, confidentiality, proposal cost allocation) and either attach the subcontract form or set the terms to be negotiated.",
  },
  {
    id: "COMM-156",
    name: "Proposal data and confidentiality",
    cite: cfr("48", "3.104", "FAR — Procurement Integrity Act restrictions"),
    pat: [
      /(proprietary|confidential)/i,
      /(proposal\s+(data|information)|bid\s+and\s+proposal|source\s+selection\s+information)/i,
    ],
    why: "Team members exchange pricing and technical data that becomes the other's competitive advantage on the recompete. The Procurement Integrity Act separately restricts contractor bid or proposal information.",
    fix: "Add a confidentiality clause covering proposal data with a survival period, a residuals limit, and an acknowledgment of the Procurement Integrity Act restrictions.",
  },
]);

// ── FAR flow-down rider ─────────────────────────────────────────────
const FLOWDOWN = pack("far-subcontract-flowdown", C, [
  {
    id: "COMM-157",
    name: "Mandatory clause list and incorporation by reference",
    cite: cfr(
      "48",
      "52.244-6",
      "FAR — subcontracts for commercial products and commercial services",
    ),
    pat: [
      /(incorporated\s+by\s+reference|set\s+forth\s+in\s+full\s+text)/i,
      /(52\.\d{3}-\d+|far\s+clause)/i,
    ],
    why: "Flow-down clauses bind a subcontractor only if the rider actually names them; a bare 'all applicable FAR clauses flow down' is unenforceably vague and leaves the prime out of compliance with its own contract.",
    fix: "List each flowed-down clause by FAR/DFARS number and date, and state the substitutions of 'Contractor' for 'Government' where they apply.",
    sev: "critical",
  },
  {
    id: "COMM-158",
    name: "Audit and records access",
    cite: cfr("48", "52.215-2", "FAR — audit and records, negotiation"),
    pat: [
      /(52\.215-2|audit\s+and\s+records)/i,
      /(access\s+to\s+records|examine\s+(any\s+)?records|three\s+years\s+after\s+final\s+payment)/i,
    ],
    why: "The government's audit right reaches subcontract records for three years after final payment. A prime that fails to flow it down cannot produce what a DCAA auditor demands.",
    fix: "Flow down FAR 52.215-2 with the record-retention period and the right of the Comptroller General and the contracting officer to examine records.",
  },
  {
    id: "COMM-159",
    name: "Termination for convenience of the government",
    cite: cfr(
      "48",
      "52.249-2",
      "FAR — termination for convenience of the Government (fixed-price)",
    ),
    pat: [
      /(termination\s+for\s+(the\s+)?convenience)/i,
      /(52\.249|settlement\s+proposal|terminated\s+work)/i,
    ],
    why: "When the government terminates the prime for convenience, the prime must be able to pass that termination down or it owes full performance damages to a subcontractor whose work has been cancelled.",
    fix: "Flow down the termination-for-convenience clause with the subcontractor's settlement-proposal procedure and deadline.",
  },
  {
    id: "COMM-160",
    name: "Cybersecurity — DFARS 252.204-7012 / NIST SP 800-171",
    cite: cfr(
      "48",
      "252.204-7012",
      "DFARS — safeguarding covered defense information and cyber incident reporting",
    ),
    pat: [
      /(252\.204-7012|252\.204-7020|nist\s+sp\s+800-171|cmmc)/i,
      /(covered\s+defense\s+information|controlled\s+unclassified\s+information|cyber\s+incident\s+report)/i,
    ],
    why: "DFARS 252.204-7012(m) requires the clause in all subcontracts where covered defense information will be handled, with a 72-hour incident report to DoD. The prime is liable for a subcontractor's failure.",
    fix: "Flow down 252.204-7012 (and 7019/7020 where applicable), require NIST SP 800-171 implementation and an SPRS score, and set the 72-hour incident-report duty.",
    when: [/(defense|dod|department\s+of\s+defense|dfars|covered\s+defense\s+information)/i],
    sev: "critical",
  },
  {
    id: "COMM-161",
    name: "Small-business and socioeconomic clauses",
    cite: cfr("48", "52.219-8", "FAR — utilization of small business concerns"),
    pat: [
      /(52\.219|small\s+business\s+(subcontracting|concerns))/i,
      /(52\.222-26|equal\s+opportunity|affirmative\s+action)/i,
    ],
    why: "FAR 52.219-8 and 52.222-26 are among the handful of clauses required in subcontracts above threshold regardless of commerciality. Their omission is a recurring finding in prime contractor audits.",
    fix: "Flow down FAR 52.219-8, 52.222-26, 52.222-35/36/37, and 52.222-50 as applicable to the subcontract value and type.",
  },
  {
    id: "COMM-162",
    name: "Payment and prompt-payment flow-down",
    cite: cfr(
      "48",
      "52.232-40",
      "FAR — providing accelerated payments to small business subcontractors",
    ),
    pat: [
      /(prompt\s+payment|accelerated\s+payment)/i,
      /(52\.232|payment\s+within\s+\d+\s+days|pay\s+when\s+paid|pay\s+if\s+paid)/i,
    ],
    why: "FAR 52.232-40 requires primes to accelerate payments to small-business subcontractors after receiving accelerated payment themselves. Pay-if-paid clauses are separately unenforceable in many states.",
    fix: "State the payment terms and days, flow down FAR 52.232-40 where the subcontractor is a small business, and confirm whether payment is conditioned on the prime's receipt.",
  },
]);

// ── GSA schedule ────────────────────────────────────────────────────
const GSA = pack("gsa-schedule-contract", C, [
  {
    id: "COMM-163",
    name: "Basis-of-award customer and Price Reductions clause",
    cite: cfr("48", "552.238-81", "GSAR — Price Reductions clause"),
    pat: [
      /(price\s+reductions?\s+clause|552\.238-81|552\.238-75)/i,
      /(basis\s+of\s+award|boa\s+customer|discount\s+relationship)/i,
    ],
    why: "The Price Reductions clause is the single largest source of False Claims Act exposure on a Schedule contract: a discount to the basis-of-award customer that is not passed to GSA is a defective-pricing claim years later.",
    fix: "Identify the basis-of-award customer or category, state the discount relationship, and describe the monitoring and disclosure process for triggering events.",
    sev: "critical",
  },
  {
    id: "COMM-164",
    name: "Industrial Funding Fee and sales reporting",
    cite: cfr("48", "552.238-80", "GSAR — industrial funding fee and sales reporting"),
    pat: [
      /(industrial\s+funding\s+fee|iff)/i,
      /(sales\s+report|72a|transactional\s+data\s+report)/i,
    ],
    why: "The IFF is remitted quarterly on reported Schedule sales; under-reporting is both a contract breach and a potential FCA claim. Whether the contract is on 72A or TDR changes the reporting entirely.",
    fix: "State the IFF rate, the reporting system (72A or Transactional Data Reporting), the reporting cadence, and the remittance deadline.",
  },
  {
    id: "COMM-165",
    name: "Trade Agreements Act country of origin",
    cite: cfr("48", "52.225-5", "FAR — Trade Agreements"),
    pat: [
      /(trade\s+agreements?\s+act|52\.225-5|taa)/i,
      /(country\s+of\s+origin|designated\s+country|substantially\s+transformed)/i,
    ],
    why: "Products on a Schedule contract must be US-made or designated-country end products. TAA non-compliance is a frequent qui tam theory, and 'substantial transformation' is a fact question the contractor must be able to document.",
    fix: "Certify country of origin for each offered product, state the substantial-transformation basis where relied on, and require notice of any change.",
  },
  {
    id: "COMM-166",
    name: "Ordering procedures and order-level terms",
    cite: cfr("48", "8.405", "FAR — ordering procedures for Federal Supply Schedules"),
    pat: [
      /(ordering\s+(procedures|activit)|task\s+order|delivery\s+order)/i,
      /(8\.405|order-?level\s+materials|blanket\s+purchase\s+agreement)/i,
    ],
    why: "FAR 8.405 governs how ordering activities compete Schedule orders. Order-level terms that conflict with the Schedule contract are a recurring dispute, and the Schedule terms generally control.",
    fix: "State the ordering procedures, whether BPAs are contemplated, and that Schedule contract terms govern over inconsistent order-level terms.",
  },
  {
    id: "COMM-167",
    name: "Option periods and extensions",
    cite: cfr("48", "52.217-9", "FAR — option to extend the term of the contract"),
    pat: [
      /(option\s+(period|to\s+extend)|52\.217-9)/i,
      /(base\s+period|five\s+years|exercise\s+the\s+option)/i,
    ],
    why: "Schedule contracts run a five-year base with three five-year options. Missing the exercise mechanics leaves the contractor unsure whether continued performance is under contract at all.",
    fix: "State the base period, the option periods, the notice required to exercise, and the maximum contract duration.",
  },
]);

// ── Advertising insertion order ─────────────────────────────────────
const INSERTION_ORDER = pack("advertising-insertion-order", C, [
  {
    id: "COMM-168",
    name: "Flight dates, inventory, and impressions",
    cite: standardForm(
      "IAB Standard Terms and Conditions v3.0",
      "standard terms for internet advertising for media buys one year or less",
      "https://www.iab.com/guidelines/standard-terms-conditions-internet-advertising-media-buys-one-year-less/",
    ),
    pat: [
      /(flight\s+dates?|campaign\s+dates?|start\s+date)/i,
      /(impressions?|inventory|placements?|units)/i,
    ],
    why: "The IO is the contract; the terms are the boilerplate. Without flight dates and a deliverable quantity there is nothing to measure under-delivery against.",
    fix: "State the flight dates, ad units, placements, targeting, and the guaranteed impression or delivery quantity.",
  },
  {
    id: "COMM-169",
    name: "Pricing, discrepancy resolution, and third-party measurement",
    cite: standardForm(
      "IAB Standard Terms and Conditions v3.0",
      "measurement, discrepancy, and billing provisions",
      "https://www.iab.com/guidelines/standard-terms-conditions-internet-advertising-media-buys-one-year-less/",
    ),
    pat: [
      /(cpm|cpc|net\s+cost|rate)/i,
      /(discrepanc|third[- ]party\s+(ad\s+server|measurement)|counting\s+method)/i,
    ],
    why: "Ad server counts differ by a few percent as a matter of course. IAB § III sets a discrepancy tolerance and names the system of record; without it, every invoice is negotiable.",
    fix: "State the pricing model and rate, name the system of record for billing, and set the discrepancy threshold above which the parties reconcile.",
  },
  {
    id: "COMM-170",
    name: "Makegood and under-delivery remedy",
    cite: standardForm(
      "IAB Standard Terms and Conditions v3.0",
      "makegood provisions for under-delivery",
      "https://www.iab.com/guidelines/standard-terms-conditions-internet-advertising-media-buys-one-year-less/",
    ),
    pat: [/makegood/i, /(under-?deliver|shortfall|credit\s+for\s+undelivered)/i],
    why: "Under-delivery is normal, not exceptional. The IAB default is a makegood proposal within a stated window and a credit if none is accepted — the buyer's only practical remedy.",
    fix: "State the makegood proposal window, the buyer's approval right, and the credit or refund available when no acceptable makegood is offered.",
  },
  {
    id: "COMM-171",
    name: "Cancellation notice periods",
    cite: standardForm(
      "IAB Standard Terms and Conditions v3.0",
      "cancellation provisions by inventory type",
      "https://www.iab.com/guidelines/standard-terms-conditions-internet-advertising-media-buys-one-year-less/",
    ),
    pat: [/cancel(lation)?/i, /(days'?\s+(prior\s+)?notice|without\s+penalty|non-?cancelable)/i],
    why: "IAB terms give different cancellation rights for guaranteed vs. non-guaranteed and sponsorship inventory. Silence usually means the media company's own form applies, which is materially less favorable to the buyer.",
    fix: "State the cancellation notice period for each inventory type and whether any portion is non-cancelable.",
  },
  {
    id: "COMM-172",
    name: "Sequential liability and agency payment",
    cite: standardForm(
      "IAB Standard Terms and Conditions v3.0",
      "sequential liability provisions",
      "https://www.iab.com/guidelines/standard-terms-conditions-internet-advertising-media-buys-one-year-less/",
    ),
    pat: [
      /sequential(ly)?\s+liab/i,
      /(agency\s+is\s+not\s+liable|solely\s+as\s+agent|advertiser\s+shall\s+be\s+liable)/i,
    ],
    why: "Sequential liability makes the agency liable only to the extent it has been paid by the advertiser. Whether the media company accepts it decides who bears the advertiser's insolvency.",
    fix: "State whether the agency is liable sequentially or jointly, and identify the party responsible for payment if the advertiser does not fund.",
  },
]);

// ── Sponsorship ─────────────────────────────────────────────────────
const SPONSORSHIP = pack("sponsorship-agreement", C, [
  {
    id: "COMM-173",
    name: "Rights granted and category exclusivity",
    cite: practice(
      "sponsorship-rights",
      "rights and category exclusivity in sponsorship agreements",
    ),
    pat: [
      /(rights\s+granted|sponsor(ship)?\s+(rights|benefits)|official\s+(sponsor|partner))/i,
      /(exclusiv|category|competing\s+(brand|sponsor))/i,
    ],
    why: "Category exclusivity is what the sponsor is paying for. Its boundary — the product category, not the company — must be drawn precisely or a competitor arrives through an adjacent category.",
    fix: "Enumerate the rights granted (signage, naming, hospitality, digital, IP use) and define the exclusive category by product, not by named competitor.",
    sev: "critical",
  },
  {
    id: "COMM-174",
    name: "Sponsorship fee and payment schedule",
    cite: practice("sponsorship-fee", "fee and payment structuring in sponsorship agreements"),
    pat: [
      /(sponsorship\s+fee|rights\s+fee|the\s+fee)/i,
      /(payment\s+schedule|installments?|value-?in-?kind)/i,
    ],
    why: "Sponsorship fees are usually paid before the season or event delivers, so the payment schedule and any value-in-kind component decide who is exposed if the property under-delivers.",
    fix: "State the cash fee, the payment schedule tied to delivery milestones, and the agreed valuation of any value-in-kind component.",
  },
  {
    id: "COMM-175",
    name: "Trademark license and approval rights",
    cite: usc("15", "1055", "Lanham Act — use by related companies and quality control"),
    pat: [
      /(trademark|logo|marks?)\s+(license|use)/i,
      /(approv(e|al)\s+(of\s+)?(all\s+)?(uses|materials|creative)|prior\s+written\s+approval)/i,
    ],
    why: "Both parties license marks to each other. A trademark licensor that does not control quality risks abandonment through naked licensing under the Lanham Act.",
    fix: "Grant reciprocal, limited trademark licenses with brand guidelines, an approval process with a deemed-approval deadline, and quality-control rights.",
  },
  {
    id: "COMM-176",
    name: "Event cancellation and force majeure remedy",
    cite: practice(
      "sponsorship-cancellation",
      "cancellation and force majeure remedies in sponsorship",
    ),
    pat: [
      /(force\s+majeure|cancel(l)?ation\s+of\s+the\s+event|postpone)/i,
      /(refund|pro\s?rata|credit\s+against\s+future)/i,
    ],
    why: "The 2020 season cancellations proved that sponsorship force majeure clauses usually excused the property's performance without refunding the sponsor. The remedy — refund, proration, or make-good year — has to be stated.",
    fix: "State the remedy for cancellation, postponement, and reduced-capacity events: pro rata refund, credit, or extension, with a mechanism for partial delivery.",
  },
  {
    id: "COMM-177",
    name: "Morals clause and reputational termination",
    cite: practice("morals-clause", "morals clauses in sponsorship and endorsement agreements"),
    pat: [/(morals?\s+clause|disrepute|scandal|reputation)/i, /(terminat|suspend|withhold)/i],
    why: "Reputational harm runs both ways, and a one-sided morals clause protecting only the sponsor is the norm the property should push back on. The trigger must be objective enough to invoke.",
    fix: "Add a mutual morals clause with an objective trigger (conviction, admitted conduct, or conduct that brings the party into public disrepute), a cure or suspension step, and the fee consequence.",
  },
]);

// ── Influencer / endorsement ────────────────────────────────────────
const INFLUENCER = pack("influencer-agreement", C, [
  {
    id: "COMM-178",
    // 1.1.0 — an express disclaimer of this column is now reported as a
    // disclaimer rather than read as compliance (`v5/_pack.ts`, `denied`).
    ver: "1.1.0",
    name: "Clear and conspicuous material-connection disclosure duty",
    cite: cfr("16", "255.5", "FTC Endorsement Guides — disclosure of material connections"),
    pat: [
      /(#ad\b|#sponsored|paid\s+partnership)/i,
      /(clearly?\s+and\s+conspicuous|material\s+connection|disclose\s+the\s+relationship)/i,
    ],
    why: "16 C.F.R. § 255.5 requires disclosure of a material connection between endorser and advertiser. Since the 2023 Guides revision and the Rule on Consumer Reviews, both the brand and the creator carry exposure, and the brand is liable for failing to instruct and monitor.",
    fix: 'Require a clear and conspicuous disclosure in the post itself (not only in a bio or "more" fold), specify the accepted formats, and require it on every platform and every re-post.',
    denied: expressDenial(String.raw`material[- ]connection\s+disclosure`),
    sev: "critical",
  },
  {
    id: "COMM-179",
    name: "Substantiation of claims made",
    cite: cfr("16", "255.1", "FTC Endorsement Guides — general considerations"),
    pat: [
      /(substantiat|claims?\s+about\s+the\s+products?|approved\s+claims)/i,
      /(may\s+not\s+(make|state)|shall\s+only\s+(make|use)|talking\s+points)/i,
    ],
    why: "An endorsement may not convey a claim the advertiser could not itself substantiate, and the endorser must be a bona fide user where the ad says so. Free-form creator copy is where unsubstantiated claims enter.",
    fix: "Provide an approved claims list, prohibit unapproved health, efficacy, or comparative claims, and require the creator to be an actual user where the content implies it.",
  },
  {
    id: "COMM-180",
    name: "Content ownership and usage license",
    cite: practice(
      "influencer-ip",
      "content ownership and whitelisting rights in creator agreements",
    ),
    pat: [
      /(ownership\s+of\s+the\s+content|work\s+made\s+for\s+hire|creator\s+retains)/i,
      /(license\s+to\s+(use|repost)|usage\s+rights|whitelist|paid\s+amplification)/i,
    ],
    why: "Brands routinely amplify creator content as paid media without having bought the right to. Usage term, territory, media, and whether the creator's likeness travels with the content are all separate grants.",
    fix: "State who owns the content, grant the brand a license with defined media, territory, and duration, and price any extension for paid amplification or whitelisting.",
  },
  {
    id: "COMM-181",
    name: "Exclusivity and competing brands",
    cite: practice("influencer-exclusivity", "category exclusivity in creator agreements"),
    pat: [/exclusiv/i, /(competing\s+(brand|product)|shall\s+not\s+promote|category)/i],
    why: "Exclusivity is the creator's largest cost and is frequently written open-ended. Category and duration have to be bounded or the creator has sold their whole calendar for one campaign fee.",
    fix: "Define the exclusive category narrowly, state the exclusivity period, and confirm whether it survives the content term.",
  },
  {
    id: "COMM-182",
    name: "Takedown right and content correction",
    cite: cfr(
      "16",
      "255.5",
      "FTC Endorsement Guides — advertiser responsibility for endorser conduct",
    ),
    pat: [
      /(remove|take\s?down|delete\s+the\s+(content|post))/i,
      /(correct|edit|amend\s+the\s+(post|disclosure))/i,
    ],
    why: "The brand's monitoring duty is meaningless without the contractual power to require correction or removal of a non-compliant post — and to do so quickly.",
    fix: "Reserve the right to require correction or removal within a stated number of hours, and make repeated non-compliance a termination event with fee forfeiture.",
  },
  {
    id: "COMM-183",
    name: "FTC compliance training and monitoring",
    cite: cfr("16", "255.5", "FTC Endorsement Guides — monitoring of endorsers"),
    pat: [
      /(train(ing)?|guidelines\s+provided|compliance\s+program)/i,
      /(monitor|periodic\s+review|audit\s+of\s+(posts|content))/i,
    ],
    why: "FTC consent orders in this area consistently require the advertiser to have a monitoring program. Contractual language creating one is the evidence that the program existed.",
    fix: "Require the creator to complete disclosure training, and commit the brand to a periodic monitoring review with a documented escalation path.",
  },
]);

// ── Model / talent release ──────────────────────────────────────────
const MEDIA_RELEASE = pack("media-release", C, [
  {
    id: "COMM-184",
    name: "Scope of media, territory, and duration",
    cite: stateLaw(
      "right-of-publicity",
      "statutory right-of-publicity protection for name, image, and likeness",
      "https://www.law.cornell.edu/wex/publicity",
    ),
    pat: [
      /(in\s+all\s+media|any\s+and\s+all\s+media|print,?\s+digital)/i,
      /(worldwide|territory|in\s+perpetuity|for\s+a\s+period\s+of)/i,
    ],
    why: "A release with no stated media, territory, or duration is read narrowly against the drafter in several states. The producer that assumed perpetual worldwide rights often did not buy them.",
    fix: "State the media, territory, and duration of the grant expressly, including whether it extends to derivative and promotional uses.",
    sev: "critical",
  },
  {
    id: "COMM-185",
    name: "Consideration recited",
    cite: practice("release-consideration", "consideration in likeness releases"),
    pat: [
      /(in\s+consideration\s+of|for\s+good\s+and\s+valuable\s+consideration)/i,
      /(\$|payment|compensation|receipt\s+of\s+which\s+is\s+acknowledged)/i,
    ],
    why: "A gratuitous release is revocable in several jurisdictions. Reciting consideration — even nominal, and acknowledging receipt — is what makes the release a contract rather than a permission.",
    fix: "Recite the consideration paid and acknowledge its receipt, or state the non-monetary consideration exchanged.",
  },
  {
    id: "COMM-186",
    name: "Minor's parent or guardian signature",
    cite: practice("minor-release", "parental consent for likeness releases by minors"),
    pat: [
      /(parent|guardian)/i,
      /(minor|under\s+the\s+age\s+of\s+18|on\s+behalf\s+of\s+my\s+child)/i,
    ],
    why: "A minor's release is voidable; only a parent or guardian signature — and in some states court approval — binds. Productions using minors without the signature block have no release at all.",
    fix: "Add a parent/guardian signature block with an affirmation of authority, and note where court approval is required for the engagement.",
    when: [/(minor|child|under\s+the\s+age\s+of\s+18|parent\s+or\s+guardian)/i],
  },
  {
    id: "COMM-187",
    name: "Irrevocability and waiver of inspection rights",
    cite: practice(
      "release-irrevocability",
      "irrevocability and approval waivers in likeness releases",
    ),
    pat: [
      /(irrevocab|shall\s+not\s+revoke)/i,
      /(waive[sd]?\s+(any\s+)?right\s+to\s+(inspect|approve)|no\s+right\s+of\s+approval)/i,
    ],
    why: "Without an express waiver of inspection and approval, a subject can claim a right to review the final use — which is unworkable for a production already in distribution.",
    fix: "State that the release is irrevocable and that the subject waives any right to inspect or approve the finished work or the copy used with it.",
  },
  {
    id: "COMM-188",
    name: "Post-mortem right-of-publicity treatment",
    cite: stateLaw(
      "post-mortem-publicity",
      "descendible post-mortem right of publicity in states that recognize one",
      "https://www.law.cornell.edu/wex/publicity",
    ),
    pat: [
      /(heirs|successors|assigns|estate)/i,
      /(post-?mortem|after\s+(my\s+)?death|descendible)/i,
    ],
    why: "About half the states recognize a descendible post-mortem right of publicity running decades past death. A release that does not bind heirs leaves a claim the estate can assert.",
    fix: "State that the release binds the subject's heirs, executors, and assigns, and that it survives the subject's death.",
  },
]);

export const V5_COMMERCIAL_RULES: readonly Rule[] = [
  ...PURCHASE_ORDER,
  ...MASTER_PURCHASE,
  ...EQUIPMENT_LEASE,
  ...FREIGHT,
  ...WAREHOUSING,
  ...STAFFING,
  ...FRANCHISE,
  ...FDD,
  ...JOINT_VENTURE,
  ...TEAMING,
  ...FLOWDOWN,
  ...GSA,
  ...INSERTION_ORDER,
  ...SPONSORSHIP,
  ...INFLUENCER,
  ...MEDIA_RELEASE,
];
