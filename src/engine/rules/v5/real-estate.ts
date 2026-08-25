/**
 * v5 sub-domain E′ — US real estate: leasing satellites, brokerage,
 * conveyancing, and residential purchase (spec-v45.md §6.E). Rule ids
 * continue the RE namespace at 101.
 */

import type { Rule } from "../../finding.js";
import { pack } from "./_pack.js";
import { usc, stateLaw, practice } from "./_helpers.js";

const C = "real-estate";

const SUBLEASE = pack("sublease-agreement", C, [
  {
    id: "RE-101",
    name: "Prime-lease incorporation and precedence",
    cite: practice("sublease-incorporation", "incorporation of the prime lease into a sublease"),
    pat: [
      /(prime\s+lease|master\s+lease|overlease)/i,
      /(incorporated\s+by\s+reference|subject\s+(and\s+subordinate)?\s+to|terms\s+of\s+the\s+(prime|master)\s+lease\s+(shall\s+)?(apply|govern))/i,
    ],
    why: "A subtenant is bound by prime-lease obligations it cannot read unless the sublease attaches and incorporates it. Incorporation without a copy attached is the most common sublease defect.",
    fix: "Attach the prime lease, incorporate its terms as between sublandlord and subtenant with stated exclusions, and state which document controls on conflict.",
    sev: "critical",
  },
  {
    id: "RE-102",
    name: "Landlord consent as a condition precedent",
    cite: practice("sublease-consent", "landlord consent requirements for subleasing"),
    pat: [
      /landlord'?s?\s+consent/i,
      /(condition\s+precedent|shall\s+not\s+be\s+effective\s+until|if\s+consent\s+is\s+not\s+obtained)/i,
    ],
    why: "Nearly every commercial lease forbids subletting without consent, and a sublease made without it is a default that can terminate the prime lease — taking the sublease with it.",
    fix: "Condition effectiveness on the landlord's written consent, set an outside date, and give both parties a termination right if consent is not obtained by then.",
    sev: "critical",
  },
  {
    id: "RE-103",
    name: "Recapture and termination risk allocation",
    cite: practice("sublease-recapture", "recapture rights in commercial leases"),
    pat: [
      /recapture/i,
      /(terminate\s+the\s+(prime|master)\s+lease|landlord\s+may\s+elect|prime\s+lease\s+terminates)/i,
    ],
    why: "Many leases let the landlord recapture the space instead of consenting, and the subtenant's whole deal disappears. A subtenant investing in improvements needs to know the risk before it spends.",
    fix: "Disclose any recapture right, state what happens to the subtenant if it is exercised or if the prime lease terminates early, and allocate the cost of improvements.",
  },
  {
    id: "RE-104",
    name: "Rent, escalations, and pass-throughs",
    cite: practice("sublease-rent", "rent and operating-expense pass-throughs in subleases"),
    pat: [
      /(rent|base\s+rent)/i,
      /(escalat|operating\s+expenses|additional\s+rent|pass-?through|proportionate\s+share)/i,
    ],
    why: "A subtenant paying a fixed rent while the sublandlord absorbs escalations is a different economic deal from one that takes a proportionate share. The pass-through mechanics must match the prime lease's own.",
    fix: "State base rent, escalations, and which prime-lease operating expenses pass through, with the base year and proportionate share.",
  },
  {
    id: "RE-105",
    name: "Surrender condition and holdover",
    cite: practice("sublease-surrender", "surrender and holdover in subleases"),
    pat: [
      /(surrender|return\s+the\s+(subleased\s+)?premises)/i,
      /(holdover|hold\s+over|restore|remove\s+(the\s+)?(alterations|improvements))/i,
    ],
    why: "A subtenant that holds over exposes the sublandlord to prime-lease holdover rent — commonly 150% to 200% of rent plus consequential damages. The indemnity for that exposure is the sublandlord's key protection.",
    fix: "State the surrender condition and removal obligations, and require the subtenant to indemnify the sublandlord for prime-lease holdover damages.",
  },
  {
    id: "RE-106",
    name: "Attornment on prime-lease termination",
    cite: practice(
      "sublease-attornment",
      "direct-lease attornment on termination of the prime lease",
    ),
    pat: [/attorn/i, /(direct\s+lease|recognize\s+the\s+subtenant|non-?disturbance)/i],
    why: "Without an attornment or recognition agreement from the landlord, termination of the prime lease extinguishes the sublease no matter how well the subtenant has performed.",
    fix: "Obtain the landlord's recognition and non-disturbance in the consent, and add a subtenant attornment covenant on prime-lease termination.",
  },
]);

const LEASE_LOI = pack("letter-of-intent-lease", C, [
  {
    id: "RE-107",
    name: "Binding versus non-binding provisions identified",
    cite: practice("loi-binding", "the binding/non-binding split in letters of intent"),
    pat: [
      /(non-?binding|not\s+(intended\s+to\s+be\s+)?(legally\s+)?binding)/i,
      /(binding\s+(provisions?|obligations?)|except\s+(for|as\s+to)|the\s+following\s+(paragraphs?|provisions?)\s+are\s+binding)/i,
    ],
    why: "An LOI that says nothing about intent can be enforced as a contract where the material terms are present. Naming which paragraphs bind — usually exclusivity, confidentiality, and expenses — is the whole point of the document.",
    fix: "State expressly that the LOI is non-binding except for identified paragraphs, and list them.",
    sev: "critical",
  },
  {
    id: "RE-108",
    name: "Premises, term, and base rent",
    cite: practice("loi-economics", "economic terms in a lease letter of intent"),
    pat: [
      /(premises|rentable\s+square\s+feet|suite)/i,
      /(base\s+rent|term\s+of\s+\d+|commencement)/i,
    ],
    why: "An LOI without the three economic terms is not worth negotiating from; the drafting attorney will have to ask for all of them anyway.",
    fix: "State the premises and rentable area, the measurement standard, the term and commencement, and the base rent with escalations.",
  },
  {
    id: "RE-109",
    name: "Tenant improvement allowance and free rent",
    cite: practice("loi-concessions", "concession terms in lease letters of intent"),
    pat: [
      /(tenant\s+improvement\s+allowance|ti\s+allowance|improvement\s+allowance)/i,
      /(free\s+rent|abated?\s+rent|rent\s+abatement|months?\s+of\s+free)/i,
    ],
    why: "Concessions are the negotiated value in most lease deals. Left out of the LOI, they reappear in the lease draft as a surprise for one side.",
    fix: "State the allowance amount per rentable square foot, what it may be spent on, and the free-rent period and where it falls in the term.",
  },
  {
    id: "RE-110",
    name: "Exclusivity or no-shop period",
    cite: practice("loi-exclusivity", "exclusivity provisions in letters of intent"),
    pat: [
      /(exclusiv|no-?shop)/i,
      /(shall\s+not\s+(negotiate|market|offer)|until\s+the\s+(expiration|earlier))/i,
    ],
    why: "Exclusivity is one of the few genuinely binding LOI terms and the reason a tenant is willing to spend on space planning and legal fees.",
    fix: "Add a binding exclusivity covenant with a stated period and a defined scope of what the landlord may not do during it.",
  },
  {
    id: "RE-111",
    name: "Expiration of the letter of intent",
    cite: practice("loi-expiration", "expiration of letters of intent"),
    pat: [
      /(expire|terminate|of\s+no\s+further\s+force)/i,
      /(if\s+not\s+(executed|signed|accepted)\s+by|on\s+or\s+before|outside\s+date)/i,
    ],
    why: "An LOI with no expiration lives forever in a file and gets produced years later as evidence of terms. A stated expiry closes it.",
    fix: "State the date the LOI expires if a lease is not executed, and that it is of no further force thereafter.",
  },
]);

const PROPERTY_MGMT = pack("property-management-agreement", C, [
  {
    id: "RE-112",
    name: "Scope of authority and expenditure limits",
    cite: practice("pma-authority", "authority limits in property management agreements"),
    pat: [
      /(authority|authorized\s+to)/i,
      /(without\s+(the\s+)?owner'?s?\s+(prior\s+)?(written\s+)?(approval|consent)|expenditures?\s+(in\s+excess\s+of|exceeding)|\$)/i,
    ],
    why: "A manager with unbounded spending authority can commit the owner to capital work it never approved. The dollar threshold and the emergency exception are the central controls.",
    fix: "State the manager's authority, the per-item and annual expenditure limits requiring owner approval, and the emergency exception with a notice duty.",
    sev: "critical",
  },
  {
    id: "RE-113",
    name: "Management fee and leasing commissions",
    cite: practice("pma-fee", "management fees and leasing commissions"),
    pat: [
      /management\s+fee/i,
      /(leasing\s+commission|percentage\s+of\s+(gross\s+)?(collected\s+)?(rent|revenue)|construction\s+management\s+fee)/i,
    ],
    why: "Fee disputes turn on the base — collected versus billed rent, and whether the fee applies to recoveries, parking, and termination payments. Leasing commissions are usually a separate schedule.",
    fix: "State the fee percentage and the exact revenue base, and attach the leasing commission and construction-management fee schedules.",
  },
  {
    id: "RE-114",
    name: "Segregated trust and operating accounts",
    cite: stateLaw(
      "broker-trust-account",
      "trust account and commingling rules for real estate brokers and property managers",
      "https://www.law.cornell.edu/wex/escrow",
    ),
    pat: [
      /(trust\s+account|separate\s+account|segregated)/i,
      /(operating\s+account|security\s+deposits?|shall\s+not\s+(be\s+)?commingle)/i,
    ],
    why: "Commingling owner funds is a licensing violation in every state and a conversion claim. Security deposits are separately regulated and often must sit in their own account.",
    fix: "Require segregated operating and security-deposit accounts in the owner's name, prohibit commingling, and state the reserve balance and disbursement authority.",
  },
  {
    id: "RE-115",
    name: "Real estate broker licensing recital",
    cite: stateLaw(
      "broker-licensing",
      "real estate broker licensing requirements for property management and leasing activity",
      "https://www.law.cornell.edu/wex/real_estate_broker",
    ),
    pat: [/licens(e|ed|ing)/i, /(real\s+estate\s+broker|brokerage|in\s+the\s+state\s+of)/i],
    why: "Leasing and management for compensation requires a broker's license in most states, and an unlicensed manager may be unable to sue for its fee.",
    fix: "Recite the manager's broker license number and state of licensure, and require it to remain licensed throughout the term.",
  },
  {
    id: "RE-116",
    name: "Insurance, indemnity, and standard of care",
    cite: practice("pma-insurance", "insurance and indemnity allocation in property management"),
    pat: [
      /insur(e|ance)/i,
      /(indemnif|standard\s+of\s+care|gross\s+negligence|willful\s+misconduct)/i,
    ],
    why: "Managers seek indemnity for acts within the scope of the agreement; owners resist covering the manager's own negligence. Where that line falls is the agreement's main risk term.",
    fix: "Require the manager to carry general liability, crime/fidelity, and E&O coverage naming the owner, and state a mutual indemnity carving out negligence and willful misconduct.",
  },
  {
    id: "RE-117",
    name: "Termination rights and transition of records",
    cite: practice(
      "pma-termination",
      "termination and transition obligations in property management",
    ),
    pat: [
      /terminat/i,
      /(deliver|turn\s+over|transition|records|keys|tenant\s+files|final\s+accounting)/i,
    ],
    why: "The value in a management relationship is the records — leases, tenant ledgers, vendor contracts, deposits. A termination clause that does not compel their delivery leaves the owner unable to operate.",
    fix: "State the termination rights and notice, and require delivery of all records, funds, deposits, keys, and a final accounting within a stated number of days.",
  },
]);

const LISTING = pack("listing-agreement", C, [
  {
    id: "RE-118",
    name: "Listing type and exclusivity",
    cite: practice("listing-type", "exclusive right to sell versus exclusive agency listings"),
    pat: [
      /(exclusive\s+right\s+to\s+sell|exclusive\s+agency|open\s+listing)/i,
      /(listing\s+period|term\s+of\s+this\s+(listing|agreement)|expires?)/i,
    ],
    why: "Under an exclusive right to sell, the broker is paid even if the owner finds the buyer; under exclusive agency it is not. Owners frequently sign the first believing they signed the second.",
    fix: "State the listing type in plain terms, explain the commission consequence of an owner-procured buyer, and state the listing period with its expiration date.",
    sev: "critical",
  },
  {
    id: "RE-119",
    name: "Commission rate and earning trigger",
    cite: practice("commission-trigger", "when a real estate commission is earned"),
    pat: [
      /commission/i,
      /(earned\s+(when|upon)|ready,?\s+willing\s+and\s+able|at\s+closing|procuring\s+cause)/i,
    ],
    why: "A commission earned on procuring a ready, willing, and able buyer is payable even if the sale never closes. Sellers almost always intend payment at closing, and the difference is the whole fee.",
    fix: "State the commission rate and specify whether it is earned on producing a ready, willing, and able buyer or only on actual closing and funding.",
    sev: "critical",
  },
  {
    id: "RE-120",
    name: "Protection or tail period and registered buyers",
    cite: practice("listing-tail", "protection periods in listing agreements"),
    pat: [
      /(protection\s+period|tail\s+period|carryover)/i,
      /(after\s+(the\s+)?(expiration|termination)|registered|named\s+in\s+a\s+list|prospects?)/i,
    ],
    why: "A tail period that applies to any buyer, rather than to prospects the broker registered in writing, can capture a sale the broker had nothing to do with — and can double-commission the seller who relists.",
    fix: "Limit the tail to buyers the broker identifies in a written list delivered within a stated period after expiration, and exclude sales through a successor broker.",
  },
  {
    id: "RE-121",
    name: "Agency disclosure and dual-agency consent",
    cite: stateLaw(
      "agency-disclosure",
      "mandatory real estate agency relationship disclosures and dual agency consent",
      "https://www.law.cornell.edu/wex/agency",
    ),
    pat: [
      /(agency\s+(disclosure|relationship)|dual\s+agen|designated\s+agen)/i,
      /(consent|acknowledge|informed\s+written\s+consent)/i,
    ],
    why: "Every state mandates agency disclosure, and dual agency requires informed written consent (and is prohibited outright in a few states). Undisclosed dual agency forfeits the commission and supports a fiduciary claim.",
    fix: "Include the state-mandated agency disclosure and, where dual or designated agency is possible, obtain informed written consent describing the limits on the broker's duties.",
    sev: "critical",
  },
  {
    id: "RE-122",
    name: "MLS and marketing authorizations",
    cite: practice("listing-mls", "MLS submission and marketing authorizations"),
    pat: [
      /(multiple\s+listing\s+service|mls)/i,
      /(authoriz|photograph|lockbox|signage|yard\s+sign|internet\s+display|market\s+the\s+property)/i,
    ],
    all: true,
    why: "MLS submission, photography, lockbox use, signage, and internet display each need the owner's authorization, and owners increasingly want opt-outs for privacy or off-market strategy.",
    fix: "Authorize MLS submission and the specific marketing activities, and record any owner opt-outs (internet display, address display, lockbox).",
  },
]);

const OPTION = pack("option-to-purchase-real-estate", C, [
  {
    id: "RE-123",
    name: "Option consideration recited and non-refundable",
    cite: practice("option-consideration", "consideration supporting a real property option"),
    pat: [
      /(option\s+(consideration|fee|payment)|in\s+consideration\s+of)/i,
      /(non-?refundable|independent\s+consideration|receipt\s+of\s+which)/i,
    ],
    why: "An option unsupported by separate consideration is a revocable offer. Several states require the consideration to be independent of the purchase price and actually paid.",
    fix: "Recite the option consideration, acknowledge its receipt, state it is non-refundable, and state whether it is credited against the purchase price.",
    sev: "critical",
  },
  {
    id: "RE-124",
    name: "Exercise notice mechanics and deadline",
    cite: practice("option-exercise", "exercise mechanics in real property options"),
    pat: [
      /exercis/i,
      /(written\s+notice|on\s+or\s+before|time\s+is\s+of\s+the\s+essence|deadline)/i,
    ],
    why: "Option exercise is strictly construed: late, informal, or conditional exercise fails. The notice method, address, and deemed-delivery rule are the terms that decide whether the option was exercised at all.",
    fix: "State the exercise deadline, the required form and content of notice, the delivery method and address, and that time is of the essence.",
    sev: "critical",
  },
  {
    id: "RE-125",
    name: "Purchase price or pricing formula",
    cite: practice("option-price", "price determination in real property options"),
    pat: [
      /(purchase\s+price|option\s+price)/i,
      /(\$|formula|apprais|fair\s+market\s+value|determined\s+by)/i,
    ],
    why: "An option with an open price term is often unenforceable for indefiniteness. Where price is by appraisal, the appraiser-selection mechanism has to be complete enough to work without cooperation.",
    fix: "State the price, or a complete formula including the appraisal process, appraiser qualifications, selection method, and tie-breaking.",
  },
  {
    id: "RE-126",
    name: "Memorandum of option and recordation",
    cite: stateLaw(
      "recording",
      "recording acts and constructive notice for interests in real property",
      "https://www.law.cornell.edu/wex/recording_acts",
    ),
    pat: [
      /(memorandum\s+of\s+option|short\s+form)/i,
      /(record|county\s+recorder|register\s+of\s+deeds)/i,
    ],
    why: "An unrecorded option is defeated by a bona fide purchaser. Recording a memorandum gives constructive notice without publishing the commercial terms.",
    fix: "Authorize recording a memorandum of option, and provide for a recordable release if the option expires unexercised.",
  },
  {
    id: "RE-127",
    name: "Rule against perpetuities savings clause",
    cite: stateLaw(
      "rule-against-perpetuities",
      "application of the rule against perpetuities to options in gross",
      "https://www.law.cornell.edu/wex/rule_against_perpetuities",
    ),
    pat: [
      /(rule\s+against\s+perpetuit|perpetuit)/i,
      /(twenty-?one\s+years|21\s+years|savings\s+clause|in\s+no\s+event\s+shall)/i,
    ],
    why: "Options in gross are subject to the rule against perpetuities in states that have not abolished it for commercial options; an option exercisable beyond the period is void.",
    fix: "Add a savings clause capping the option period within the applicable perpetuities period, or confirm the state has exempted commercial options.",
  },
]);

const QUITCLAIM = pack("quitclaim-deed", C, [
  {
    id: "RE-128",
    name: "Granting words appropriate to a quitclaim",
    cite: stateLaw(
      "deed-granting-words",
      "statutory forms and operative words of conveyance",
      "https://www.law.cornell.edu/wex/deed",
    ),
    pat: [
      /(remise,?\s+release|hereby\s+quit\s?claims?|releases?\s+and\s+forever\s+quit)/i,
      /(convey|grant|transfer)/i,
    ],
    all: true,
    why: "Granting words determine the deed's operative effect and, in several states, whether the statutory short form applies. A deed titled quitclaim but using warranty granting words is ambiguous.",
    fix: "Use the state's quitclaim granting words — typically \"remise, release, and forever quitclaim\" — consistently with the deed's title.",
    sev: "critical",
  },
  {
    id: "RE-129",
    name: "Legal description of the property",
    cite: stateLaw(
      "legal-description",
      "sufficiency of legal descriptions for conveyances of real property",
      "https://www.law.cornell.edu/wex/deed",
    ),
    pat: [
      /(legal\s+description|more\s+particularly\s+described)/i,
      /(lot\s+\d|block\s+\d|metes\s+and\s+bounds|township|parcel\s+(no|number|id)|exhibit\s+[a-z])/i,
    ],
    why: "A deed with only a street address or an APN is frequently held insufficient to convey. The legal description is the only identification a title examiner can chain.",
    fix: "Attach or set out the full legal description, and add the parcel number and street address as additional identification, not as a substitute.",
    sev: "critical",
  },
  {
    id: "RE-130",
    name: "No-warranty recital",
    cite: stateLaw(
      "quitclaim-effect",
      "the absence of title covenants in a quitclaim conveyance",
      "https://www.law.cornell.edu/wex/quitclaim_deed",
    ),
    pat: [
      /(without\s+(any\s+)?(covenant|warrant)|no\s+(covenants?|warrant)|whatever\s+(right|interest).{0,40}(if\s+any))/i,
      /(as\s+is|grantor\s+makes\s+no)/i,
    ],
    why: "The defining feature of a quitclaim is that it conveys only what the grantor has, with no covenants. Saying so in the instrument prevents a later argument that warranties were intended.",
    fix: "State that the conveyance is without any covenant or warranty of title, express or implied, and conveys only the grantor's interest, if any.",
  },
  {
    id: "RE-131",
    name: "Consideration recital and transfer-tax statement",
    cite: stateLaw(
      "transfer-tax",
      "real estate transfer tax declarations and exemption statements",
      "https://www.law.cornell.edu/wex/transfer_tax",
    ),
    pat: [
      /(consideration|in\s+consideration\s+of|\$)/i,
      /(transfer\s+tax|documentary\s+(stamp|transfer)|exempt|revenue\s+stamps)/i,
    ],
    why: "Recorders reject deeds without the consideration recital or the transfer-tax declaration, and intra-family quitclaims need the exemption stated to avoid the tax.",
    fix: "Recite the consideration (or the nominal amount for an exempt transfer) and include the transfer-tax declaration or exemption citation the county requires.",
  },
  {
    id: "RE-132",
    name: "Notarial acknowledgment and recording block",
    cite: stateLaw(
      "acknowledgment",
      "notarial acknowledgment requirements for recordable instruments",
      "https://www.law.cornell.edu/wex/notary_public",
    ),
    pat: [
      /(notary\s+public|acknowledged\s+before\s+me|state\s+of\s+\w+\s*,?\s*county\s+of)/i,
      /(record(ing|ed)?\s+(requested|return)|after\s+recording\s+return\s+to|mail\s+tax\s+statements)/i,
    ],
    why: "A deed without a conforming acknowledgment is not recordable and gives no constructive notice, leaving the grantee vulnerable to a subsequent bona fide purchaser.",
    fix: "Add the state's acknowledgment form, the notary's commission details, and the recording-return and tax-statement addresses.",
    sev: "critical",
  },
]);

const WARRANTY_DEED = pack("warranty-deed", C, [
  {
    id: "RE-133",
    name: "Granting words and warranty covenants",
    cite: stateLaw(
      "title-covenants",
      "the covenants of title implied by a general or special warranty deed",
      "https://www.law.cornell.edu/wex/warranty_deed",
    ),
    pat: [
      /(grant,?\s+bargain,?\s+(and\s+)?sell|convey\s+and\s+warrant|does\s+hereby\s+grant)/i,
      /(warrant(s)?\s+and\s+(will\s+)?defend|covenants?\s+of\s+(title|warranty)|general\s+warranty|special\s+warranty)/i,
    ],
    why: "A general warranty covers title defects from any time; a special warranty covers only the grantor's own period. The granting words decide which, and title insurers price on the difference.",
    fix: "Use the state's granting words for the intended warranty type and include the covenant to warrant and defend against lawful claims.",
    sev: "critical",
  },
  {
    id: "RE-134",
    name: "Permitted exceptions schedule",
    cite: practice("permitted-exceptions", "exceptions to the warranty of title in a deed"),
    pat: [
      /(subject\s+to|except\s+for|permitted\s+exceptions)/i,
      /(easements|restrictions|covenants\s+of\s+record|taxes\s+not\s+yet\s+due|matters\s+of\s+record)/i,
    ],
    why: "A warranty deed that excepts nothing warrants against every recorded easement and restriction on the parcel — an exposure no seller intends and no title company will insure over.",
    fix: "Except the permitted encumbrances by schedule or by reference to the title commitment's exception schedule.",
    sev: "critical",
  },
  {
    id: "RE-135",
    name: "Legal description of the property",
    cite: stateLaw(
      "legal-description",
      "sufficiency of legal descriptions for conveyances of real property",
      "https://www.law.cornell.edu/wex/deed",
    ),
    pat: [
      /(legal\s+description|more\s+particularly\s+described)/i,
      /(lot\s+\d|block\s+\d|metes\s+and\s+bounds|township|parcel\s+(no|number|id)|exhibit\s+[a-z])/i,
    ],
    why: "The description in the deed is what gets indexed and chained. A description that does not match the title commitment creates a gap the next examiner has to resolve.",
    fix: "Set out the full legal description, matching the title commitment exactly, and add the parcel number and address as supplemental identification.",
    sev: "critical",
  },
  {
    id: "RE-136",
    name: "Consideration and transfer-tax declaration",
    cite: stateLaw(
      "transfer-tax",
      "real estate transfer tax declarations and exemption statements",
      "https://www.law.cornell.edu/wex/transfer_tax",
    ),
    pat: [
      /(consideration|\$)/i,
      /(transfer\s+tax|documentary\s+(stamp|transfer)|exempt|revenue\s+stamps|affidavit\s+of\s+consideration)/i,
    ],
    why: "Transfer-tax declarations are a recording prerequisite in most counties, and an understated consideration is a tax matter separate from the conveyance.",
    fix: "Recite the consideration and complete the transfer-tax declaration or exemption statement the recording jurisdiction requires.",
  },
  {
    id: "RE-137",
    name: "Notarial acknowledgment and recording block",
    cite: stateLaw(
      "acknowledgment",
      "notarial acknowledgment requirements for recordable instruments",
      "https://www.law.cornell.edu/wex/notary_public",
    ),
    pat: [
      /(notary\s+public|acknowledged\s+before\s+me|state\s+of\s+\w+\s*,?\s*county\s+of)/i,
      /(after\s+recording\s+return\s+to|record(ing|ed)?\s+(requested|return)|mail\s+tax\s+statements)/i,
    ],
    why: "Without a conforming acknowledgment the deed cannot be recorded and gives no constructive notice, which defeats the buyer's priority against later purchasers and creditors.",
    fix: "Add the state's acknowledgment form with the notary's commission details and the recording-return and tax-statement addresses.",
    sev: "critical",
  },
]);

const RESIDENTIAL_PSA = pack("residential-purchase-agreement", C, [
  {
    id: "RE-138",
    name: "Earnest money and escrow holder",
    cite: practice("earnest-money", "earnest money deposits and escrow in residential purchases"),
    pat: [
      /earnest\s+money|good\s+faith\s+deposit/i,
      /(escrow|held\s+by|title\s+company|deposited\s+within)/i,
    ],
    why: "The deposit is the seller's only security and the buyer's largest exposure. Who holds it, when it must be delivered, and when it becomes non-refundable are the terms disputes are built on.",
    fix: "State the deposit amount, the delivery deadline, the escrow holder, and the conditions under which the deposit becomes non-refundable.",
    sev: "critical",
  },
  {
    id: "RE-139",
    name: "Financing and appraisal contingencies",
    cite: practice(
      "financing-contingency",
      "financing and appraisal contingencies in residential purchases",
    ),
    pat: [
      /(financ(e|ing)\s+contingenc|loan\s+contingenc|mortgage\s+contingenc)/i,
      /(apprais|loan\s+approval|days\s+to\s+obtain|waive[sd]?\s+the\s+financing)/i,
    ],
    why: "Waiving the financing contingency puts the deposit at risk if the loan fails; waiving the appraisal contingency puts the buyer on the hook for the shortfall in cash. Both need to be conscious decisions.",
    fix: "State the financing contingency with the loan type, amount, rate ceiling, and approval deadline, and state the appraisal contingency or its express waiver.",
    sev: "critical",
  },
  {
    id: "RE-140",
    name: "Inspection contingency and repair procedure",
    cite: practice("inspection-contingency", "inspection contingencies and repair negotiation"),
    pat: [
      /inspect/i,
      /(contingenc|repair\s+request|days\s+after\s+(the\s+)?(acceptance|effective\s+date)|right\s+to\s+(terminate|cancel))/i,
    ],
    why: "The inspection period is the buyer's only unconditional exit in most forms. Its length, whether termination is at the buyer's sole discretion, and what happens if the parties cannot agree on repairs are all separate terms.",
    fix: "State the inspection period, the buyer's right to terminate and recover the deposit, the repair-request procedure, and the outcome if no repair agreement is reached.",
  },
  {
    id: "RE-141",
    name: "Lead-based paint disclosure for pre-1978 housing",
    cite: usc(
      "42",
      "4852d",
      "Residential Lead-Based Paint Hazard Reduction Act — disclosure of known lead-based paint hazards",
    ),
    pat: [/lead-?based\s+paint/i, /(1978|disclosure|pamphlet|10-?day|protect\s+your\s+family)/i],
    why: "42 U.S.C. § 4852d and 24 C.F.R. Part 35 require a disclosure form, the EPA pamphlet, and a 10-day inspection opportunity for target housing. The penalty is treble damages, and the disclosure is a strict requirement.",
    fix: "Attach the lead-based paint disclosure and acknowledgment, confirm delivery of the EPA pamphlet, and give the 10-day assessment opportunity or the buyer's written waiver.",
    when: [
      /(built\s+(in\s+)?(19[0-7]|before\s+1978)|pre-?1978|lead-?based\s+paint|target\s+housing)/i,
    ],
    sev: "critical",
  },
  {
    id: "RE-142",
    name: "Seller property-condition disclosure",
    cite: stateLaw(
      "seller-disclosure",
      "statutory seller property condition disclosure statements",
      "https://www.law.cornell.edu/wex/caveat_emptor",
    ),
    pat: [
      /(seller'?s?\s+disclosure|property\s+condition\s+(disclosure|statement)|disclosure\s+statement)/i,
      /(known\s+(defects|material\s+facts)|material\s+defect|as\s+is)/i,
    ],
    why: "Nearly every state mandates a seller disclosure form for residential sales, and an omitted or false disclosure survives closing as a fraud claim regardless of an as-is clause.",
    fix: "Attach the state-mandated disclosure statement, confirm its delivery date, and state the buyer's rights if it is delivered late.",
    sev: "critical",
  },
  {
    id: "RE-143",
    name: "Title, survey, and permitted exceptions",
    cite: practice("title-review", "title and survey review in residential purchases"),
    pat: [
      /(title\s+(commitment|insurance|report)|preliminary\s+report)/i,
      /(survey|objection|permitted\s+exceptions|cure\s+the\s+title)/i,
    ],
    why: "The title objection process is the buyer's mechanism to force cure of a defect before closing. Without a deadline and a cure procedure, a title problem discovered late becomes a closing failure.",
    fix: "State who orders and pays for title and survey, the objection deadline, the seller's cure period, and the buyer's remedy if the defect is not cured.",
  },
  {
    id: "RE-144",
    name: "Closing date, possession, and prorations",
    cite: practice("closing-prorations", "closing, possession, and proration terms"),
    pat: [
      /(closing\s+date|settlement\s+date)/i,
      /(possession|prorat|taxes\s+(shall\s+be\s+)?prorated|occupancy)/i,
    ],
    why: "Possession delivered other than at closing needs its own agreement and insurance; prorations of taxes, HOA dues, and utilities decide who pays for the period straddling the closing.",
    fix: "State the closing date, when possession transfers, the proration method and date, and any post-closing occupancy agreement.",
  },
  {
    id: "RE-145",
    name: "Default remedies and liquidated damages",
    cite: practice(
      "psa-default",
      "default remedies and liquidated damages in residential purchase contracts",
    ),
    pat: [
      /(default|breach)/i,
      /(liquidated\s+damages|specific\s+performance|retain\s+the\s+(earnest\s+money|deposit)|sole\s+remedy)/i,
    ],
    why: "A liquidated damages clause capping the seller's recovery at the deposit is enforceable in most states only if separately initialed or conspicuous, and specific performance is the buyer's usual remedy.",
    fix: "State each party's remedies on default, whether the deposit is liquidated damages, and satisfy any separate-initialing or conspicuousness requirement.",
  },
]);

const WORK_LETTER = pack("tenant-improvement-work-letter", C, [
  {
    id: "RE-146",
    name: "Allowance amount, draw process, and deadline",
    cite: practice("ti-allowance", "tenant improvement allowances and draw procedures"),
    pat: [
      /(tenant\s+improvement\s+allowance|ti\s+allowance|improvement\s+allowance)/i,
      /(draw|disburs|invoice|lien\s+waiver|deadline|forfeit)/i,
    ],
    why: "Allowances routinely expire unused because the draw conditions and deadline were never read. Unused allowance is landlord money the tenant paid for in rent.",
    fix: "State the allowance amount, the documentation each draw requires, the disbursement timing, the deadline to use it, and whether unused amounts convert to rent credit.",
    sev: "critical",
  },
  {
    id: "RE-147",
    name: "Scope split between landlord's and tenant's work",
    cite: practice("work-letter-scope", "allocation of construction scope in work letters"),
    pat: [
      /landlord'?s?\s+work/i,
      /(tenant'?s?\s+work|base\s+building|turn-?key|shell\s+condition)/i,
    ],
    why: "Every item not assigned to one party becomes a change order. Base-building condition — HVAC capacity, sprinklers, ADA path of travel, demising walls — is where the arguments concentrate.",
    fix: "Attach the base building definition and a responsibility matrix assigning each scope item to the landlord or the tenant.",
  },
  {
    id: "RE-148",
    name: "Plan approval timeline and deemed approval",
    cite: practice("plan-approval", "plan submission and approval deadlines in work letters"),
    pat: [
      /(space\s+plan|construction\s+drawings|working\s+drawings|plans\s+and\s+specifications)/i,
      /(approv|deemed\s+approved|business\s+days|shall\s+respond\s+within)/i,
    ],
    why: "Landlord review with no deadline is the most common cause of delivery delay, and delay without a deemed-approval backstop pushes rent commencement onto the tenant.",
    fix: "Set submission and response deadlines with a deemed-approval consequence, and limit the grounds on which the landlord may disapprove.",
  },
  {
    id: "RE-149",
    name: "Tenant-delay definition and rent commencement",
    cite: practice("tenant-delay", "tenant delay and rent commencement in work letters"),
    pat: [
      /tenant\s+delay/i,
      /(rent\s+commencement|substantial\s+completion|deemed\s+(delivered|substantially\s+complete)|day-?for-?day)/i,
    ],
    why: "Tenant delay accelerates rent commencement to the date the space would have been ready. An open-ended definition lets the landlord charge rent on a space the tenant cannot occupy.",
    fix: "Define tenant delay narrowly with a notice requirement, and state its precise effect on the delivery date and rent commencement.",
    sev: "critical",
  },
  {
    id: "RE-150",
    name: "Change orders and cost overruns",
    cite: practice("work-letter-change", "change order procedure and overrun responsibility"),
    pat: [
      /change\s+order/i,
      /(cost\s+overrun|excess\s+cost|in\s+excess\s+of\s+the\s+allowance|tenant\s+shall\s+pay)/i,
    ],
    why: "Overruns are the tenant's, and the payment timing (before the landlord funds, or on completion) is a working-capital term the tenant needs to know before construction starts.",
    fix: "State the change-order procedure with pricing and approval deadlines, and when the tenant must deposit or pay costs exceeding the allowance.",
  },
]);

export const V5_REAL_ESTATE_RULES: readonly Rule[] = [
  ...SUBLEASE,
  ...LEASE_LOI,
  ...PROPERTY_MGMT,
  ...LISTING,
  ...OPTION,
  ...QUITCLAIM,
  ...WARRANTY_DEED,
  ...RESIDENTIAL_PSA,
  ...WORK_LETTER,
];
