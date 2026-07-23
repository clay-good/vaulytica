/**
 * v4 Real-estate ruleset — 60 rules (spec-v4.md §6.E, Step 48).
 *
 * Eight playbooks: net lease (NNN single-tenant), real-estate PSA,
 * ground lease, easement, CC&Rs, estoppel certificate, SNDA, lease
 * assignment. Citations anchor to URLTA, state landlord-tenant codes,
 * the Statute of Frauds, state recording acts, the Uniform Easement
 * Relocation Act / Restatement of Property, state HOA statutes, and
 * IRC § 1031 like-kind-exchange treatment.
 *
 * Rule ids are flat `RE-NNN` (001..060); each rule's
 * `applies_to_playbooks` restricts execution.
 */

import type { Rule } from "../../../finding.js";
import {
  buildV4PresenceRule,
  buildV4LanguageRule,
  type V4PresenceSpec,
  type V4LanguageSpec,
} from "../_helpers.js";
import {
  RE_PLAYBOOK_NET_LEASE,
  RE_PLAYBOOK_PSA,
  RE_PLAYBOOK_GROUND_LEASE,
  RE_PLAYBOOK_EASEMENT,
  RE_PLAYBOOK_CCR,
  RE_PLAYBOOK_ESTOPPEL,
  RE_PLAYBOOK_SNDA,
  RE_PLAYBOOK_LEASE_ASSIGN,
  stateLT,
  statuteOfFrauds,
  recordingAct,
  easementLaw,
  hoaStatutes,
  irc1031,
  rePractice,
} from "./_helpers.js";

const CATEGORY = "real-estate";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });
const language = (s: Omit<V4LanguageSpec, "category">): Rule =>
  buildV4LanguageRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// E.2 — Single-Tenant Net Lease (NNN). 8 rules: RE-001..RE-008.
// ────────────────────────────────────────────────────────────────────

const NET_LEASE_RULES: Rule[] = [
  presence({
    id: "RE-001",
    name: "Triple-net (NNN) cost allocation stated",
    description:
      "Net lease must specify which expenses (real estate taxes, insurance, CAM / operating expenses) pass through to tenant.",
    citation: rePractice(
      "nnn-baseline",
      "Single-tenant NNN lease practice baseline",
      "https://www.americanbar.org/groups/real_property_trust_estate/",
    ),
    playbooks: [RE_PLAYBOOK_NET_LEASE],
    missing_title: "NNN cost-allocation clause missing",
    missing_description:
      "No clause was found allocating real-estate taxes, insurance, and operating expenses to the tenant.",
    explanation:
      "The economic essence of a NNN lease is tenant assumption of three expense categories. Silence converts the lease to gross by default.",
    recommendation:
      "Add 'Additional Rent' clauses identifying real-estate taxes, property insurance, and CAM / operating expenses as tenant's responsibility.",
    present_patterns: [
      /triple.net/i,
      /\bnnn\b/i,
      /real\s+estate\s+taxes?.{0,80}(tenant)/is,
      /(cam|common\s+area\s+maintenance|operating\s+expenses)/i,
    ],
  }),
  presence({
    id: "RE-002",
    name: "Real-estate-tax pass-through mechanics",
    description:
      "Net lease should specify whether taxes are paid directly by tenant or reimbursed.",
    citation: rePractice(
      "nnn-taxes",
      "NNN tax pass-through mechanics",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_NET_LEASE],
    missing_title: "Tax pass-through mechanics missing",
    missing_description:
      "No clause was found specifying how real-estate taxes are paid (direct or reimbursement).",
    explanation:
      "Direct payment shifts tax-bill risk; reimbursement keeps landlord on the bill and creates timing disputes.",
    recommendation:
      "Add a 'Taxes' clause specifying direct payment or estimated-and-reconciled reimbursement.",
    present_patterns: [/real\s+estate\s+taxes?/i, /(impositions|property\s+taxes)/i],
    default_severity: "warning",
  }),
  presence({
    id: "RE-003",
    name: "Insurance requirements (liability + property)",
    description:
      "NNN lease must specify tenant insurance: CGL with minimum limits, property insurance, waiver of subrogation.",
    citation: rePractice(
      "nnn-insurance",
      "NNN tenant insurance baseline",
      "https://www.americanbar.org/groups/real_property_trust_estate/",
    ),
    playbooks: [RE_PLAYBOOK_NET_LEASE],
    missing_title: "Insurance requirements clause missing",
    missing_description: "No tenant insurance clause was found.",
    explanation:
      "Without minimums and waiver of subrogation, landlord's coverage stack is exposed.",
    recommendation:
      "Add 'Insurance' specifying CGL minimums ($1M / $2M typical), property insurance, additional-insured / loss-payee, and waiver of subrogation.",
    present_patterns: [
      /commercial\s+general\s+liability/i,
      /property\s+insurance/i,
      /waiver\s+of\s+subrogation/i,
    ],
  }),
  presence({
    id: "RE-004",
    name: "Maintenance and repair obligations",
    description:
      "Single-tenant NNN puts maintenance / repair on tenant; landlord typically retains only structural / roof obligations.",
    citation: rePractice(
      "nnn-maintenance",
      "NNN maintenance allocation",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_NET_LEASE],
    missing_title: "Maintenance / repair clause missing",
    missing_description: "No maintenance / repair allocation clause was found.",
    explanation:
      "Allocation between roof / structure (landlord) and everything else (tenant) is the heart of a single-tenant NNN.",
    recommendation:
      "Add 'Maintenance and Repair' specifying landlord's structural / roof obligations and tenant's responsibility for everything else.",
    present_patterns: [
      /maintenance\s+and\s+repair/i,
      /(roof|structural)\s+(integrity|repair|maintenance)/i,
    ],
  }),
  presence({
    id: "RE-005",
    name: "CAM / operating-expense audit right",
    description: "Tenant should have a CAM / operating-expense audit right.",
    citation: rePractice(
      "nnn-cam-audit",
      "Tenant CAM audit-right practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_NET_LEASE],
    missing_title: "Tenant CAM-audit right missing",
    missing_description: "No tenant CAM / operating-expense audit right was found.",
    explanation:
      "Practice baseline: tenant has a 12-month window to audit and a discrepancy-trigger reimbursement.",
    recommendation:
      "Add 'Audit Right' giving tenant a 12-month audit window and a discrepancy-trigger fee allocation.",
    present_patterns: [
      /audit\s+right/i,
      /tenant.{0,40}audit/is,
      /(twelve|12)\s+months?.{0,40}(audit|inspect)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "RE-006",
    name: "Casualty and condemnation",
    description: "Net lease must address damage / destruction and condemnation.",
    citation: rePractice(
      "nnn-casualty",
      "NNN casualty / condemnation practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_NET_LEASE],
    missing_title: "Casualty / condemnation clause missing",
    missing_description: "No casualty or condemnation clause was found.",
    explanation:
      "Allocation of rebuild obligation and termination rights on partial / total casualty is essential to a NNN lease.",
    recommendation: "Add 'Damage and Destruction' and 'Condemnation' sections.",
    present_patterns: [
      /(casualty|damage\s+and\s+destruction|fire\s+and\s+other\s+casualty)/i,
      /condemnation/i,
      /eminent\s+domain/i,
    ],
  }),
  presence({
    id: "RE-007",
    name: "Right to relet / mitigate damages on default",
    description: "Landlord remedies should address relet / mitigation duty per state law.",
    citation: stateLT(),
    playbooks: [RE_PLAYBOOK_NET_LEASE],
    missing_title: "Relet / mitigation clause missing",
    missing_description: "No relet / mitigation clause was found.",
    explanation:
      "Many states impose a mitigation duty on landlords; the lease should acknowledge or restate it.",
    recommendation: "Add 'Default Remedies' covering relet and mitigation obligations.",
    present_patterns: [/relet/i, /(mitigation|mitigate).{0,40}damages/is],
    default_severity: "warning",
  }),
  presence({
    id: "RE-008",
    name: "Holdover and surrender",
    description: "Net lease should address holdover rent multiplier and surrender condition.",
    citation: rePractice(
      "nnn-holdover",
      "NNN holdover / surrender practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_NET_LEASE],
    missing_title: "Holdover / surrender clause missing",
    missing_description: "No holdover or surrender clause was found.",
    explanation:
      "Practice baseline: holdover at 150–200% rent, surrender in good condition with restoration obligations.",
    recommendation:
      "Add 'Holdover' (150–200% multiplier) and 'Surrender' with restoration / removal-of-trade-fixtures language.",
    present_patterns: [/holdover/i, /surrender/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// E.4 — Real-Estate Purchase and Sale Agreement (PSA). 9 rules: RE-009..RE-017.
// ────────────────────────────────────────────────────────────────────

const PSA_RULES: Rule[] = [
  presence({
    id: "RE-009",
    name: "Property description / legal description",
    description: "PSA must include a legal description of the property (Statute of Frauds).",
    citation: statuteOfFrauds(),
    playbooks: [RE_PLAYBOOK_PSA],
    missing_title: "Legal property description missing",
    missing_description: "No legal property description was found.",
    explanation:
      "Statute of Frauds requires that a real-property contract identify the property with reasonable certainty. Practice baseline: legal description in an exhibit.",
    recommendation: "Add 'Property' with an Exhibit A legal description.",
    present_patterns: [
      /legal\s+description/i,
      /(real\s+property|the\s+property)\s+(described\s+(in|on)|located\s+at)/i,
      /exhibit\s+[a-z].{0,40}legal\s+description/is,
    ],
  }),
  presence({
    id: "RE-010",
    name: "Purchase price and earnest money",
    description: "PSA must state purchase price and earnest-money deposit.",
    citation: rePractice(
      "psa-earnest-money",
      "PSA earnest-money practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_PSA],
    missing_title: "Purchase price / earnest money clause missing",
    missing_description: "No purchase-price or earnest-money clause was found.",
    explanation:
      "Earnest-money structure (refundable vs non-refundable, escrow, hard / soft) is central to PSA economics.",
    recommendation:
      "Add 'Purchase Price' and 'Earnest Money' specifying amount, escrow, refundable / hard-money tiers.",
    present_patterns: [/purchase\s+price/i, /earnest\s+money/i, /deposit/i],
  }),
  presence({
    id: "RE-011",
    name: "Due diligence / inspection period",
    description: "PSA must include a due diligence / inspection / feasibility period.",
    citation: rePractice(
      "psa-due-diligence",
      "PSA due-diligence period practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_PSA],
    missing_title: "Due-diligence period clause missing",
    missing_description: "No due-diligence period clause was found.",
    explanation:
      "Practice baseline: 30–60 day due-diligence period during which buyer may terminate.",
    recommendation:
      "Add 'Due Diligence Period' with a defined window and buyer's right to terminate.",
    present_patterns: [
      /due\s+diligence\s+period/i,
      /inspection\s+period/i,
      /feasibility\s+period/i,
    ],
  }),
  presence({
    id: "RE-012",
    name: "Title commitment / title objections",
    description: "PSA must address title commitment and the cure mechanism for title objections.",
    citation: rePractice(
      "psa-title",
      "PSA title commitment / objections practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_PSA],
    missing_title: "Title commitment / objections clause missing",
    missing_description: "No title-commitment or objection-cure clause was found.",
    explanation:
      "Standard pattern: buyer obtains a title commitment, identifies objections within X days, seller has Y days to cure.",
    recommendation:
      "Add 'Title' specifying commitment, survey, objection / cure mechanics, and permitted exceptions.",
    present_patterns: [/title\s+commitment/i, /title\s+objection/i, /permitted\s+exceptions/i],
  }),
  presence({
    id: "RE-013",
    name: "Closing conditions",
    description: "PSA must specify closing conditions for both buyer and seller.",
    citation: rePractice(
      "psa-closing-conditions",
      "PSA closing-conditions practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_PSA],
    missing_title: "Closing-conditions clause missing",
    missing_description: "No closing-conditions clause was found.",
    explanation:
      "Practice baseline: bring-down of reps, performance of covenants, no material change, title insurance available.",
    recommendation:
      "Add 'Conditions to Closing' with bring-down, performance, no-MAC, and title-insurance conditions.",
    present_patterns: [/conditions?\s+to\s+closing/i, /closing\s+conditions/i],
  }),
  presence({
    id: "RE-014",
    name: "Risk of loss before closing",
    description: "PSA must address risk of loss before closing.",
    citation: rePractice(
      "psa-risk-of-loss",
      "PSA risk-of-loss practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_PSA],
    missing_title: "Risk-of-loss clause missing",
    missing_description: "No risk-of-loss clause was found.",
    explanation:
      "State law on risk allocation pre-closing varies (UVPRA vs common-law equitable conversion).",
    recommendation:
      "Add 'Risk of Loss' specifying treatment of casualty and condemnation between contract and closing.",
    present_patterns: [
      /risk\s+of\s+loss/i,
      /(casualty|condemnation).{0,80}(prior\s+to\s+closing|before\s+closing)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "RE-015",
    name: "Seller representations and warranties",
    description:
      "PSA should include core seller reps (authority, no defaults under leases, environmental, litigation).",
    citation: rePractice("psa-reps", "PSA seller reps practice", "https://www.americanbar.org/"),
    playbooks: [RE_PLAYBOOK_PSA],
    missing_title: "Seller-rep clause missing",
    missing_description: "No seller representations clause was found.",
    explanation:
      "Even AS-IS sales include a baseline rep package: authority, no leases, no notices of violation.",
    recommendation:
      "Add 'Representations and Warranties of Seller' covering authority, leases / contracts, environmental, and litigation.",
    present_patterns: [
      /representations?\s+(and\s+)?warranties\s+of\s+seller/i,
      /seller\s+represents/i,
    ],
  }),
  presence({
    id: "RE-016",
    name: "Like-kind exchange cooperation (IRC § 1031)",
    description:
      "PSA should address whether parties will cooperate with a § 1031 like-kind exchange.",
    citation: irc1031(),
    playbooks: [RE_PLAYBOOK_PSA],
    missing_title: "§ 1031 cooperation clause missing",
    missing_description: "No § 1031 cooperation clause was found.",
    explanation:
      "Many sellers structure as forward / reverse § 1031 exchanges; buyer cooperation is the standard.",
    recommendation:
      "Add 'Section 1031 Exchange' with mutual cooperation and a no-cost-to-cooperating-party limit.",
    present_patterns: [/(section\s+1031|like.kind\s+exchange|1031\s+exchange)/i],
    default_severity: "warning",
  }),
  presence({
    id: "RE-017",
    name: "Brokers / commission representation",
    description: "PSA should include broker / commission representations and indemnification.",
    citation: rePractice(
      "psa-broker",
      "PSA broker rep / indemnification practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_PSA],
    missing_title: "Brokers clause missing",
    missing_description: "No brokers / commission clause was found.",
    explanation:
      "Each side represents which brokers it dealt with and indemnifies the other for additional commissions.",
    recommendation: "Add 'Brokers' with reciprocal reps and indemnification.",
    present_patterns: [/(broker|commission)/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// E.5 — Ground Lease. 7 rules: RE-018..RE-024.
// ────────────────────────────────────────────────────────────────────

const GROUND_LEASE_RULES: Rule[] = [
  presence({
    id: "RE-018",
    name: "Long-term term stated (49 / 50 / 99 years)",
    description: "Ground lease should state a long-term term (typically 49, 50, or 99 years).",
    citation: rePractice(
      "ground-lease-term",
      "Ground lease term practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_GROUND_LEASE],
    missing_title: "Long-term term clause missing",
    missing_description: "No clause was found stating a long-term ground-lease term.",
    explanation:
      "Practice baseline: ground leases run 49 / 50 / 99 years to amortize tenant's improvements.",
    recommendation: "Add 'Term' stating the initial term (typically 49, 50, or 99 years).",
    present_patterns: [/(49|50|99)\s+years/i, /(forty.nine|fifty|ninety.nine)\s+years/i],
  }),
  presence({
    id: "RE-019",
    name: "Tenant's right to construct / improvements",
    description: "Ground lease should specify tenant's right to construct improvements.",
    citation: rePractice(
      "ground-lease-construction",
      "Ground lease tenant construction rights",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_GROUND_LEASE],
    missing_title: "Construction rights clause missing",
    missing_description: "No clause was found specifying tenant's right to construct improvements.",
    explanation:
      "Ground leases turn on tenant's right to develop. Standard pattern: tenant may construct subject to plan approval.",
    recommendation:
      "Add 'Improvements' specifying construction rights, plan-approval mechanic, and contractor / insurance requirements.",
    present_patterns: [/tenant.{0,40}(construct|improvements?|build)/is, /right\s+to\s+construct/i],
  }),
  presence({
    id: "RE-020",
    name: "Leasehold mortgage (lender protection)",
    description: "Ground lease should permit leasehold mortgages and include lender protections.",
    citation: rePractice(
      "ground-lease-mortgage",
      "Leasehold mortgage / lender-protection practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_GROUND_LEASE],
    missing_title: "Leasehold mortgage / lender protections missing",
    missing_description:
      "No clause was found permitting leasehold mortgages or protecting leasehold lenders.",
    explanation:
      "Tenant's construction financing depends on leasehold-mortgage rights and lender protections (notice + cure, new-lease right).",
    recommendation:
      "Add 'Leasehold Mortgage' with permission, notice-and-cure rights, and new-lease right on tenant default.",
    present_patterns: [/leasehold\s+mortgage/i, /leasehold\s+lender/i, /new.?lease\s+right/i],
  }),
  presence({
    id: "RE-021",
    name: "Reversion / ownership of improvements at expiration",
    description: "Ground lease must address what happens to improvements at term expiration.",
    citation: rePractice(
      "ground-lease-reversion",
      "Ground lease reversion practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_GROUND_LEASE],
    missing_title: "Reversion clause missing",
    missing_description: "No reversion / improvements-at-expiration clause was found.",
    explanation:
      "Practice baseline: improvements revert to landlord at expiration; some leases require tenant to remove.",
    recommendation: "Add 'Reversion' specifying ownership of improvements at expiration.",
    present_patterns: [
      /(revert|reversion).{0,80}improvements/is,
      /improvements.{0,40}(revert|surrender)/is,
      /title\s+to\s+improvements/i,
    ],
  }),
  presence({
    id: "RE-022",
    name: "Rent escalation / CPI / market reset",
    description: "Ground leases include rent escalators (CPI, fixed steps, or market-rent resets).",
    citation: rePractice(
      "ground-lease-escalation",
      "Ground lease rent escalation practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_GROUND_LEASE],
    missing_title: "Rent escalation / reset clause missing",
    missing_description: "No rent-escalation clause was found.",
    explanation: "A 99-year flat-rent lease is anti-economical; long-term rent must adjust.",
    recommendation:
      "Add 'Rent Escalation' with CPI escalator, fixed steps, or periodic market resets.",
    present_patterns: [
      /(cpi|consumer\s+price\s+index)/i,
      /rent\s+adjustment/i,
      /market\s+rent\s+reset/i,
      /fair\s+market\s+rent/i,
    ],
  }),
  presence({
    id: "RE-023",
    name: "Assignment and subletting",
    description: "Ground lease should address assignment / subletting consent.",
    citation: rePractice(
      "ground-lease-assignment",
      "Ground lease assignment / subletting practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_GROUND_LEASE],
    missing_title: "Assignment / subletting clause missing",
    missing_description: "No assignment or subletting clause was found.",
    explanation:
      "Ground leases typically allow assignment without consent (or with consent not unreasonably withheld) to keep collateral marketable.",
    recommendation:
      "Add 'Assignment and Subletting' with a consent standard and permitted-assignment carve-outs.",
    present_patterns: [/assign(ment)?\s+(and|or)\s+sublet/i, /transfer.{0,40}leasehold/is],
    default_severity: "warning",
  }),
  presence({
    id: "RE-024",
    name: "Memorandum of lease to be recorded",
    description: "Ground leases commonly record a memorandum of lease.",
    citation: recordingAct(),
    playbooks: [RE_PLAYBOOK_GROUND_LEASE],
    missing_title: "Memorandum-of-lease clause missing",
    missing_description: "No memorandum-of-lease clause was found.",
    explanation:
      "A recorded memorandum gives constructive notice of the leasehold interest; standard for long-term leases.",
    recommendation: "Add 'Memorandum of Lease' authorizing recording of a short-form memorandum.",
    present_patterns: [/memorandum\s+of\s+lease/i, /short.form\s+memorandum/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// E.6 — Easement Agreement. 7 rules: RE-025..RE-031.
// ────────────────────────────────────────────────────────────────────

const EASEMENT_RULES: Rule[] = [
  presence({
    id: "RE-025",
    name: "Servient and dominant tenement identified",
    description:
      "Easement agreement must identify servient (burdened) and dominant (benefited) parcels.",
    citation: easementLaw(),
    playbooks: [RE_PLAYBOOK_EASEMENT],
    missing_title: "Servient / dominant tenement clause missing",
    missing_description: "No clause was found identifying the servient and dominant parcels.",
    explanation:
      "Easements appurtenant require both parcels to be identified; easements in gross identify only the burdened parcel.",
    recommendation:
      "Add 'Servient Tenement' and 'Dominant Tenement' (or for easements in gross, 'Easement in Gross') with legal descriptions.",
    present_patterns: [/(servient|dominant)\s+(tenement|estate|parcel)/i, /easement\s+in\s+gross/i],
  }),
  presence({
    id: "RE-026",
    name: "Easement type stated (appurtenant vs in gross; affirmative vs negative)",
    description: "Easement agreement should state the type of easement.",
    citation: easementLaw(),
    playbooks: [RE_PLAYBOOK_EASEMENT],
    missing_title: "Easement-type clause missing",
    missing_description: "No clause was found specifying the easement type.",
    explanation:
      "Easement type determines transferability, scope, and termination — must be stated.",
    recommendation:
      "Add 'Nature of Easement' (appurtenant / in gross; affirmative / negative; exclusive / non-exclusive).",
    present_patterns: [
      /(appurtenant|in\s+gross)/i,
      /(affirmative|negative)\s+easement/i,
      /(exclusive|non.exclusive)\s+easement/i,
    ],
  }),
  presence({
    id: "RE-027",
    name: "Scope of use",
    description: "Easement must define scope of use (purpose, intensity, vehicles, hours).",
    citation: easementLaw(),
    playbooks: [RE_PLAYBOOK_EASEMENT],
    missing_title: "Scope-of-use clause missing",
    missing_description: "No scope-of-use clause was found.",
    explanation: "Scope is the most litigated easement issue; specificity is protective.",
    recommendation:
      "Add 'Scope and Use' specifying purpose, intensity, vehicles / pedestrians, and any time restrictions.",
    present_patterns: [
      /scope\s+(of\s+)?use/i,
      /purpose\s+of\s+(the\s+)?easement/i,
      /permitted\s+uses?/i,
    ],
  }),
  presence({
    id: "RE-028",
    name: "Maintenance and repair allocation",
    description: "Easement should allocate maintenance and repair costs.",
    citation: easementLaw(),
    playbooks: [RE_PLAYBOOK_EASEMENT],
    missing_title: "Maintenance / repair allocation clause missing",
    missing_description: "No maintenance / repair allocation clause was found.",
    explanation:
      "Without explicit allocation, courts default to use-proportional or beneficiary-pays — frequent disputes.",
    recommendation: "Add 'Maintenance and Repair' with cost allocation and trigger events.",
    present_patterns: [/maintenance\s+(and|or)\s+repair/i],
  }),
  presence({
    id: "RE-029",
    name: "Indemnification and insurance",
    description: "Easement should include indemnification and insurance covenant.",
    citation: rePractice(
      "easement-insurance",
      "Easement indemnification / insurance practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_EASEMENT],
    missing_title: "Indemnification / insurance clause missing",
    missing_description: "No indemnification or insurance clause was found.",
    explanation:
      "Use of the servient parcel creates liability exposure that the dominant owner should indemnify.",
    recommendation:
      "Add 'Indemnification' from dominant owner + minimum liability insurance with servient owner as additional insured.",
    present_patterns: [/indemnif/i, /(insurance|insured)/i],
    default_severity: "warning",
  }),
  presence({
    id: "RE-030",
    name: "Term / termination conditions",
    description: "Easement should state term (perpetual vs term) and termination triggers.",
    citation: easementLaw(),
    playbooks: [RE_PLAYBOOK_EASEMENT],
    missing_title: "Term / termination clause missing",
    missing_description: "No term / termination clause was found.",
    explanation:
      "Easements may be perpetual, for a term of years, or terminable on specified events. Silence creates litigation.",
    recommendation:
      "Add 'Term' specifying duration (perpetual or years) and termination triggers (abandonment, merger of title, expiration).",
    present_patterns: [
      /(perpetual|in\s+perpetuity)/i,
      /termin(ate|ation).{0,80}easement/is,
      /abandonment/i,
    ],
  }),
  presence({
    id: "RE-031",
    name: "Recording covenant",
    description: "Easement must be recorded to bind successors (state recording acts).",
    citation: recordingAct(),
    playbooks: [RE_PLAYBOOK_EASEMENT],
    missing_title: "Recording covenant clause missing",
    missing_description: "No recording-covenant clause was found.",
    explanation:
      "Recording is required for the easement to run with the land against subsequent purchasers (race / notice / race-notice).",
    recommendation:
      "Add 'Recording' covenant requiring the easement to be recorded in the public records.",
    present_patterns: [
      /recorded?\s+in\s+(the\s+)?(public\s+)?records/i,
      /(record|recording).{0,40}(public|county)/is,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// E.7 — CC&Rs. 8 rules: RE-032..RE-039.
// ────────────────────────────────────────────────────────────────────

const CCR_RULES: Rule[] = [
  presence({
    id: "RE-032",
    name: "Declaration of CC&Rs identification",
    description:
      "CC&Rs must identify themselves as a Declaration of Covenants, Conditions, and Restrictions.",
    citation: hoaStatutes(),
    playbooks: [RE_PLAYBOOK_CCR],
    missing_title: "CC&Rs identification missing",
    missing_description:
      "No 'Declaration of Covenants, Conditions, and Restrictions' identification was found.",
    explanation:
      "State HOA statutes (e.g., Davis-Stirling Act in CA) require specific naming conventions for the recorded declaration.",
    recommendation: "Title the document 'Declaration of Covenants, Conditions, and Restrictions'.",
    present_patterns: [
      /covenants,?\s+conditions(,?\s+and)?\s+restrictions/i,
      /\bcc.?rs?\b/i,
      /declaration\s+of\s+covenants/i,
    ],
  }),
  presence({
    id: "RE-033",
    name: "HOA / association formation",
    description: "CC&Rs typically create an owners association and assign powers.",
    citation: hoaStatutes(),
    playbooks: [RE_PLAYBOOK_CCR],
    missing_title: "HOA formation clause missing",
    missing_description: "No HOA / owners-association formation clause was found.",
    explanation:
      "State HOA statutes presume an association; CC&Rs should formalize its formation and powers.",
    recommendation:
      "Add 'Association' creating the homeowners / owners association and identifying its powers.",
    present_patterns: [/homeowners.?\s+association/i, /owners?\s+association/i, /\bhoa\b/i],
  }),
  presence({
    id: "RE-034",
    name: "Assessment and lien rights",
    description: "CC&Rs must address assessments and lien rights against delinquent owners.",
    citation: hoaStatutes(),
    playbooks: [RE_PLAYBOOK_CCR],
    missing_title: "Assessment / lien rights clause missing",
    missing_description: "No assessment or lien-rights clause was found.",
    explanation: "Assessments fund the association; without lien rights they are uncollectable.",
    recommendation:
      "Add 'Assessments and Liens' specifying assessment authority, special assessments, and the lien procedure under state HOA law.",
    present_patterns: [/assessment/i, /lien.{0,40}(delinquent|unpaid|owners?)/is],
  }),
  presence({
    id: "RE-035",
    name: "Use restrictions / architectural standards",
    description: "CC&Rs must specify use restrictions and any architectural-control standards.",
    citation: hoaStatutes(),
    playbooks: [RE_PLAYBOOK_CCR],
    missing_title: "Use restrictions / architectural-control clause missing",
    missing_description: "No use-restrictions or architectural-control clause was found.",
    explanation:
      "The substantive heart of CC&Rs is use restrictions and architectural control; both should be enumerated.",
    recommendation:
      "Add 'Use Restrictions' and 'Architectural Control' covering permitted uses, prohibited uses, and the approval process for changes.",
    present_patterns: [
      /use\s+restrictions?/i,
      /(architectural\s+control|review)/i,
      /(prohibited|permitted)\s+uses?/i,
    ],
  }),
  presence({
    id: "RE-036",
    name: "Amendment procedure (supermajority)",
    description: "CC&Rs should specify amendment procedure (typically supermajority of owners).",
    citation: hoaStatutes(),
    playbooks: [RE_PLAYBOOK_CCR],
    missing_title: "Amendment procedure clause missing",
    missing_description: "No amendment procedure was found.",
    explanation:
      "State HOA statutes default to specified supermajority (e.g., 67% or 75%); CC&Rs typically restate or modify.",
    recommendation:
      "Add 'Amendment' specifying the required supermajority and recording requirements for amendments.",
    present_patterns: [/amendment.{0,40}declaration/is, /supermajority/i, /(67|75|80)\s*%/i],
  }),
  presence({
    id: "RE-037",
    name: "Term / duration of restrictions",
    description:
      "CC&Rs should specify term (perpetual or set years) and automatic-extension mechanic.",
    citation: hoaStatutes(),
    playbooks: [RE_PLAYBOOK_CCR],
    missing_title: "Term / duration clause missing",
    missing_description: "No term clause was found.",
    explanation:
      "Many state statutes impose a sunset (e.g., 30 years with automatic extension); CC&Rs should restate.",
    recommendation: "Add 'Term' specifying duration and automatic-renewal mechanism.",
    present_patterns: [
      /(perpetual|in\s+perpetuity)/i,
      /(30|50)\s+year.{0,40}term/is,
      /automatic\s+renewal/i,
    ],
    default_severity: "warning",
  }),
  language({
    id: "RE-038",
    name: "Race / discriminatory covenant flagged",
    description:
      "Discriminatory covenants based on race, color, religion, sex, familial status, national origin, or disability are unenforceable (Shelley v. Kraemer; FHA 42 U.S.C. § 3604).",
    citation: rePractice(
      "fair-housing-act",
      "42 U.S.C. § 3604 (Fair Housing Act); Shelley v. Kraemer, 334 U.S. 1 (1948)",
      "https://www.law.cornell.edu/uscode/text/42/3604",
    ),
    playbooks: [RE_PLAYBOOK_CCR],
    bad_patterns: [
      /(no|not).{0,40}(african|asian|black|hispanic|jewish|negro|persons\s+of\s+color)/is,
      /restricted\s+to\s+(persons\s+of\s+the\s+)?caucasian/is,
    ],
    // The bad_patterns are proximity-only, so a modern fair-housing compliance
    // or repudiation clause ("occupancy shall not be denied to any person who
    // is Black …", "any prior restriction purporting to exclude such persons is
    // void") trips the same `no/not` + protected-class window as the covenant
    // it repudiates. Accusing the remediation clause of being the covenant is
    // the worst false accusation this rule can make.
    exclude_if: [
      /\bfair\s+housing\b/i,
      /shall\s+not\s+be\s+denied/i,
      /purport(?:ing|s)?\s+to\s+(?:exclude|restrict|discriminate)/i,
      /\bvoid\b[^.]{0,60}(?:force|effect|unenforceable)/i,
    ],
    bad_title: "Discriminatory restrictive covenant flagged",
    bad_description:
      "The CC&Rs appear to contain a discriminatory covenant based on race, color, religion, or national origin.",
    explanation:
      "Such covenants are unenforceable per *Shelley v. Kraemer* and violate 42 U.S.C. § 3604.",
    recommendation:
      "Strike the discriminatory covenant entirely; some states require recordation of a fair-housing rider disclaiming any such legacy language.",
    default_severity: "critical",
  }),
  presence({
    id: "RE-039",
    name: "Dispute resolution / enforcement",
    description: "CC&Rs should specify dispute resolution / enforcement procedure.",
    citation: hoaStatutes(),
    playbooks: [RE_PLAYBOOK_CCR],
    missing_title: "Dispute-resolution clause missing",
    missing_description: "No dispute-resolution or enforcement clause was found.",
    explanation:
      "State HOA statutes increasingly require pre-suit ADR (e.g., Davis-Stirling § 5925); the CC&Rs should restate the process.",
    recommendation:
      "Add 'Dispute Resolution' including mandatory ADR / mediation before litigation.",
    present_patterns: [
      /dispute\s+resolution/i,
      /(alternative\s+dispute\s+resolution|adr)/i,
      /mediation/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// E.8 — Estoppel Certificate. 6 rules: RE-040..RE-045.
// ────────────────────────────────────────────────────────────────────

const ESTOPPEL_RULES: Rule[] = [
  presence({
    id: "RE-040",
    name: "Lease identification (parties / dates / amendments)",
    description: "Estoppel certificate must identify the lease (parties, dates, amendments).",
    citation: rePractice(
      "estoppel-baseline",
      "Estoppel certificate baseline content",
      "https://www.americanbar.org/groups/real_property_trust_estate/",
    ),
    playbooks: [RE_PLAYBOOK_ESTOPPEL],
    missing_title: "Lease-identification clause missing",
    missing_description: "No lease-identification clause was found.",
    explanation: "Without identifying the lease and amendments the estoppel cannot bind.",
    recommendation: "Add 'Lease' identifying the lease, parties, dates, and amendments.",
    present_patterns: [/the\s+lease/i, /(amendment|amendments?)/i, /(landlord|tenant)/i],
  }),
  presence({
    id: "RE-041",
    name: "Rent and security deposit",
    description: "Estoppel must state current rent and security deposit.",
    citation: rePractice(
      "estoppel-rent",
      "Estoppel rent / SD baseline",
      "https://www.americanbar.org/groups/real_property_trust_estate/",
    ),
    playbooks: [RE_PLAYBOOK_ESTOPPEL],
    missing_title: "Rent / security deposit clause missing",
    missing_description: "No rent or security-deposit clause was found.",
    explanation:
      "Lenders / buyers rely on stated rent and SD for underwriting; tenant is later estopped from denying.",
    recommendation: "Add 'Rent' and 'Security Deposit' with the current amounts.",
    present_patterns: [/current\s+(monthly\s+)?rent/i, /security\s+deposit/i],
  }),
  presence({
    id: "RE-042",
    name: "No default representation",
    description:
      "Estoppel must include a representation that no default exists (or list defaults).",
    citation: rePractice(
      "estoppel-no-default",
      "Estoppel no-default rep",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_ESTOPPEL],
    missing_title: "No-default representation missing",
    missing_description: "No 'no default' representation was found.",
    explanation: "The most common diligence question — both sides need it stated.",
    recommendation: "Add 'No Default' affirmatively stating no defaults exist (or listing them).",
    present_patterns: [/no\s+default/i, /(landlord|tenant)\s+is\s+not\s+in\s+default/i],
  }),
  presence({
    id: "RE-043",
    name: "Lease in full force and effect",
    description: "Estoppel should state the lease is in full force and effect.",
    citation: rePractice(
      "estoppel-ffe",
      "Estoppel full-force-and-effect",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_ESTOPPEL],
    missing_title: "Lease-in-full-force clause missing",
    missing_description: "No 'lease in full force and effect' representation was found.",
    explanation:
      "Standard practice for estoppels; reassures the relying party that no termination is pending.",
    recommendation:
      "Add 'Full Force and Effect' representation that the lease is in full force and not been modified except as listed.",
    present_patterns: [/full\s+force\s+and\s+effect/i],
  }),
  presence({
    id: "RE-044",
    version: "1.1.0",
    name: "Reliance / addressee identification",
    description: "Estoppel should identify who may rely on it (lender, buyer, successor).",
    citation: rePractice(
      "estoppel-reliance",
      "Estoppel reliance practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_ESTOPPEL],
    missing_title: "Reliance / addressee clause missing",
    missing_description: "No reliance / addressee clause was found.",
    explanation: "Estoppels bind only those entitled to rely; identification is essential.",
    recommendation: "Add 'Reliance' identifying the lender / buyer / successor entitled to rely.",
    present_patterns: [
      /entitled\s+to\s+rely/i,
      /reliance/i,
      /(addressee|recipient)/i,
      // "each of them … WILL RELY on the statements in this Certificate" —
      // the verb form, which the noun-only branch missed.
      /\brel(?:y|ies)\s+(?:up)?on\b/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "RE-045",
    version: "1.1.0",
    name: "Knowledge / authority qualifier",
    description: "Estoppel reps should carry a knowledge / authority qualifier.",
    citation: rePractice(
      "estoppel-knowledge",
      "Estoppel knowledge qualifier practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_ESTOPPEL],
    missing_title: "Knowledge / authority qualifier missing",
    missing_description: "No knowledge / authority qualifier was found.",
    explanation: "Reasonable estoppels qualify reps by knowledge of the signing officer.",
    recommendation:
      "Add 'Knowledge Qualifier' stating that reps are to the knowledge of the signing officer.",
    present_patterns: [
      /to\s+(the\s+)?(undersigned|signer|signing\s+officer)('s)?\s+knowledge/is,
      /knowledge\s+of\s+the\s+undersigned/i,
      // The standard form qualifies by the PARTY ROLE — "to Tenant's actual
      // knowledge", "to Seller's knowledge" — not by "the undersigned".
      /to\s+(?:the\s+)?[A-Z]\w+[''\u2019]s\s+(?:actual\s+)?knowledge/,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// E.9 — SNDA (Subordination, Non-Disturbance, Attornment). 8 rules:
// RE-046..RE-053.
// ────────────────────────────────────────────────────────────────────

const SNDA_RULES: Rule[] = [
  presence({
    id: "RE-046",
    name: "Subordination clause (lease to mortgage)",
    description: "SNDA must contain an express subordination of the lease to the mortgage.",
    citation: rePractice(
      "snda-subordination",
      "SNDA subordination practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_SNDA],
    missing_title: "Subordination clause missing",
    missing_description: "No subordination clause was found.",
    explanation:
      "The S in SNDA — the lease is subordinated to the lien of the mortgage / deed of trust.",
    recommendation:
      "Add 'Subordination' subordinating the lease to the mortgage and any future advances.",
    present_patterns: [/subordinat/i, /lease.{0,40}subordinated\s+to/is],
  }),
  presence({
    id: "RE-047",
    name: "Non-disturbance covenant",
    description: "Lender's non-disturbance covenant protects tenant on foreclosure.",
    citation: rePractice(
      "snda-nondisturbance",
      "SNDA non-disturbance practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_SNDA],
    missing_title: "Non-disturbance covenant missing",
    missing_description: "No non-disturbance covenant was found.",
    explanation:
      "The N in SNDA — lender covenants that on foreclosure tenant's possession will not be disturbed if not in default.",
    recommendation: "Add 'Non-Disturbance' covenant from the lender / successor mortgagee.",
    present_patterns: [
      /non.disturbance/i,
      /(possession|quiet\s+enjoyment).{0,40}not\s+be\s+disturbed/is,
    ],
  }),
  presence({
    id: "RE-048",
    name: "Attornment by tenant",
    description: "Tenant attornment to the successor / foreclosure purchaser.",
    citation: rePractice(
      "snda-attornment",
      "SNDA attornment practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_SNDA],
    missing_title: "Attornment clause missing",
    missing_description: "No attornment clause was found.",
    explanation:
      "The A in SNDA — tenant attorns to the successor landlord after foreclosure, accepting it as landlord.",
    recommendation: "Add 'Attornment' from tenant to lender / successor.",
    present_patterns: [/attorn/i],
  }),
  presence({
    id: "RE-049",
    name: "Lender / successor obligations limited",
    description:
      "SNDA should limit lender's / successor's liability for prior landlord's defaults.",
    citation: rePractice(
      "snda-lender-limit",
      "SNDA lender liability-limit practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_SNDA],
    missing_title: "Lender-liability limitation clause missing",
    missing_description:
      "No clause limiting lender / successor liability for prior-landlord defaults was found.",
    explanation:
      "Lender will not accept successor liability for prior landlord's actions; SNDA should explicitly so state.",
    recommendation:
      "Add 'Successor Limitations' carving out prior-landlord defaults from successor liability.",
    present_patterns: [
      /successor.{0,80}not.{0,40}(liable|responsible).{0,40}(prior\s+landlord|previous\s+landlord)/is,
      /lender.{0,40}not.{0,40}bound.{0,40}prior/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "RE-050",
    name: "Notice to lender of landlord default",
    description:
      "Tenant should agree to provide notice and cure window to lender for landlord defaults.",
    citation: rePractice(
      "snda-notice",
      "SNDA tenant-notice-to-lender practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_SNDA],
    missing_title: "Notice-to-lender clause missing",
    missing_description: "No notice-to-lender clause was found.",
    explanation: "Lender wants the opportunity to cure before tenant terminates.",
    recommendation:
      "Add 'Notice to Lender' requiring tenant to give lender concurrent notice of landlord defaults and an additional cure window.",
    present_patterns: [
      /notice\s+(to|of).{0,40}(lender|mortgagee)/is,
      /cure\s+(period|right).{0,40}(lender|mortgagee)/is,
    ],
  }),
  presence({
    id: "RE-051",
    name: "No prepayment of rent (more than one month)",
    description: "Lender wants tenant to covenant not to prepay more than one month rent.",
    citation: rePractice(
      "snda-no-prepay",
      "SNDA no-rent-prepayment covenant",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_SNDA],
    missing_title: "No-prepayment-of-rent clause missing",
    missing_description: "No 'no prepayment of rent' covenant was found.",
    explanation:
      "Lender protects against tenant having paid rent forward to landlord, which lender cannot collect a second time.",
    recommendation: "Add 'No Prepayment' restricting rent prepayments beyond one month.",
    present_patterns: [
      /no\s+prepay(ment)?\s+of\s+rent/i,
      /not.{0,40}prepay.{0,40}(more\s+than\s+one\s+month|rent)/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "RE-052",
    name: "No modification of lease without lender consent",
    description: "Lender wants veto on material lease modifications post-loan.",
    citation: rePractice(
      "snda-no-mod",
      "SNDA no-modification-without-consent",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_SNDA],
    missing_title: "No-modification-without-consent clause missing",
    missing_description:
      "No clause restricting lease modifications without lender consent was found.",
    explanation:
      "Without this lender's collateral could be impaired by post-closing lease changes.",
    recommendation:
      "Add 'No Modification' requiring lender consent for material lease modifications.",
    present_patterns: [
      /no\s+modification.{0,40}without.{0,40}consent/is,
      /lender.{0,40}consent.{0,40}modification/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "RE-053",
    name: "Recording / memorandum of SNDA",
    description: "SNDA is commonly recorded.",
    citation: recordingAct(),
    playbooks: [RE_PLAYBOOK_SNDA],
    missing_title: "Recording / memorandum clause missing",
    missing_description: "No recording / memorandum clause was found.",
    explanation: "Recording binds successor lenders / owners and provides constructive notice.",
    recommendation: "Add 'Recording' authorizing recording of the SNDA or a short-form memorandum.",
    present_patterns: [/record/i, /memorandum/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// E.10 — Lease Assignment. 7 rules: RE-054..RE-060.
// ────────────────────────────────────────────────────────────────────

const LEASE_ASSIGNMENT_RULES: Rule[] = [
  presence({
    id: "RE-054",
    name: "Assignor / assignee / lease identification",
    description: "Assignment must identify assignor, assignee, and the underlying lease.",
    citation: rePractice(
      "lease-assign-baseline",
      "Lease assignment baseline content",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_LEASE_ASSIGN],
    missing_title: "Parties / lease identification missing",
    missing_description: "No clause identifying assignor, assignee, or the lease was found.",
    explanation:
      "Operative baseline — without these identifications the document is unenforceable.",
    recommendation: "Add 'Parties' and 'Lease' identifications.",
    present_patterns: [/assignor/i, /assignee/i, /(the\s+)?lease.{0,40}(dated|between)/is],
  }),
  presence({
    id: "RE-055",
    name: "Landlord consent",
    description:
      "Most commercial leases require landlord consent to assignment; the assignment should evidence that consent.",
    citation: rePractice(
      "lease-assign-consent",
      "Landlord consent to assignment practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_LEASE_ASSIGN],
    missing_title: "Landlord-consent clause missing",
    missing_description: "No landlord-consent clause / joinder was found.",
    explanation:
      "Without consent the assignment may breach the lease and trigger landlord remedies.",
    recommendation: "Add 'Landlord Consent' clause or landlord joinder signature block.",
    present_patterns: [/landlord(.s)?\s+consent/i, /consent\s+to\s+assignment/i],
  }),
  presence({
    id: "RE-056",
    name: "Assumption of obligations by assignee",
    description: "Assignee should expressly assume all tenant obligations under the lease.",
    citation: rePractice(
      "lease-assign-assumption",
      "Assignment / assumption baseline",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_LEASE_ASSIGN],
    missing_title: "Assumption-of-obligations clause missing",
    missing_description: "No assumption-of-obligations clause was found.",
    explanation: "Without express assumption, assignee's privity of contract is unclear.",
    recommendation:
      "Add 'Assumption' clause expressly assuming all tenant obligations from and after the effective date.",
    present_patterns: [/assumes?\s+all.{0,40}obligations/is, /assumption\s+of/i],
  }),
  presence({
    id: "RE-057",
    name: "Release of assignor (or continuing liability)",
    description: "Assignment should address whether assignor is released or remains liable.",
    citation: rePractice(
      "lease-assign-release",
      "Assignor release / continuing-liability practice",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_LEASE_ASSIGN],
    missing_title: "Release / continuing-liability clause missing",
    missing_description:
      "No clause was found addressing release of assignor or its continuing liability.",
    explanation:
      "Default: assignor remains liable; many assignments release if landlord approves; the document must address.",
    recommendation: "Add 'Release of Assignor' or 'Continuing Liability' as appropriate.",
    present_patterns: [
      /release\s+of\s+assignor/i,
      /assignor.{0,80}(continue|continuing)\s+(to\s+be\s+)?liable/is,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "RE-058",
    name: "Effective date of assignment",
    description: "Assignment must state an effective date.",
    citation: rePractice(
      "lease-assign-date",
      "Assignment effective-date baseline",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_LEASE_ASSIGN],
    missing_title: "Effective-date clause missing",
    missing_description: "No effective-date clause was found.",
    explanation: "Effective date anchors the rent / SD prorations and the assumption.",
    recommendation: "Add 'Effective Date' to the assignment.",
    present_patterns: [/effective\s+(as\s+of|date)/i],
  }),
  presence({
    id: "RE-059",
    name: "Security deposit / prepaid rent transfer",
    description: "Assignment should address transfer of security deposit and any prepaid rent.",
    citation: rePractice(
      "lease-assign-deposit",
      "Security deposit transfer on assignment",
      "https://www.americanbar.org/",
    ),
    playbooks: [RE_PLAYBOOK_LEASE_ASSIGN],
    missing_title: "Security deposit / prepaid rent clause missing",
    missing_description:
      "No clause was found addressing transfer of security deposit or prepaid rent.",
    explanation: "Common source of post-assignment disputes — must be addressed.",
    recommendation: "Add 'Security Deposit and Prepaid Rent' specifying transfer mechanics.",
    present_patterns: [/security\s+deposit/i, /prepaid\s+rent/i],
    default_severity: "warning",
  }),
  presence({
    id: "RE-060",
    name: "Recording / notice to mortgagee",
    description:
      "Lease assignments may need to be recorded (memorandum of lease was recorded) and / or noticed to mortgagee under SNDA.",
    citation: recordingAct(),
    playbooks: [RE_PLAYBOOK_LEASE_ASSIGN],
    missing_title: "Recording / mortgagee-notice clause missing",
    missing_description: "No recording or mortgagee-notice clause was found.",
    explanation:
      "If a memorandum of the underlying lease was recorded the assignment should also be recorded; lender notice required under SNDA.",
    recommendation: "Add 'Recording / Notice to Mortgagee' addressing both.",
    present_patterns: [/record/i, /(mortgagee|lender).{0,40}notice/is],
    default_severity: "info",
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate. 60 rules total.
// ────────────────────────────────────────────────────────────────────

export const REAL_ESTATE_RULES: Rule[] = [
  ...NET_LEASE_RULES,
  ...PSA_RULES,
  ...GROUND_LEASE_RULES,
  ...EASEMENT_RULES,
  ...CCR_RULES,
  ...ESTOPPEL_RULES,
  ...SNDA_RULES,
  ...LEASE_ASSIGNMENT_RULES,
];

export {
  NET_LEASE_RULES,
  PSA_RULES,
  GROUND_LEASE_RULES,
  EASEMENT_RULES,
  CCR_RULES,
  ESTOPPEL_RULES,
  SNDA_RULES,
  LEASE_ASSIGNMENT_RULES,
};
