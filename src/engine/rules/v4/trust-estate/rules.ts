/**
 * v4 Trust / estate / family ruleset — 60 rules
 * (spec-v4.md §6.N, Step 57).
 *
 * Eight new playbooks (N.1–N.8): last will and testament, revocable
 * living trust, advance directive / living will, healthcare proxy /
 * POA for healthcare, durable power of attorney (financial),
 * prenuptial agreement, postnuptial agreement, and family-law MSA.
 *
 * Spec §6.N caveat — every output in this sub-domain must say
 * explicitly that **execution formalities (witnesses, notary,
 * holographic state-specific requirements) cannot be verified from a
 * docx alone**. This is enforced by the always-fires `EST-060`
 * disclaimer rule scoped to every N playbook.
 *
 * Rule ids are flat `EST-NNN` (001..060).
 */

import { makeFinding, type Finding, type Rule, type RuleContext } from "../../../finding.js";
import { buildV4PresenceRule, docTop, type V4PresenceSpec } from "../_helpers.js";
import {
  EST_PLAYBOOK_WILL,
  EST_PLAYBOOK_REVOCABLE_TRUST,
  EST_PLAYBOOK_ADVANCE_DIRECTIVE,
  EST_PLAYBOOK_HC_POA,
  EST_PLAYBOOK_DURABLE_POA,
  EST_PLAYBOOK_PRENUP,
  EST_PLAYBOOK_POSTNUP,
  EST_PLAYBOOK_FAMILY_MSA,
  EST_PLAYBOOK_IDS,
  upc,
  utc,
  upoaa,
  upmaa,
  stateAdv,
  estPractice,
} from "./_helpers.js";

const CATEGORY = "trust-estate";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// N.1 — Last will and testament. 8 rules: EST-001..EST-008.
// ────────────────────────────────────────────────────────────────────

const WILL_RULES: Rule[] = [
  presence({
    id: "EST-001",
    name: "Testator identification + domicile",
    description: "Will must identify the testator and the testator's domicile.",
    citation: upc("2-501", "Who may make a will"),
    playbooks: [EST_PLAYBOOK_WILL],
    missing_title: "Testator identification / domicile clause missing",
    missing_description: "No clause was found identifying the testator and domicile.",
    explanation:
      "UPC § 2-501 + state codes require the will to be made by a competent adult; the writing should identify the testator and state of domicile (drives applicable law).",
    recommendation:
      "Add 'Testator and Domicile' identifying the testator (full legal name, address) and stating the state of domicile.",
    present_patterns: [
      /(testator|i,\s+the\s+undersigned|my\s+name\s+is)/i,
      /(domicile|reside|resident|state\s+of)/i,
    ],
  }),
  presence({
    id: "EST-002",
    name: "Revocation of prior wills + codicils",
    description: "Will must revoke prior wills and codicils.",
    citation: upc("2-507", "Revocation by writing or act"),
    playbooks: [EST_PLAYBOOK_WILL],
    missing_title: "Revocation-of-prior-wills clause missing",
    missing_description: "No clause was found revoking prior wills / codicils.",
    explanation:
      "UPC § 2-507(a) recognizes revocation by subsequent writing. Without an express revocation clause, prior wills may control to the extent not inconsistent.",
    recommendation: "Add 'Revocation' expressly revoking all prior wills and codicils.",
    present_patterns: [
      /(revoke|revoking|revocation)/i,
      /(prior\s+wills?|all\s+(former|previous)\s+wills?|codicils?)/i,
    ],
  }),
  presence({
    id: "EST-003",
    name: "Executor / personal representative nomination",
    description: "Will must nominate an executor / personal representative (and successors).",
    citation: upc("3-203", "Priority for appointment"),
    playbooks: [EST_PLAYBOOK_WILL],
    missing_title: "Executor / personal representative clause missing",
    missing_description: "No clause was found nominating an executor / personal representative.",
    explanation:
      "Without a nomination, the court appoints from statutory priority list (often surviving spouse). Successor nominations avoid contested appointments.",
    recommendation:
      "Add 'Executor / Personal Representative' nominating a primary and at least one successor.",
    present_patterns: [
      /(executor|personal\s+representative|administrator)/i,
      /(nominate|appoint|designate)/i,
    ],
  }),
  presence({
    id: "EST-004",
    name: "Bond waiver for fiduciaries",
    description:
      "Will should waive bond / surety for executor and other fiduciaries unless state law requires.",
    citation: upc("3-603", "Bond not required"),
    playbooks: [EST_PLAYBOOK_WILL],
    missing_title: "Fiduciary-bond waiver clause missing",
    missing_description: "No clause was found waiving bond / surety for fiduciaries.",
    explanation:
      "UPC § 3-603 permits bond waiver in the will. Without waiver, bond may be required, adding cost and friction.",
    recommendation:
      "Add 'Fiduciary Bond' waiving bond and surety for executor / personal representative and any trustees.",
    present_patterns: [
      /(bond|surety)/i,
      /(waive(s|d|r)?|without\s+bond|no\s+bond\s+(shall\s+be\s+)?required)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-005",
    name: "Specific bequests + residuary clause",
    description: "Will must include a residuary clause (and identify any specific bequests).",
    citation: upc("2-606", "Specific devise"),
    playbooks: [EST_PLAYBOOK_WILL],
    missing_title: "Residuary clause missing",
    missing_description: "No residuary clause was found.",
    explanation:
      "Without a residuary clause, property not specifically devised passes by intestacy — likely contrary to testator's intent.",
    recommendation:
      "Add 'Residuary Estate' devising the residue to named beneficiaries (and contingent residuary beneficiaries).",
    present_patterns: [
      /(residuary|residue|remainder)\s+(of\s+)?(my\s+)?(estate|property)/i,
      /(devise|bequeath|give)/i,
    ],
  }),
  presence({
    id: "EST-006",
    name: "Guardianship nomination for minor children",
    description: "Wills involving minor children should nominate a guardian (and successors).",
    citation: upc("5-202", "Testamentary appointment of guardian"),
    playbooks: [EST_PLAYBOOK_WILL],
    missing_title: "Guardianship nomination clause missing",
    missing_description: "No guardianship nomination for minor children was found.",
    explanation:
      "UPC § 5-202 recognizes testamentary appointment of guardian for unmarried minor child. Without it, the court chooses from family members based on statutory factors.",
    recommendation:
      "If testator has minor children, add 'Guardian for Minor Children' nominating a guardian and successor.",
    present_patterns: [
      /(guardian|guardianship)/i,
      /(minor\s+children|minor\s+child|under\s+the\s+age\s+of\s+18)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-007",
    name: "Self-proving affidavit reference",
    description:
      "Will should reference a self-proving affidavit per UPC § 2-504 (most states recognize).",
    citation: upc("2-504", "Self-proved will"),
    playbooks: [EST_PLAYBOOK_WILL],
    missing_title: "Self-proving affidavit clause missing",
    missing_description: "No self-proving affidavit reference was found.",
    explanation:
      "UPC § 2-504 self-proving affidavit makes witness testimony unnecessary in probate, speeding the process.",
    recommendation:
      "Add 'Self-Proving Affidavit' adopting the statutory form (or state-specific equivalent).",
    present_patterns: [/(self.proving|self.proved)\s+affidavit/i, /(witness|notary|notar(y|ial))/i],
    default_severity: "warning",
  }),
  presence({
    id: "EST-008",
    name: "Execution block — testator + witnesses (2)",
    description:
      "Will must include execution block for testator signature and at least two witnesses.",
    citation: upc("2-502", "Execution; witnessed wills"),
    playbooks: [EST_PLAYBOOK_WILL],
    missing_title: "Execution block (signature + witnesses) missing",
    missing_description:
      "No execution block (testator signature + at least two witnesses) was found in the text.",
    explanation:
      "UPC § 2-502 requires at least two competent witnesses. Note: actual execution formalities cannot be verified from the docx alone (see EST-060).",
    recommendation:
      "Add execution block with testator signature line + 2 witness signature lines + (recommended) notary block.",
    present_patterns: [
      /(testator.{0,10}signature|signed\s+by\s+the\s+testator)/i,
      /(witness(es)?|attested)/i,
      /(notary|notar(y|ial))/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// N.2 — Revocable living trust. 8 rules: EST-009..EST-016.
// ────────────────────────────────────────────────────────────────────

const REVOCABLE_TRUST_RULES: Rule[] = [
  presence({
    id: "EST-009",
    name: "Settlor / grantor / trustor identification",
    description: "Revocable living trust must identify settlor (also called grantor / trustor).",
    citation: utc("103", "Definitions"),
    playbooks: [EST_PLAYBOOK_REVOCABLE_TRUST],
    missing_title: "Settlor / grantor identification clause missing",
    missing_description: "No clause was found identifying the settlor / grantor.",
    explanation:
      "UTC § 103 defines settlor as the person creating the trust. Identification is required for capacity / formation purposes.",
    recommendation: "Add 'Settlor' (or 'Grantor' / 'Trustor') line identifying the trust creator.",
    present_patterns: [/(settlor|grantor|trustor)/i, /(creates?|establishes?|declares?)/i],
  }),
  presence({
    id: "EST-010",
    name: "Trustee + successor trustees",
    description: "Trust must identify the initial trustee and at least one successor trustee.",
    citation: utc("704", "Vacancy in trusteeship"),
    playbooks: [EST_PLAYBOOK_REVOCABLE_TRUST],
    missing_title: "Trustee / successor trustees clause missing",
    missing_description: "No trustee / successor-trustee clause was found.",
    explanation:
      "UTC § 704 governs vacancies. Without successor designation, the court appoints, creating delay and unintended outcomes.",
    recommendation:
      "Add 'Trustees' identifying initial trustee + at least one successor (and remove / replace procedures).",
    present_patterns: [/(trustee)/i, /(successor|alternate)\s+trustee/i],
  }),
  presence({
    id: "EST-011",
    name: "Revocability / amendment power",
    description: "Revocable trust must clearly state it is revocable and amendable by the settlor.",
    citation: utc("602", "Revocation or amendment"),
    playbooks: [EST_PLAYBOOK_REVOCABLE_TRUST],
    missing_title: "Revocability / amendment clause missing",
    missing_description: "No clause was found stating the trust is revocable / amendable.",
    explanation:
      "UTC § 602(a) presumes revocability for trusts created after the UTC's adoption in a state — but explicit revocability + amendment language avoids dispute, especially in non-UTC states.",
    recommendation:
      "Add 'Revocation and Amendment' stating settlor may revoke or amend at any time by written instrument.",
    present_patterns: [/(revoke|revocation|revocable)/i, /(amend|amendment|alter)/i],
  }),
  presence({
    id: "EST-012",
    name: "Funding — initial trust property identified",
    description: "Trust should identify initial trust property (often Schedule A).",
    citation: utc("401", "Methods of creating trust"),
    playbooks: [EST_PLAYBOOK_REVOCABLE_TRUST],
    missing_title: "Funding / trust property clause missing",
    missing_description: "No funding / initial trust-property clause was found.",
    explanation:
      "UTC § 401 requires property for trust formation. Without funding, the trust is unfunded and inoperative.",
    recommendation: "Add 'Trust Property' (or Schedule A) describing the initial trust corpus.",
    present_patterns: [
      /(trust\s+property|trust\s+corpus|schedule\s+a|initial\s+funding)/i,
      /(transfer(s|red)?|conveyed?|assign(s|ed)?)/i,
    ],
  }),
  presence({
    id: "EST-013",
    name: "Distributions during settlor's life",
    description:
      "Trust must address distributions during settlor's lifetime (typically: all income and principal to settlor).",
    citation: utc("813", "Duty to inform and report"),
    playbooks: [EST_PLAYBOOK_REVOCABLE_TRUST],
    missing_title: "Lifetime-distribution clause missing",
    missing_description: "No lifetime-distribution clause was found.",
    explanation:
      "Without explicit lifetime-distribution direction, ambiguity about whether trustee may distribute principal can defeat estate-planning intent.",
    recommendation:
      "Add 'Distributions During Settlor's Lifetime' authorizing income + principal as settlor directs / requests.",
    present_patterns: [
      /(during\s+(settlor.?s|grantor.?s)\s+lifetime|while\s+settlor\s+(is\s+)?living)/i,
      /(income|principal|distribut)/i,
    ],
  }),
  presence({
    id: "EST-014",
    name: "Distributions on settlor's death — beneficiaries identified",
    description:
      "Trust must specify the disposition of trust property on settlor's death (named beneficiaries / shares).",
    citation: utc("103", "Beneficiary"),
    playbooks: [EST_PLAYBOOK_REVOCABLE_TRUST],
    missing_title: "Death-distribution clause missing",
    missing_description: "No clause was found specifying disposition on settlor's death.",
    explanation:
      "The post-death distribution is the trust's principal estate-planning function; named beneficiaries with stated shares should be identified.",
    recommendation:
      "Add 'Distributions on Settlor's Death' naming beneficiaries, shares, and contingent beneficiaries.",
    present_patterns: [
      /(upon\s+(settlor.?s|grantor.?s)\s+death|after\s+death)/i,
      /(beneficiar|distribute)/i,
    ],
  }),
  presence({
    id: "EST-015",
    name: "Pour-over reference (to coordinate with will)",
    description:
      "Revocable trust + pour-over will is a common pattern; trust should reference the pour-over will.",
    citation: estPractice(
      "pour-over",
      "UPC § 2-511 / state pour-over statutes",
      "https://www.law.cornell.edu/wex/pourover_will",
    ),
    playbooks: [EST_PLAYBOOK_REVOCABLE_TRUST],
    missing_title: "Pour-over reference missing",
    missing_description: "No pour-over reference was found.",
    explanation:
      "Pour-over wills devise residuary to the trust. Coordination prevents probate of trust-funded property — but unfunded property must be addressed.",
    recommendation:
      "Add 'Pour-Over' clause referencing the testator's pour-over will (or noting absence).",
    present_patterns: [/(pour.?over|pourover)/i, /(will|last\s+will)/i],
    default_severity: "warning",
  }),
  presence({
    id: "EST-016",
    name: "Spendthrift + creditor-protection clause",
    description:
      "Trust should include a spendthrift clause restraining beneficiaries' creditors (UTC § 502).",
    citation: utc("502", "Spendthrift provision"),
    playbooks: [EST_PLAYBOOK_REVOCABLE_TRUST],
    missing_title: "Spendthrift clause missing",
    missing_description: "No spendthrift / creditor-protection clause was found.",
    explanation:
      "UTC § 502 enforces spendthrift provisions restricting both voluntary and involuntary transfers of beneficial interests. Standard estate-planning practice.",
    recommendation:
      "Add 'Spendthrift Provision' restraining voluntary and involuntary transfers of beneficial interests.",
    present_patterns: [/spendthrift/i, /(creditor|involuntary\s+transfer|attachment)/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// N.3 — Advance directive / living will. 7 rules: EST-017..EST-023.
// ────────────────────────────────────────────────────────────────────

const ADVANCE_DIRECTIVE_RULES: Rule[] = [
  presence({
    id: "EST-017",
    name: "Declarant identification + capacity recital",
    description:
      "Advance directive must identify the declarant and recite competence at execution.",
    citation: stateAdv(
      "advance-directive",
      "State advance-directive statutes (e.g., CA Prob. § 4670 et seq.; NY Pub. Health § 2980 et seq.)",
    ),
    playbooks: [EST_PLAYBOOK_ADVANCE_DIRECTIVE],
    missing_title: "Declarant identification / capacity clause missing",
    missing_description: "No clause was found identifying declarant and capacity at execution.",
    explanation:
      "Advance directives require competent declarant; identification + capacity recital protect against later challenge.",
    recommendation:
      "Add 'Declarant' clause identifying the declarant and reciting capacity at execution.",
    present_patterns: [
      /(declarant|principal|patient|i,\s+the\s+undersigned)/i,
      /(competent|sound\s+mind|of\s+legal\s+age|18\s+years)/i,
    ],
  }),
  presence({
    id: "EST-018",
    name: "End-of-life treatment preferences",
    description:
      "Living will must state end-of-life treatment preferences (life-sustaining treatment, artificial nutrition / hydration).",
    citation: stateAdv("end-of-life", "State end-of-life decision-making statutes"),
    playbooks: [EST_PLAYBOOK_ADVANCE_DIRECTIVE],
    missing_title: "End-of-life preferences clause missing",
    missing_description: "No clause was found stating end-of-life treatment preferences.",
    explanation:
      "The core function of a living will is to instruct providers about life-sustaining treatment in terminal / persistent-vegetative / end-stage conditions.",
    recommendation:
      "Add 'Treatment Preferences' covering life-sustaining treatment, artificial nutrition and hydration, and pain management.",
    present_patterns: [
      /(life.sustaining|artificial\s+(nutrition|hydration|respiration))/i,
      /(end.of.life|terminal|persistent\s+vegetative|end.stage)/i,
    ],
  }),
  presence({
    id: "EST-019",
    name: "Pain management / comfort care directive",
    description: "Advance directive should address pain management / comfort care preferences.",
    citation: stateAdv("comfort-care", "State comfort-care / hospice directives"),
    playbooks: [EST_PLAYBOOK_ADVANCE_DIRECTIVE],
    missing_title: "Pain-management / comfort-care clause missing",
    missing_description: "No pain-management / comfort-care clause was found.",
    explanation:
      "Even when foregoing life-sustaining treatment, declarant typically wants palliative / comfort care. Explicit direction avoids under-treatment.",
    recommendation:
      "Add 'Pain Management / Comfort Care' directing palliative care even when life-sustaining treatment is foregone.",
    present_patterns: [
      /(pain\s+management|palliative\s+care|comfort\s+care|hospice)/i,
      /(relieve\s+pain|pain\s+relief)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-020",
    name: "Organ donation / anatomical gift",
    description: "Advance directive should address organ-donation / anatomical-gift preferences.",
    citation: stateAdv("uagd", "Uniform Anatomical Gift Act (revised 2006)"),
    playbooks: [EST_PLAYBOOK_ADVANCE_DIRECTIVE],
    missing_title: "Organ donation / anatomical gift clause missing",
    missing_description: "No organ-donation / anatomical-gift clause was found.",
    explanation:
      "Uniform Anatomical Gift Act allows declarant to authorize donation in the advance directive; without it, the next-of-kin makes the call.",
    recommendation:
      "Add 'Anatomical Gift / Organ Donation' specifying donate-all / specific-organs / decline.",
    present_patterns: [
      /(organ\s+donation|anatomical\s+gift|donate\s+(my\s+)?organs?)/i,
      /(uagd|uniform\s+anatomical)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-021",
    name: "Witness requirements + notarial acknowledgment",
    description:
      "Advance directive must include execution block with witnesses (and notarization where required).",
    citation: stateAdv("ad-execution", "State advance-directive execution-formality statutes"),
    playbooks: [EST_PLAYBOOK_ADVANCE_DIRECTIVE],
    missing_title: "Witnesses / notary clause missing",
    missing_description: "No witnesses / notary clause was found in the text.",
    explanation:
      "States vary: two witnesses common; some require notary; many disqualify health-care provider / agent / heir from witnessing. Execution formalities cannot be verified from text — see EST-060.",
    recommendation:
      "Add execution block with two witnesses (non-providers, non-agents, non-heirs) + notary block where required.",
    present_patterns: [/(witness(es)?|attested)/i, /(notary|notar(y|ial))/i],
  }),
  presence({
    id: "EST-022",
    name: "Effective-date / triggering condition",
    description:
      "Advance directive must state when it becomes effective (incapacity / terminal condition).",
    citation: stateAdv("trigger", "Advance-directive triggering-condition statutes"),
    playbooks: [EST_PLAYBOOK_ADVANCE_DIRECTIVE],
    missing_title: "Triggering-condition clause missing",
    missing_description: "No triggering-condition / effective-on clause was found.",
    explanation:
      "Common triggers: terminal condition, irreversible coma, persistent vegetative state, end-stage condition. Without trigger, providers cannot determine when the directive applies.",
    recommendation:
      "Add 'Effective When' specifying the triggering condition(s) and who makes the determination (typically two physicians).",
    present_patterns: [
      /(terminal|irreversible|persistent\s+vegetative|end.stage)/i,
      /(effective|applies?|takes\s+effect)/i,
    ],
  }),
  presence({
    id: "EST-023",
    name: "Revocation method",
    description:
      "Advance directive should describe how it may be revoked (writing / oral statement / destruction).",
    citation: stateAdv("ad-revocation", "Advance-directive revocation statutes"),
    playbooks: [EST_PLAYBOOK_ADVANCE_DIRECTIVE],
    missing_title: "Revocation-method clause missing",
    missing_description: "No revocation-method clause was found.",
    explanation:
      "Most states allow oral revocation by competent declarant. Clear revocation language reduces ambiguity.",
    recommendation:
      "Add 'Revocation' describing the methods (oral, written, physical destruction, contrary directive).",
    present_patterns: [/(revoke|revocation|revoking)/i, /(oral|written|destroy(ed)?|contrary)/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// N.4 — Healthcare proxy / POA for healthcare. 7 rules: EST-024..EST-030.
// ────────────────────────────────────────────────────────────────────

const HEALTHCARE_POA_RULES: Rule[] = [
  presence({
    id: "EST-024",
    name: "Principal + agent identification",
    description: "Healthcare proxy must identify principal and agent (and successor agent).",
    citation: stateAdv("hcp", "State healthcare-proxy / POA statutes"),
    playbooks: [EST_PLAYBOOK_HC_POA],
    missing_title: "Principal / agent identification clause missing",
    missing_description: "No clause was found identifying principal and agent.",
    explanation:
      "Healthcare proxies designate a surrogate decision-maker. Identification of principal + agent (with successor) is the core operative step.",
    recommendation:
      "Add 'Principal and Agent' identifying the principal and the primary + successor agents.",
    present_patterns: [
      /(principal|grantor|i,\s+the\s+undersigned)/i,
      /(agent|attorney.in.fact|proxy|surrogate)/i,
    ],
  }),
  presence({
    id: "EST-025",
    name: "Scope of agent's healthcare authority",
    description:
      "Proxy must define the scope of agent's authority (treatment decisions, access to records, etc.).",
    citation: stateAdv("hc-scope", "State healthcare-POA scope statutes"),
    playbooks: [EST_PLAYBOOK_HC_POA],
    missing_title: "Scope of authority clause missing",
    missing_description: "No clause was found defining the scope of agent's authority.",
    explanation:
      "Authority varies — some forms grant general authority, others enumerate treatment decisions, records access, end-of-life decisions. Explicit scope avoids dispute.",
    recommendation:
      "Add 'Scope of Authority' enumerating treatment decisions, records access (HIPAA), placement decisions, end-of-life decisions.",
    present_patterns: [
      /(authority|authorize|empower)/i,
      /(treatment|medical\s+decisions?|records?|placement)/i,
    ],
  }),
  presence({
    id: "EST-026",
    name: "HIPAA authorization for agent",
    description: "Healthcare proxy should include HIPAA authorization for agent to access PHI.",
    citation: stateAdv("hipaa-agent", "45 C.F.R. § 164.502(g) — personal representative"),
    playbooks: [EST_PLAYBOOK_HC_POA],
    missing_title: "HIPAA authorization for agent clause missing",
    missing_description: "No HIPAA authorization for agent clause was found.",
    explanation:
      "45 C.F.R. § 164.502(g) makes the agent a personal representative for HIPAA purposes; an explicit recital in the proxy avoids provider hesitation.",
    recommendation:
      "Add 'HIPAA Authorization' authorizing agent as personal representative for HIPAA + state confidentiality purposes.",
    present_patterns: [
      /(hipaa|protected\s+health\s+information|phi)/i,
      /(authoriz|personal\s+representative)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-027",
    name: "Activation — when does agent's authority begin",
    description:
      "Proxy must state when agent's authority activates (typically: incapacity per physician determination).",
    citation: stateAdv("hc-activation", "State healthcare-POA activation statutes"),
    playbooks: [EST_PLAYBOOK_HC_POA],
    missing_title: "Activation / capacity trigger clause missing",
    missing_description: "No activation / capacity-trigger clause was found.",
    explanation:
      "Springing vs immediate: springing proxies activate on incapacity per physician; immediate proxies operate concurrently with principal.",
    recommendation:
      "Add 'Activation' specifying when agent's authority begins (immediate or springing on physician determination of incapacity).",
    present_patterns: [
      /(activate|springs?|takes?\s+effect|effective\s+(when|upon))/i,
      /(incapacity|incapacitated|unable\s+to\s+(make|communicate))/i,
    ],
  }),
  presence({
    id: "EST-028",
    name: "End-of-life instructions / DNR",
    description:
      "Healthcare proxy should address end-of-life instructions (or expressly defer to a separate living will).",
    citation: stateAdv("eol", "State end-of-life / DNR statutes"),
    playbooks: [EST_PLAYBOOK_HC_POA],
    missing_title: "End-of-life / DNR instructions clause missing",
    missing_description: "No end-of-life / DNR instructions clause was found.",
    explanation:
      "Without instruction or cross-reference to a living will, the agent may face ambiguity in end-of-life decisions.",
    recommendation:
      "Add 'End-of-Life Instructions' or expressly defer to a separately executed living will / DNR order.",
    present_patterns: [
      /(end.of.life|life.sustaining|dnr|do.not.resuscitate)/i,
      /(living\s+will|advance\s+directive)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-029",
    name: "Limitations / restrictions on agent",
    description:
      "Healthcare proxy may include limitations (no abortion, no withholding of nutrition, etc.) per declarant's preferences.",
    citation: stateAdv("hc-limits", "State healthcare-POA limitation statutes"),
    playbooks: [EST_PLAYBOOK_HC_POA],
    missing_title: "Limitations on agent clause missing",
    missing_description: "No limitations / restrictions on agent clause was found.",
    explanation:
      "Express limitations protect the principal's preferences. Drafters often leave this blank but should give the principal the option.",
    recommendation: "Add 'Limitations' enumerating any restrictions or expressly stating 'none'.",
    present_patterns: [
      /(limitation|restriction|except)/i,
      /(may\s+not|shall\s+not|prohibit|forbid)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-030",
    name: "Witnesses / notary execution block",
    description:
      "Healthcare proxy execution must include witnesses and (where required) notary block.",
    citation: stateAdv("hc-execution", "State healthcare-POA execution-formality statutes"),
    playbooks: [EST_PLAYBOOK_HC_POA],
    missing_title: "Witnesses / notary clause missing",
    missing_description: "No witnesses / notary execution block was found in the text.",
    explanation:
      "States require witnesses (often two non-providers / non-agents) + notary in many states. Execution formalities cannot be verified from text — see EST-060.",
    recommendation:
      "Add execution block with required witnesses + notary acknowledgment where applicable.",
    present_patterns: [/(witness(es)?|attested)/i, /(notary|notar(y|ial)|sworn)/i],
  }),
];

// ────────────────────────────────────────────────────────────────────
// N.5 — Durable power of attorney (financial). 7 rules: EST-031..EST-037.
// ────────────────────────────────────────────────────────────────────

const DURABLE_POA_RULES: Rule[] = [
  presence({
    id: "EST-031",
    name: "Principal + agent identification (financial)",
    description: "Durable POA must identify principal and agent (and successor agent).",
    citation: upoaa("110", "Co-agents and successor agents"),
    playbooks: [EST_PLAYBOOK_DURABLE_POA],
    missing_title: "Principal / agent identification clause missing",
    missing_description: "No clause was found identifying principal and agent.",
    explanation:
      "UPOAA § 110 contemplates co-agents and successor agents. Identification is the operative core.",
    recommendation:
      "Add 'Principal and Agent' identifying the principal and primary / successor agents.",
    present_patterns: [/(principal|grantor)/i, /(agent|attorney.in.fact)/i],
  }),
  presence({
    id: "EST-032",
    name: "Durable language — survives incapacity",
    description: "POA must include durable language stating it survives principal's incapacity.",
    citation: upoaa("104", "Power of attorney is durable"),
    playbooks: [EST_PLAYBOOK_DURABLE_POA],
    missing_title: "Durability / durable-language clause missing",
    missing_description: "No durability clause was found.",
    explanation:
      "UPOAA § 104 makes POAs durable by default; non-UPOAA states require express durability language. Without it, the POA terminates on incapacity.",
    recommendation:
      "Add 'Durability' stating the POA is not affected by principal's subsequent incapacity or disability.",
    present_patterns: [
      /durabl/i,
      /(survives?|not\s+affected\s+by|notwithstanding).{0,40}(incapacity|disability|incompet)/is,
    ],
  }),
  presence({
    id: "EST-033",
    name: "Scope of agent's authority — categories / hot powers",
    description:
      "POA must enumerate scope (real property, banks, taxes, business, gifts, etc.); 'hot powers' (gifts, beneficiary changes) require specific authority.",
    citation: upoaa("201", "Authority that requires specific grant"),
    playbooks: [EST_PLAYBOOK_DURABLE_POA],
    missing_title: "Scope / hot-powers clause missing",
    missing_description: "No scope / hot-powers clause was found.",
    explanation:
      "UPOAA § 201 enumerates 'hot powers' (gifts, creating / amending trusts, changing beneficiary designations, etc.) that require explicit specific grant.",
    recommendation:
      "Add 'Scope of Authority' enumerating each category and any hot-powers requiring specific authority.",
    present_patterns: [
      /(real\s+(property|estate)|banking|taxes?|business|gifts?)/i,
      /(hot\s+powers?|specific(ally)?\s+authoriz)/i,
    ],
  }),
  presence({
    id: "EST-034",
    name: "Springing vs immediate effectiveness",
    description: "POA must state whether it is immediately effective or springing (on incapacity).",
    citation: upoaa("109", "When power of attorney is effective"),
    playbooks: [EST_PLAYBOOK_DURABLE_POA],
    missing_title: "Springing / immediate effectiveness clause missing",
    missing_description: "No clause was found stating immediate or springing effectiveness.",
    explanation:
      "Springing POAs activate only on incapacity; immediate POAs operate from signing. UPOAA § 109 permits springing on incapacity with a stated mechanism for verifying incapacity.",
    recommendation:
      "Add 'Effectiveness' specifying immediate vs springing, and (if springing) the incapacity-determination mechanism.",
    present_patterns: [
      /(immediately\s+effective|takes?\s+effect\s+(immediately|upon|on))/i,
      /(springing|upon\s+incapacity)/i,
    ],
  }),
  presence({
    id: "EST-035",
    name: "Agent's duties — fiduciary obligations",
    description:
      "POA should recite agent's fiduciary duties (UPOAA § 114): loyalty, good faith, no commingling.",
    citation: upoaa("114", "Agent's duties"),
    playbooks: [EST_PLAYBOOK_DURABLE_POA],
    missing_title: "Agent fiduciary duties clause missing",
    missing_description: "No clause was found reciting agent's fiduciary duties.",
    explanation:
      "UPOAA § 114 imposes duties of loyalty, good faith, recordkeeping. Without recital, principal protections are weaker and third parties may hesitate to honor the POA.",
    recommendation:
      "Add 'Agent's Duties' reciting loyalty, good faith, no commingling, and recordkeeping obligations.",
    present_patterns: [
      /(agent.?s\s+duties|fiduciary|loyalty)/i,
      /(good\s+faith|records|commingl)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-036",
    name: "Third-party reliance / acceptance protection",
    description:
      "POA should provide third-party reliance / acceptance protection (UPOAA § 119 / § 120).",
    citation: upoaa("119", "Acceptance of and reliance upon acknowledged power of attorney"),
    playbooks: [EST_PLAYBOOK_DURABLE_POA],
    missing_title: "Third-party reliance / acceptance clause missing",
    missing_description: "No third-party reliance / acceptance clause was found.",
    explanation:
      "UPOAA §§ 119–120 protect third parties who accept the POA in good faith; reciting this encourages banks / institutions to honor the POA without delay.",
    recommendation:
      "Add 'Third-Party Reliance' clause invoking UPOAA § 119–120 (or state equivalent) protection for accepting institutions.",
    present_patterns: [/(third.?party|reliance|acceptance)/i, /(good\s+faith|119|120|liability)/i],
    default_severity: "warning",
  }),
  presence({
    id: "EST-037",
    name: "Notarial acknowledgment + recording (for real property)",
    description:
      "Durable POA must be notarized; recording is needed where real property is involved.",
    citation: upoaa("105", "Execution"),
    playbooks: [EST_PLAYBOOK_DURABLE_POA],
    missing_title: "Notary / recording clause missing",
    missing_description: "No notary / recording clause was found.",
    explanation:
      "UPOAA § 105 requires notarial acknowledgment; recording with the county recorder is required for POAs used to convey / encumber real property. Execution formalities cannot be verified from text — see EST-060.",
    recommendation:
      "Add notarial acknowledgment block and (if real property) recording instructions.",
    present_patterns: [
      /(notary|notar(y|ial)|acknowledg(ment|ed))/i,
      /(record|recording|county\s+recorder)/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// N.6 — Prenuptial agreement. 8 rules: EST-038..EST-045.
// ────────────────────────────────────────────────────────────────────

const PRENUP_RULES: Rule[] = [
  presence({
    id: "EST-038",
    name: "Parties + contemplation of marriage recital",
    description:
      "Prenup must identify parties and recite that the agreement is made in contemplation of marriage.",
    citation: upmaa("3", "Formation"),
    playbooks: [EST_PLAYBOOK_PRENUP],
    missing_title: "Parties / contemplation-of-marriage clause missing",
    missing_description: "No clause was found identifying parties and contemplation of marriage.",
    explanation:
      "UPMAA / UPAA require contemplation-of-marriage recital; absent the recital, the document is not a prenup.",
    recommendation:
      "Add 'Parties' identifying both prospective spouses and reciting contemplation of marriage.",
    present_patterns: [
      /(prospective\s+spouses?|future\s+spouses?)/i,
      /(contemplation\s+of\s+marriage|in\s+anticipation\s+of\s+marriage|marriage\s+is\s+contemplated)/i,
    ],
  }),
  presence({
    id: "EST-039",
    name: "Financial disclosure schedules + adequacy recital",
    description:
      "Prenup must include financial disclosure schedules and recital that disclosures are fair and reasonable.",
    citation: upmaa("9", "Disclosure"),
    playbooks: [EST_PLAYBOOK_PRENUP],
    missing_title: "Financial disclosure / adequacy clause missing",
    missing_description: "No financial-disclosure / adequacy-recital clause was found.",
    explanation:
      "Failure to disclose is the leading ground for invalidation. UPMAA § 9 requires fair and reasonable disclosure or knowing waiver.",
    recommendation:
      "Attach Schedule A (party 1 assets / debts) and Schedule B (party 2 assets / debts) with an adequacy recital and any knowing waiver.",
    present_patterns: [
      /(disclosure|schedule\s+a|schedule\s+b|assets\s+and\s+liabilities)/i,
      /(fair\s+and\s+reasonable|adequate|knowing\s+waiver)/i,
    ],
  }),
  presence({
    id: "EST-040",
    name: "Separate vs marital property characterization",
    description:
      "Prenup must characterize separate vs marital / community property and its post-marriage treatment.",
    citation: upmaa("9", "Permitted terms"),
    playbooks: [EST_PLAYBOOK_PRENUP],
    missing_title: "Property characterization clause missing",
    missing_description: "No property-characterization clause was found.",
    explanation:
      "The central operative function of a prenup is to override default state characterization rules. State-by-state distinctions (community vs equitable distribution) drive drafting.",
    recommendation:
      "Add 'Property Characterization' defining separate, marital, community property, and the treatment of appreciation / income from separate property.",
    present_patterns: [
      /(separate\s+property|marital\s+property|community\s+property)/i,
      /(appreciation|income\s+from|transmutation|commingl)/i,
    ],
  }),
  presence({
    id: "EST-041",
    name: "Alimony / spousal-support waiver or terms",
    description:
      "Prenup should address alimony / spousal support (waiver, formula, or cross-reference to state default).",
    citation: upmaa("10", "Limitations"),
    playbooks: [EST_PLAYBOOK_PRENUP],
    missing_title: "Alimony / spousal-support clause missing",
    missing_description: "No alimony / spousal-support clause was found.",
    explanation:
      "Alimony waivers are heavily scrutinized and unenforceable in some states (CA permits with counsel; some states refuse). UPMAA § 10(a)(4) permits with limitations.",
    recommendation:
      "Add 'Spousal Support' addressing alimony — waiver, formula, or default — with attention to state-specific enforceability (e.g., CA Fam. § 1612(c) counsel requirement).",
    present_patterns: [
      /(alimony|spousal\s+support|maintenance)/i,
      /(waive(s|d|r)?|formula|amount|duration)/i,
    ],
  }),
  presence({
    id: "EST-042",
    name: "Estate / inheritance rights",
    description:
      "Prenup may waive elective-share / homestead / family-allowance / intestate rights (and should address probate coordination).",
    citation: upmaa("9", "Permitted terms"),
    playbooks: [EST_PLAYBOOK_PRENUP],
    missing_title: "Estate / inheritance rights clause missing",
    missing_description: "No estate / inheritance rights clause was found.",
    explanation:
      "UPMAA § 9 expressly permits waiver of elective share, homestead, and intestate rights. Without waiver, surviving spouse retains default elective-share rights.",
    recommendation:
      "Add 'Estate Rights' addressing elective share, homestead allowance, family allowance, intestate share, and beneficiary designations.",
    present_patterns: [
      /(elective\s+share|homestead\s+allowance|family\s+allowance|intestate)/i,
      /(waive(s|d|r)?|estate|inheritance)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-043",
    name: "Independent counsel recital + opportunity to consult",
    description:
      "Prenup should recite that each party was represented by (or had opportunity to consult) independent counsel.",
    citation: upmaa("9", "Voluntary execution"),
    playbooks: [EST_PLAYBOOK_PRENUP],
    missing_title: "Independent counsel recital missing",
    missing_description: "No independent-counsel recital was found.",
    explanation:
      "Independent counsel is critical to enforceability (and required in CA for alimony waivers per Fam. § 1612(c)). Adequate time to review is also a factor.",
    recommendation:
      "Add 'Independent Counsel' reciting each party was represented (or knowingly waived counsel) and had adequate time to review.",
    present_patterns: [
      /(independent\s+counsel|separate\s+counsel|own\s+attorney)/i,
      /(opportunity\s+to\s+consult|adequate\s+time|waive|represented\s+by)/i,
    ],
  }),
  presence({
    id: "EST-044",
    name: "Choice of law + venue",
    description:
      "Prenup should specify governing law and venue (state where parties expect to marry / reside).",
    citation: upmaa("11", "Choice of law"),
    playbooks: [EST_PLAYBOOK_PRENUP],
    missing_title: "Choice-of-law / venue clause missing",
    missing_description: "No choice-of-law / venue clause was found.",
    explanation:
      "UPMAA § 11 honors the parties' choice of law; absent choice, the law of the state where the agreement is signed applies.",
    recommendation:
      "Add 'Governing Law and Venue' specifying state law that will govern enforceability and venue.",
    present_patterns: [/(governing\s+law|choice\s+of\s+law)/i, /(venue|jurisdiction)/i],
    default_severity: "warning",
  }),
  presence({
    id: "EST-045",
    name: "Execution — signatures + notarial acknowledgment + time-before-marriage",
    description:
      "Prenup must be executed in writing, with signatures and notary; should be signed adequately before the wedding.",
    citation: upmaa("4", "Execution"),
    playbooks: [EST_PLAYBOOK_PRENUP],
    missing_title: "Execution / notary clause missing",
    missing_description: "No execution / notary clause was found.",
    explanation:
      "UPMAA § 4 requires a signed writing. Signing under duress, on the eve of the wedding, can be an enforceability red flag. Execution formalities cannot be verified from text — see EST-060.",
    recommendation:
      "Add execution block with notarial acknowledgment + a recital of when the agreement was executed relative to the wedding.",
    present_patterns: [
      /(signature|signed)/i,
      /(notary|notar(y|ial)|acknowledg(ment|ed))/i,
      /(date|prior\s+to\s+marriage|before\s+the\s+wedding)/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// N.7 — Postnuptial agreement. 7 rules: EST-046..EST-052.
// ────────────────────────────────────────────────────────────────────

const POSTNUP_RULES: Rule[] = [
  presence({
    id: "EST-046",
    name: "Parties + during-marriage recital",
    description:
      "Postnup must identify the spouses and recite the agreement is made during the marriage.",
    citation: upmaa("3", "Formation"),
    playbooks: [EST_PLAYBOOK_POSTNUP],
    missing_title: "Parties / during-marriage clause missing",
    missing_description: "No clause was found identifying spouses and the during-marriage status.",
    explanation:
      "Postnups are more scrutinized than prenups because spouses owe heightened fiduciary duties (CA Fam. § 721, IL, NY). The during-marriage recital frames the analysis.",
    recommendation:
      "Add 'Parties' identifying the spouses and reciting that the parties are married and entering this agreement during the marriage.",
    present_patterns: [
      /(spouses|husband\s+and\s+wife|married\s+couple|parties)/i,
      /(during\s+the\s+marriage|during\s+our\s+marriage)/i,
    ],
  }),
  presence({
    id: "EST-047",
    name: "Consideration recital",
    description:
      "Postnup should recite consideration (mutual promises, continuation of marriage) — separate from the marriage itself.",
    citation: estPractice(
      "postnup-consideration",
      "Postnuptial consideration baseline (state-specific)",
      "https://www.americanbar.org/groups/family_law/",
    ),
    playbooks: [EST_PLAYBOOK_POSTNUP],
    missing_title: "Consideration recital missing",
    missing_description: "No consideration recital was found.",
    explanation:
      "Some states refuse to recognize the marriage itself as consideration for a postnup. Mutual promises, settlement of disputes, or continued cohabitation may suffice.",
    recommendation:
      "Add 'Consideration' reciting the mutual promises and consideration supporting the postnup.",
    present_patterns: [
      /(consideration|in\s+consideration\s+of)/i,
      /(mutual\s+promises|settle\s+disputes|continued\s+cohabitation)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-048",
    name: "Heightened fiduciary disclosure",
    description:
      "Postnup must include full financial disclosure — heightened standard given spouses' fiduciary duties.",
    citation: upmaa("9", "Disclosure"),
    playbooks: [EST_PLAYBOOK_POSTNUP],
    missing_title: "Fiduciary disclosure clause missing",
    missing_description: "No fiduciary-disclosure / disclosure-schedules clause was found.",
    explanation:
      "Spouses owe each other fiduciary duties (e.g., CA Fam. § 721); disclosure is heightened compared to prenup. Failure to fully disclose is the leading ground for invalidation.",
    recommendation:
      "Attach Schedule A / B with full assets / debts / income and recite the disclosure was complete and adequate.",
    present_patterns: [
      /(disclosure|schedule\s+a|schedule\s+b|fiduciary\s+(duty|duties)|fully\s+disclos)/i,
      /(assets\s+and\s+(debts|liabilities)|income|fair\s+and\s+reasonable)/i,
    ],
  }),
  presence({
    id: "EST-049",
    name: "Property characterization + transmutation",
    description:
      "Postnup must address transmutation of property and characterization of community / separate / marital property.",
    citation: upmaa("9", "Permitted terms"),
    playbooks: [EST_PLAYBOOK_POSTNUP],
    missing_title: "Property characterization / transmutation clause missing",
    missing_description: "No property-characterization / transmutation clause was found.",
    explanation:
      "Transmutation rules vary sharply (CA Fam. § 852 requires express written waiver). The postnup commonly recharacterizes property to define separate / community ownership going forward.",
    recommendation:
      "Add 'Property Characterization and Transmutation' defining each party's separate / marital / community property, with explicit transmutation language where required.",
    present_patterns: [
      /(transmut|recharacteriz|recharacterize)/i,
      /(separate\s+property|marital\s+property|community\s+property)/i,
    ],
  }),
  presence({
    id: "EST-050",
    name: "Spousal support / waiver",
    description: "Postnup should address spousal support — waiver, formula, or state-default.",
    citation: upmaa("10", "Limitations"),
    playbooks: [EST_PLAYBOOK_POSTNUP],
    missing_title: "Spousal support clause missing",
    missing_description: "No spousal-support / waiver clause was found.",
    explanation:
      "Same scrutiny as prenup; some states refuse alimony waivers in postnups. CA requires independent counsel for alimony waivers in postnups.",
    recommendation:
      "Add 'Spousal Support' addressing waiver / formula / default with attention to state-specific enforceability.",
    present_patterns: [
      /(alimony|spousal\s+support|maintenance)/i,
      /(waive(s|d|r)?|formula|amount|duration)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-051",
    name: "Independent counsel + voluntary execution",
    description:
      "Postnup should recite each party had independent counsel and executed voluntarily.",
    citation: estPractice(
      "postnup-counsel",
      "Postnup independent-counsel baseline (CA Fam. § 1615 / NY DRL § 236(B))",
      "https://www.americanbar.org/groups/family_law/",
    ),
    playbooks: [EST_PLAYBOOK_POSTNUP],
    missing_title: "Independent counsel / voluntariness clause missing",
    missing_description: "No independent-counsel / voluntariness clause was found.",
    explanation:
      "Independent counsel is heavily weighted in postnup enforceability. Coercion / duress between spouses is a particular concern.",
    recommendation:
      "Add 'Independent Counsel and Voluntariness' reciting representation + voluntary execution + adequate time to review.",
    present_patterns: [
      /(independent\s+counsel|separate\s+counsel|own\s+attorney)/i,
      /(voluntar(y|ily)|no\s+(duress|coercion))/i,
    ],
  }),
  presence({
    id: "EST-052",
    name: "Execution — signatures + notarial acknowledgment",
    description: "Postnup must be executed in writing, signed, and (in many states) notarized.",
    citation: upmaa("4", "Execution"),
    playbooks: [EST_PLAYBOOK_POSTNUP],
    missing_title: "Execution / notary clause missing",
    missing_description: "No execution / notary clause was found.",
    explanation:
      "Written + signed + (in many states) notarized. Execution formalities cannot be verified from text — see EST-060.",
    recommendation:
      "Add execution block with signatures and notarial acknowledgment where required.",
    present_patterns: [/(signature|signed)/i, /(notary|notar(y|ial)|acknowledg(ment|ed))/i],
  }),
];

// ────────────────────────────────────────────────────────────────────
// N.8 — Family-law MSA (separation / marital settlement). 7 rules: EST-053..EST-059.
// ────────────────────────────────────────────────────────────────────

const FAMILY_MSA_RULES: Rule[] = [
  presence({
    id: "EST-053",
    name: "Parties + separation date recital",
    description: "Family-law MSA must identify the spouses and recite the date of separation.",
    citation: stateAdv(
      "divorce-codes",
      "State divorce / family law codes (CA Fam. § 70; NY DRL § 170)",
    ),
    playbooks: [EST_PLAYBOOK_FAMILY_MSA],
    missing_title: "Parties / separation date clause missing",
    missing_description: "No clause was found identifying spouses and date of separation.",
    explanation:
      "Date of separation drives property characterization in community-property states (CA Fam. § 70). Identification is required for incorporation into divorce judgment.",
    recommendation:
      "Add 'Parties and Date of Separation' identifying the spouses and stating the date of separation.",
    present_patterns: [
      /(spouses|husband\s+and\s+wife|petitioner\s+and\s+respondent)/i,
      /(date\s+of\s+separation|separated\s+on)/i,
    ],
  }),
  presence({
    id: "EST-054",
    name: "Division of marital / community property + debts",
    description: "MSA must allocate property and debts between the parties.",
    citation: stateAdv("property-div", "State property-division statutes"),
    playbooks: [EST_PLAYBOOK_FAMILY_MSA],
    missing_title: "Property / debt division clause missing",
    missing_description: "No property / debt division clause was found.",
    explanation:
      "Property + debt allocation is the central operative function of the MSA. Equitable distribution (most states) or community property (CA / TX / etc.) drives the framework.",
    recommendation:
      "Add 'Division of Property and Debts' allocating real property, financial accounts, retirement, vehicles, personal property, business interests, and debts.",
    present_patterns: [
      /(division\s+of\s+(property|assets)|allocation\s+of\s+(property|assets))/i,
      /(real\s+property|retirement|accounts?|debts?|liabilities)/i,
    ],
  }),
  presence({
    id: "EST-055",
    name: "Spousal support / alimony — amount + duration",
    description: "MSA must address spousal support / alimony or expressly waive.",
    citation: stateAdv("alimony", "State alimony / spousal-support statutes"),
    playbooks: [EST_PLAYBOOK_FAMILY_MSA],
    missing_title: "Spousal support clause missing",
    missing_description: "No spousal-support / alimony / waiver clause was found.",
    explanation:
      "MSAs that fail to address spousal support leave the issue for later judicial determination — often contrary to parties' intent.",
    recommendation:
      "Add 'Spousal Support' specifying amount, duration, modifiability, and termination triggers (or expressly waive).",
    present_patterns: [
      /(spousal\s+support|alimony|maintenance)/i,
      /(amount|duration|modifiable|terminat)/i,
    ],
  }),
  presence({
    id: "EST-056",
    name: "Child custody + parenting plan + child support",
    description:
      "MSAs involving minor children must address custody, parenting plan, and child support.",
    citation: stateAdv(
      "custody-support",
      "State child-custody and support statutes; UMDA / state child-support guidelines",
    ),
    playbooks: [EST_PLAYBOOK_FAMILY_MSA],
    missing_title: "Custody / parenting plan / child support clause missing",
    missing_description:
      "No clause was found addressing custody, parenting plan, or child support.",
    explanation:
      "Family-law MSAs are routinely required to include detailed parenting plans + child-support calculations. Best-interest-of-the-child standard governs custody.",
    recommendation:
      "Add 'Custody', 'Parenting Plan' (legal + physical + visitation), and 'Child Support' (with state guideline calculation).",
    present_patterns: [
      /(custody|parenting\s+plan|visitation|parenting\s+time)/i,
      /(child\s+support|guidelines?|best\s+interests?)/i,
    ],
  }),
  presence({
    id: "EST-057",
    name: "Tax provisions — dependency exemption / filing status",
    description:
      "MSA should address tax issues (dependency / child tax credit, filing status, IRC § 71 alimony treatment post-TCJA).",
    citation: estPractice(
      "msa-tax",
      "MSA tax baseline (post-TCJA — § 71 alimony deduction repealed)",
      "https://www.irs.gov/taxtopics/tc452",
    ),
    playbooks: [EST_PLAYBOOK_FAMILY_MSA],
    missing_title: "Tax provisions clause missing",
    missing_description: "No tax-provisions clause was found.",
    explanation:
      "Post-TCJA (effective for 2019+ divorces), alimony is no longer deductible / taxable. Dependency-exemption / Form 8332 release affect child tax credit. Ignored at the parties' peril.",
    recommendation:
      "Add 'Tax Provisions' covering filing status, dependency exemption (Form 8332), child tax credit allocation, and post-TCJA alimony treatment.",
    present_patterns: [
      /(tax|filing\s+status|dependency|form\s+8332|tcja)/i,
      /(child\s+tax\s+credit|exemption|deduction)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-058",
    name: "Retirement-plan division — QDRO / DRO",
    description:
      "MSAs dividing qualified retirement plans must reference a QDRO (or DRO for federal employees).",
    citation: estPractice(
      "qdro",
      "ERISA QDRO / DRO baseline (29 U.S.C. § 1056(d)(3))",
      "https://www.dol.gov/agencies/ebsa/laws-and-regulations/laws/erisa",
    ),
    playbooks: [EST_PLAYBOOK_FAMILY_MSA],
    missing_title: "QDRO / retirement division clause missing",
    missing_description: "No QDRO / DRO retirement-plan division clause was found.",
    explanation:
      "Under ERISA 29 U.S.C. § 1056(d)(3), a Qualified Domestic Relations Order is required to divide qualified plans; DRO required for federal employees (FERS / CSRS / TSP).",
    recommendation:
      "Add 'Retirement Plan Division' identifying the plans and the form of order (QDRO / DRO) required to effect division.",
    present_patterns: [
      /(qdro|domestic\s+relations\s+order|retirement\s+plan)/i,
      /(401\(k\)|pension|ira|fers|csrs|tsp)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "EST-059",
    name: "Incorporation / merger into judgment + execution",
    description:
      "MSA must address whether it will be incorporated / merged into the divorce judgment and include execution block.",
    citation: stateAdv("merger", "State merger / incorporation doctrine (modifiability)"),
    playbooks: [EST_PLAYBOOK_FAMILY_MSA],
    missing_title: "Incorporation / merger / execution clause missing",
    missing_description: "No incorporation / merger / execution clause was found.",
    explanation:
      "Merger affects modifiability of spousal support and contempt enforcement. The parties typically choose incorporation without merger to preserve contractual enforcement.",
    recommendation:
      "Add 'Incorporation' specifying incorporation / merger and a notarized execution block. Execution formalities cannot be verified from text — see EST-060.",
    present_patterns: [
      /(incorporat(ion|ed)|merg(e|er|ed)|surviv)/i,
      /(judgment|decree|notar|signed|execution)/i,
    ],
  }),
];

// ────────────────────────────────────────────────────────────────────
// EST-060 — Always-fires execution-formality disclaimer (per spec §6.N caveat).
// ────────────────────────────────────────────────────────────────────

const EXECUTION_DISCLAIMER_RULE: Rule = {
  id: "EST-060",
  version: "1.0.0",
  name: "Execution formalities cannot be verified from text alone",
  category: CATEGORY,
  default_severity: "info",
  description:
    "Per spec-v4.md §6.N caveat, every output in the trust / estate / family sub-domain must say explicitly that execution formalities (witnesses, notary, holographic state-specific requirements) cannot be verified from a docx alone. This rule emits that disclaimer on every analysis run in this sub-domain.",
  dkb_citations: ["est-execution-disclaimer"],
  applies_to_playbooks: [...EST_PLAYBOOK_IDS],
  check(ctx: RuleContext): Finding | null {
    return makeFinding({
      rule: this as Rule,
      title: "Execution formalities cannot be verified from text alone",
      description:
        "Vaulytica lints the document text. Execution formalities — witness signatures and competence, notarial acknowledgment, holographic-will requirements, and state-specific timing rules — cannot be verified from a docx / pdf alone. Confirm execution formalities under the law of the applicable state and the document's intended use.",
      excerptText: "(disclaimer applies to every trust / estate / family analysis run)",
      explanation:
        "Trust / estate / family documents (wills, trusts, advance directives, powers of attorney, prenups, postnups, family-law MSAs) live or die on execution formalities that exist outside the document text — witnesses present at signing, notarial acknowledgment, in some states holographic / handwritten requirements, age and competence of the testator / declarant / principal at signing. These cannot be verified from a digital file alone.",
      recommendation:
        "Confirm execution formalities under the applicable state's probate / advance-directive / POA / family-law statutes before relying on the document.",
      position: docTop(ctx),
      source_citations: [
        {
          id: "est-execution-disclaimer",
          source:
            "Vaulytica spec-v4.md §6.N caveat — execution-formality disclaimer required on every output in trust / estate / family sub-domain",
          source_url: "https://vaulytica.com/#spec-v4-6n-trust-estate-execution-disclaimer",
          retrieved_at: "2026-05-16T00:00:00Z",
          license: "MIT",
          license_url: "https://opensource.org/licenses/MIT",
        },
      ],
    });
  },
};

// ────────────────────────────────────────────────────────────────────
// Aggregate. 60 rules total.
// ────────────────────────────────────────────────────────────────────

export const TRUST_ESTATE_RULES: Rule[] = [
  ...WILL_RULES,
  ...REVOCABLE_TRUST_RULES,
  ...ADVANCE_DIRECTIVE_RULES,
  ...HEALTHCARE_POA_RULES,
  ...DURABLE_POA_RULES,
  ...PRENUP_RULES,
  ...POSTNUP_RULES,
  ...FAMILY_MSA_RULES,
  EXECUTION_DISCLAIMER_RULE,
];

export {
  WILL_RULES,
  REVOCABLE_TRUST_RULES,
  ADVANCE_DIRECTIVE_RULES,
  HEALTHCARE_POA_RULES,
  DURABLE_POA_RULES,
  PRENUP_RULES,
  POSTNUP_RULES,
  FAMILY_MSA_RULES,
  EXECUTION_DISCLAIMER_RULE,
};
