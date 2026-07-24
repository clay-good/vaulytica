/**
 * v4 Insurance and risk ruleset — 25 rules
 * (spec-v4.md §6.K, Step 54).
 *
 * Four new playbooks: insurance policy summary / declarations,
 * insurance endorsement review, standalone indemnification agreement,
 * and hold-harmless agreement. K.1 (Certificate of Insurance / ACORD
 * 25) continues under v3 `coi`.
 *
 * Rule ids are flat `INS-NNN` (001..025).
 */

import type { Rule } from "../../../finding.js";
import {
  buildV4PresenceRule,
  buildV4LanguageRule,
  type V4PresenceSpec,
  type V4LanguageSpec,
} from "../_helpers.js";
import {
  INS_PLAYBOOK_POLICY,
  INS_PLAYBOOK_ENDORSEMENT,
  INS_PLAYBOOK_INDEMNIFICATION,
  INS_PLAYBOOK_HOLD_HARMLESS,
  isoForm,
  stateInsCode,
  antiIndemnity,
  insPractice,
} from "./_helpers.js";

const CATEGORY = "insurance";

const presence = (s: Omit<V4PresenceSpec, "category">): Rule =>
  buildV4PresenceRule({ ...s, category: CATEGORY });
const language = (s: Omit<V4LanguageSpec, "category">): Rule =>
  buildV4LanguageRule({ ...s, category: CATEGORY });

// ────────────────────────────────────────────────────────────────────
// K.2 — Insurance Policy Summary / Declarations. 6 rules: INS-001..INS-006.
// ────────────────────────────────────────────────────────────────────

const POLICY_SUMMARY_RULES: Rule[] = [
  presence({
    id: "INS-001",
    name: "Named Insured + producer / broker",
    description:
      "Declarations must identify Named Insured (and any additional insureds) and producer.",
    citation: stateInsCode(),
    playbooks: [INS_PLAYBOOK_POLICY],
    missing_title: "Named Insured / producer clause missing",
    missing_description: "No clause was found identifying the Named Insured or the producer.",
    explanation:
      "Coverage rights run to the Named Insured. State insurance codes require declarations to identify the insured and producer / broker.",
    recommendation:
      "Add 'Named Insured' (full legal entity) and 'Producer / Broker' (agent name + license number).",
    present_patterns: [/named\s+insured/i, /(producer|broker|agent)/i],
  }),
  presence({
    id: "INS-002",
    name: "Policy period — inception + expiration",
    description: "Declarations must state the policy period (inception and expiration).",
    citation: stateInsCode(),
    playbooks: [INS_PLAYBOOK_POLICY],
    missing_title: "Policy period clause missing",
    missing_description: "No policy period (inception / expiration) was identified.",
    explanation:
      "Coverage is bounded by policy period; ambiguity invites *Montrose* / *Continental* trigger-of-coverage disputes.",
    recommendation:
      "Add 'Policy Period' with specific inception and expiration dates and time-of-day at the Named Insured's address.",
    present_patterns: [
      /policy\s+period/i,
      /(inception|effective\s+date)/i,
      /(expiration|expir|to)/i,
    ],
  }),
  presence({
    id: "INS-003",
    name: "Limits of liability — each occurrence + aggregate",
    description: "Declarations must state limits (each occurrence + aggregate / per-claim).",
    citation: stateInsCode(),
    playbooks: [INS_PLAYBOOK_POLICY],
    missing_title: "Limits of liability clause missing",
    missing_description: "No limits-of-liability clause was found.",
    explanation:
      "Limits define the insurer's maximum exposure; both per-occurrence and aggregate (or claims-made per-claim) limits should be stated.",
    recommendation:
      "Add 'Limits of Liability' for each coverage part — Each Occurrence / Per-Claim, General Aggregate, Products-Completed Operations Aggregate, etc.",
    present_patterns: [
      /(limits?\s+of\s+(liability|insurance)|limit)/i,
      /(each\s+occurrence|per\s+claim)/i,
      /(aggregate|general\s+aggregate)/i,
    ],
  }),
  presence({
    id: "INS-004",
    name: "Premium + deductibles / SIR",
    description: "Declarations must state the premium and any deductible / self-insured retention.",
    citation: stateInsCode(),
    playbooks: [INS_PLAYBOOK_POLICY],
    missing_title: "Premium / deductible clause missing",
    missing_description: "No premium or deductible / SIR clause was found.",
    explanation:
      "Premium + deductible / SIR are the economic core of the policy and must appear on the declarations.",
    recommendation:
      "Add 'Premium' (total + by coverage part) and 'Deductible / SIR' applicable to each coverage.",
    present_patterns: [/premium/i, /(deductible|self.?insured\s+retention|sir)/i],
  }),
  presence({
    id: "INS-005",
    name: "Coverage parts / forms enumerated by form number + edition",
    description:
      "Declarations must list coverage parts / forms attached, identified by ISO / AAIS form number + edition.",
    citation: isoForm("various", "ISO commercial-lines form library"),
    playbooks: [INS_PLAYBOOK_POLICY],
    missing_title: "Coverage parts / forms enumeration missing",
    missing_description:
      "No enumeration of coverage parts / forms (with form numbers + editions) was found.",
    explanation:
      "Coverage is defined by the specific form + edition; an unidentified 'GL' tells you little ('CG 00 01 04 13' identifies the precise policy language).",
    recommendation:
      "Add 'Forms Schedule' listing each form and endorsement by form number, edition date, and title.",
    present_patterns: [
      /(form\s+(no\.?|number)|cg\s+\d|cp\s+\d|aaic|aais)/i,
      /(edition|ed\.?|\(\d{2}\/\d{2}\))/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "INS-006",
    name: "Claims-made vs occurrence + retroactive date (claims-made)",
    description:
      "Declarations should specify claims-made or occurrence trigger; claims-made policies must state retroactive date and ERP.",
    citation: insPractice(
      "claims-made-trigger",
      "Claims-made coverage baseline (retroactive date + ERP)",
      "https://www.irmi.com/articles/expert-commentary/claims-made-and-reported-policy",
    ),
    playbooks: [INS_PLAYBOOK_POLICY],
    missing_title: "Coverage trigger / retroactive-date clause missing",
    missing_description:
      "No clause was found specifying the coverage trigger (claims-made vs occurrence) or retroactive date.",
    explanation:
      "Claims-made gaps (no retroactive date, no ERP) are a frequent professional-liability E&O issue. Occurrence-trigger should also be marked.",
    recommendation:
      "Add 'Coverage Trigger' identifying claims-made vs occurrence; for claims-made, add 'Retroactive Date' and 'Extended Reporting Period' (ERP) provisions.",
    present_patterns: [
      /(claims.made|occurrence)/i,
      /(retroactive\s+date|prior\s+acts)/i,
      /(extended\s+reporting\s+period|erp|tail)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// K.3 — Insurance Endorsement Review. 6 rules: INS-007..INS-012.
// ────────────────────────────────────────────────────────────────────

const ENDORSEMENT_RULES: Rule[] = [
  presence({
    id: "INS-007",
    name: "Form number + edition identification",
    description: "Endorsement must identify its form number and edition date.",
    citation: isoForm("various", "ISO endorsement library"),
    playbooks: [INS_PLAYBOOK_ENDORSEMENT],
    missing_title: "Form number / edition clause missing",
    missing_description: "No form number or edition identification was found in the endorsement.",
    explanation:
      "Endorsement effect depends on exact ISO / AAIS form + edition. Without identification, coverage cannot be verified.",
    recommendation:
      "Add the form number, edition date, and ISO / AAIS / state-specific origin in the header (e.g., 'CG 20 10 04 13').",
    present_patterns: [
      /(cg\s+\d|cp\s+\d|cu\s+\d|aais|iso)\s*\d/i,
      /(edition|ed\.?|\(\d{2}\/\d{2}\))/i,
    ],
  }),
  presence({
    id: "INS-008",
    name: "Coverage being modified identified",
    description: "Endorsement must identify the coverage / policy provisions being modified.",
    citation: stateInsCode(),
    playbooks: [INS_PLAYBOOK_ENDORSEMENT],
    missing_title: "Modified-coverage identification missing",
    missing_description:
      "No clause was found identifying the coverage / provisions being modified.",
    explanation:
      "Endorsements amend or replace specific policy provisions; the affected provision must be identified so insureds and counsel can read it together with the underlying policy.",
    recommendation:
      "Add 'Coverage Modified' identifying the underlying coverage form, section, and paragraph being amended.",
    present_patterns: [
      /(this\s+endorsement\s+modifies|amends?|changes?\s+the\s+policy)/i,
      /(section|paragraph|provision)/i,
    ],
  }),
  presence({
    id: "INS-009",
    name: "Effective date of endorsement",
    description:
      "Endorsement must state its effective date (or that it is effective at policy inception).",
    citation: stateInsCode(),
    playbooks: [INS_PLAYBOOK_ENDORSEMENT],
    missing_title: "Endorsement effective-date clause missing",
    missing_description: "No effective date was found for the endorsement.",
    explanation:
      "Endorsements may attach mid-term; the effective date is essential for coverage-trigger / claims analysis.",
    recommendation: "Add 'Effective Date' (date or 'at policy inception').",
    present_patterns: [/(effective\s+date|effective\s+as\s+of|effective\s+at)/i, /\d|inception/i],
  }),
  language({
    id: "INS-010",
    name: "Coverage-restricting endorsements flagged for review",
    description:
      "Coverage-restricting endorsements (exclusions, sublimits) should be flagged to underwriters and the broker.",
    citation: insPractice(
      "restricting-endorsements",
      "Coverage-restricting endorsement review baseline",
      "https://www.irmi.com/articles/expert-commentary/exclusions",
    ),
    playbooks: [INS_PLAYBOOK_ENDORSEMENT],
    bad_patterns: [
      /(absolute\s+exclusion|total\s+exclusion).{0,80}(pollution|cyber|communicable\s+disease|silica|asbestos|abuse|molest)/is,
      /sublimit.{0,80}(\$\s*\d{1,2}[,.]?\d{0,3}\s*(thousand|k\b))/is,
      /excludes?\s+all\s+coverage/i,
    ],
    exclude_if: [/(?:does|do|shall|will)\s+not\s+exclude/i],
    bad_title: "Coverage-restricting endorsement flagged for review",
    bad_description:
      "The endorsement contains an absolute exclusion, severe sublimit, or all-coverage exclusion that warrants underwriter / broker review.",
    explanation:
      "Coverage-restricting endorsements (e.g., absolute pollution / cyber / communicable disease exclusions, $25K sublimits) materially shrink coverage and should be negotiated or replaced with narrower forms.",
    recommendation:
      "Flag to broker / underwriter for negotiation; consider buy-back endorsements or a narrower exclusion form.",
    default_severity: "warning",
  }),
  presence({
    id: "INS-011",
    name: "Additional Insured wording — privity / limitations (ISO CG 20 10 / CG 20 38)",
    description:
      "Additional-insured endorsements should be on a current ISO form (CG 20 10 04 13 or later, CG 20 38, CG 20 37) — older 1985 / 2001 forms grant broader coverage.",
    citation: isoForm("CG 20 10", "Additional Insured — Owners, Lessees or Contractors"),
    playbooks: [INS_PLAYBOOK_ENDORSEMENT],
    missing_title: "Additional Insured form / edition clause missing",
    missing_description:
      "No clause was found tying additional-insured grants to a specific ISO form / edition.",
    explanation:
      "Post-2013 ISO additional-insured forms restrict coverage to liability caused by the named insured (CG 20 10 04 13 + CG 20 37 04 13). Older editions grant broader coverage but are sometimes unavailable. Identify the form + edition.",
    recommendation:
      "Identify the AI endorsement form + edition (e.g., 'CG 20 10 04 13 — Additional Insured — Owners, Lessees or Contractors — Scheduled Person Or Organization').",
    present_patterns: [
      /(additional\s+insured|cg\s+20\s+10|cg\s+20\s+37|cg\s+20\s+38)/i,
      /(edition|ed\.?|04\s*13|11\s*85|10\s*01|04\s*13)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "INS-012",
    name: "Waiver of subrogation (where required by contract)",
    description:
      "If the underlying contract requires waiver of subrogation, the endorsement (CG 24 04 or equivalent) must be attached.",
    citation: isoForm("CG 24 04", "Waiver of Transfer of Rights of Recovery Against Others To Us"),
    playbooks: [INS_PLAYBOOK_ENDORSEMENT],
    missing_title: "Waiver-of-subrogation endorsement missing",
    missing_description: "No waiver-of-subrogation endorsement was found.",
    explanation:
      "Many leases, construction contracts, and service agreements require a waiver of subrogation in favor of the other party. Without the CG 24 04 (or equivalent), the insurer can sue under subrogation.",
    recommendation:
      "Attach 'CG 24 04 — Waiver of Transfer of Rights of Recovery Against Others To Us' (or equivalent) when the contract requires waiver.",
    present_patterns: [
      /(waiver\s+of\s+subrogation|waiv(es?|e|ed)\s+(its\s+)?(rights?\s+of\s+)?subrogation|cg\s+24\s+04)/i,
      /(transfer\s+of\s+rights\s+of\s+recovery)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// K.4 — Indemnification Agreement (standalone). 7 rules: INS-013..INS-019.
// ────────────────────────────────────────────────────────────────────

const INDEMNIFICATION_AGREEMENT_RULES: Rule[] = [
  presence({
    id: "INS-013",
    name: "Indemnitor / indemnitee identified",
    description:
      "Indemnification agreement must identify indemnitor and indemnitee (and any third-party beneficiaries).",
    citation: antiIndemnity(),
    playbooks: [INS_PLAYBOOK_INDEMNIFICATION],
    missing_title: "Indemnitor / indemnitee identification missing",
    missing_description: "No clause was found identifying the indemnitor and indemnitee.",
    explanation:
      "Indemnity rights run between identified parties; affiliates / officers / agents who benefit should be enumerated.",
    recommendation:
      "Add 'Parties' identifying indemnitor and indemnitee, including affiliates / officers / directors / employees / agents.",
    present_patterns: [
      /(indemnit(or|ee|y|or)|indemnif(y|ies|ied))/i,
      /(parties|affiliate|officer|director|agent)/i,
    ],
  }),
  presence({
    id: "INS-014",
    name: "Scope of indemnity — Type I / II / III recital",
    description:
      "Agreement should specify the indemnity type — limited form (Type III), intermediate form (Type II), or broad form (Type I) — with the operative language for the chosen form.",
    citation: antiIndemnity(),
    playbooks: [INS_PLAYBOOK_INDEMNIFICATION],
    missing_title: "Scope of indemnity (Type I / II / III) clause missing",
    missing_description: "No clause was found specifying the type / scope of the indemnity.",
    explanation:
      "The three Types describe ascending breadth: Type III (limited — only indemnitor's own fault), Type II (intermediate — indemnitor's + concurrent negligence), Type I (broad — including indemnitee's sole negligence — often void by anti-indemnity statute).",
    recommendation:
      "Add a recital identifying the Type and matching operative language (e.g., 'caused by or arising from the negligence of indemnitor').",
    present_patterns: [
      /(limited\s+form|intermediate\s+form|broad\s+form|type\s+(i|ii|iii))/i,
      /(caused\s+by|arising\s+(out\s+)?of|attributable\s+to)/i,
      /negligen/i,
    ],
    default_severity: "warning",
  }),
  language({
    id: "INS-015",
    version: "1.1.0",
    name: "Broad-form indemnity (Type I) flagged for anti-indemnity scrutiny",
    description:
      "Type I (broad-form) indemnity is void in construction contexts in many states (CA § 2782, NY § 5-322.1, TX § 151).",
    citation: antiIndemnity(),
    playbooks: [INS_PLAYBOOK_INDEMNIFICATION],
    bad_patterns: [
      /indemnif(y|ies|ied|ying).{0,200}(including|even\s+(for|where)|regardless\s+of|notwithstanding).{0,200}(sole\s+negligence|own\s+negligence|active\s+negligence)/is,
      // The canonical Type I broad-form phrasing anti-indemnity statutes
      // target: indemnity for loss "caused IN WHOLE OR IN PART" by the
      // indemnitee's negligence. "in whole or in part" is the broad-form
      // hallmark — Type II ("to the extent") and Type III ("indemnitor's own
      // negligence") never use it, so it separates cleanly.
      /indemnif(y|ies|ied|ying)[^.]{0,200}\bin\s+whole\s+or\s+in\s+part\b/is,
      /indemnif(y|ies|ied|ying).{0,200}(any\s+and\s+all).{0,80}(claims|liabilit).{0,80}(caused\s+by\s+indemnitee|negligence\s+of\s+indemnitee)/is,
    ],
    exclude_if: [
      /(?:shall|will)\s+not\s+be\s+(?:obligated|required|liable)\s+to\s+indemnif/i,
      /\bnot\s+(?:be\s+)?(?:obligated|required)\s+to\s+indemnif/i,
    ],
    bad_title: "Type I broad-form indemnity flagged for anti-indemnity review",
    bad_description:
      "Agreement appears to indemnify indemnitee for indemnitee's own / sole / active negligence — void in construction contexts in many states.",
    explanation:
      "State anti-indemnity statutes (CA Civ. § 2782, NY Gen. Oblig. § 5-322.1, TX Ins. § 151, etc.) void indemnity for indemnitee's own / sole / active negligence in construction contracts; many states extend to oil-and-gas or transportation contexts.",
    recommendation:
      "Narrow to intermediate or limited form; add 'except to the extent caused by indemnitee's [sole / active / own] negligence' carve-out.",
    default_severity: "warning",
  }),
  presence({
    id: "INS-016",
    name: "Defense duty articulated separately from indemnity",
    description:
      "Agreement should separately articulate the duty to defend (broader than duty to indemnify under *Crawford v. Weather Shield*).",
    citation: insPractice(
      "duty-to-defend",
      "Crawford v. Weather Shield, 44 Cal. 4th 541 (2008) — duty to defend is broader than duty to indemnify",
      "https://www.law.cornell.edu/wex/duty_to_defend",
    ),
    playbooks: [INS_PLAYBOOK_INDEMNIFICATION],
    missing_title: "Defense-duty clause missing",
    missing_description: "No clause separately articulating the duty to defend was found.",
    explanation:
      "Under *Crawford v. Weather Shield*, an indemnity agreement may impose an immediate duty to defend against any claim potentially within indemnity even before liability is established. Practice: state the duty separately or expressly disclaim it.",
    recommendation:
      "Add 'Duty to Defend' clause separately articulating the obligation (including counsel selection, control of defense, and reimbursement timing) — or expressly disclaim it.",
    present_patterns: [/(duty\s+to\s+defend|defense\s+obligation)/i, /(defend|defense)/i],
    default_severity: "warning",
  }),
  presence({
    id: "INS-017",
    name: "Notice + tender + cooperation procedure",
    description:
      "Agreement must establish notice, tender, and cooperation procedure for indemnification claims.",
    citation: insPractice(
      "indemnity-procedure",
      "Indemnity claim procedure baseline (notice / tender / cooperation)",
      "https://www.americanbar.org/groups/litigation/",
    ),
    playbooks: [INS_PLAYBOOK_INDEMNIFICATION],
    missing_title: "Notice / tender / cooperation procedure missing",
    missing_description:
      "No clause was found establishing notice, tender, and cooperation procedure.",
    explanation:
      "Without a defined notice / tender / cooperation process, indemnitee may forfeit rights (late notice prejudice) or indemnitor may be left without information to defend.",
    recommendation:
      "Add 'Indemnification Procedure' covering written notice, tender deadline, indemnitor's election to defend, cooperation obligations, and consent-to-settle.",
    present_patterns: [
      /(notice|tender)/i,
      /cooperat/i,
      /(consent\s+to\s+settle|right\s+to\s+control)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "INS-018",
    name: "Insurance support — minimum limits matching indemnity",
    description:
      "Agreement should require insurance with limits matching the indemnity obligation (additional insured + waiver of subrogation).",
    citation: insPractice(
      "insurance-support",
      "Insurance-support baseline — required limits, additional insured, waiver of subrogation",
      "https://www.irmi.com/articles/expert-commentary/insurance-requirements-in-contracts",
    ),
    playbooks: [INS_PLAYBOOK_INDEMNIFICATION],
    missing_title: "Insurance-support clause missing",
    missing_description:
      "No clause was found requiring insurance with matching limits / additional insured / waiver of subrogation.",
    explanation:
      "Indemnity without supporting insurance is uncollectable. Standard pattern: minimum CGL / professional / auto / WC limits, additional insured (ISO CG 20 10 / 37 / 38), and waiver of subrogation (CG 24 04).",
    recommendation:
      "Add 'Insurance' with minimum limits per coverage, additional-insured endorsement (current ISO form), waiver of subrogation, and certificate / endorsement delivery.",
    present_patterns: [
      /(insurance|coverage)/i,
      /(additional\s+insured|cg\s+20\s+10)/i,
      /(waiver\s+of\s+subrogation|cg\s+24\s+04)/i,
    ],
  }),
  presence({
    id: "INS-019",
    name: "Survival of indemnity",
    description: "Agreement should state that indemnity obligations survive termination.",
    citation: insPractice(
      "indemnity-survival",
      "Indemnity survival baseline",
      "https://www.americanbar.org/groups/contract_law/",
    ),
    playbooks: [INS_PLAYBOOK_INDEMNIFICATION],
    missing_title: "Survival-of-indemnity clause missing",
    missing_description: "No clause was found stating that indemnity survives termination.",
    explanation:
      "Without explicit survival, indemnity may terminate with the contract — leaving long-tail claims (latent defects, third-party IP) without an indemnitor.",
    recommendation:
      "Add 'Survival' clause stating indemnity obligations survive termination of this Agreement for the applicable statute of limitations / repose.",
    present_patterns: [/(surviv(e|es|ing|al))/i, /(termination|expiration|expir)/i],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// K.5 — Hold-Harmless Agreement. 6 rules: INS-020..INS-025.
// ────────────────────────────────────────────────────────────────────

const HOLD_HARMLESS_RULES: Rule[] = [
  presence({
    id: "INS-020",
    name: "Parties identified",
    description: "Hold-harmless agreement must identify protected party and protecting party.",
    citation: stateInsCode(),
    playbooks: [INS_PLAYBOOK_HOLD_HARMLESS],
    missing_title: "Parties identification missing",
    missing_description: "No clause identifying the parties was found.",
    explanation:
      "Hold-harmless obligations run between identified parties; affiliates / agents who benefit should be enumerated.",
    recommendation:
      "Add 'Parties' identifying the protected party (held harmless) and the protecting party (providing the hold-harmless).",
    present_patterns: [
      /(hold\s+harmless|holds?\s+(.{0,40}\s+)?harmless)/i,
      /(parties|protected\s+party|protecting\s+party)/i,
    ],
  }),
  presence({
    id: "INS-021",
    name: "Activity / scope of risk identified",
    description: "Hold-harmless agreement must identify the activity or scope of risk covered.",
    citation: insPractice(
      "hh-scope",
      "Hold-harmless scope baseline (activity / location / duration)",
      "https://www.americanbar.org/groups/contract_law/",
    ),
    playbooks: [INS_PLAYBOOK_HOLD_HARMLESS],
    missing_title: "Activity / scope clause missing",
    missing_description: "No clause was found identifying the activity / scope of risk covered.",
    explanation:
      "A hold-harmless without an identified activity invites argument over reach; tie it to a specific event, location, premises, or activity period.",
    recommendation:
      "Add 'Activity / Scope' identifying the activity, location, and duration of the risk being held harmless.",
    present_patterns: [/(activity|event|premises|location)/i, /(scope|period|while|during)/i],
  }),
  language({
    id: "INS-022",
    name: "Release-of-future-claims overreach flagged",
    description:
      "Pre-dispute hold-harmless agreements that release ordinary negligence may be unenforceable in some states (esp. for recreational / fitness activities for consumers).",
    citation: insPractice(
      "hh-pre-dispute",
      "Pre-dispute waiver / release enforceability baseline (state-specific — e.g., Tunkl v. Regents in CA)",
      "https://www.law.cornell.edu/wex/exculpatory_clause",
    ),
    playbooks: [INS_PLAYBOOK_HOLD_HARMLESS],
    bad_patterns: [
      /(release|hold\s+harmless).{0,200}(any\s+and\s+all|all)\s+(future|prospective)\s+claims?/is,
      /(release|hold\s+harmless).{0,200}(gross\s+negligence|willful\s+misconduct|intentional)/is,
    ],
    exclude_if: [
      /(?:release|releases?|hold\s+harmless)\s+(?:does|do|shall|will)\s+not\s+(?:apply|extend|cover|include|reach)\b/i,
      /(?:does|do|shall|will)\s+not\s+(?:apply|extend|release|cover)\b[^.]{0,80}(?:gross\s+negligence|willful|intentional)/i,
    ],
    bad_title: "Pre-dispute release / hold-harmless overreach flagged",
    bad_description:
      "Hold-harmless purports to cover future claims, gross negligence, willful misconduct, or intentional acts — many states refuse to enforce these.",
    explanation:
      "Pre-dispute releases of gross negligence / willful misconduct / intentional acts are void in most states. Releases by consumers for recreational / fitness activities are scrutinized under the *Tunkl* factors in CA and similar lines elsewhere.",
    recommendation:
      "Limit to ordinary negligence and accrued claims; carve out gross negligence, willful misconduct, intentional acts, and rights non-waivable as a matter of public policy.",
    default_severity: "warning",
  }),
  presence({
    id: "INS-023",
    name: "Acknowledgment of risk + assumption of risk language",
    description:
      "Hold-harmless should include an explicit acknowledgment of risk + assumption of risk where activity involves physical risk.",
    citation: insPractice(
      "hh-assumption",
      "Assumption of risk baseline",
      "https://www.americanbar.org/groups/litigation/",
    ),
    playbooks: [INS_PLAYBOOK_HOLD_HARMLESS],
    missing_title: "Acknowledgment / assumption-of-risk clause missing",
    missing_description: "No acknowledgment of risk / assumption-of-risk clause was found.",
    explanation:
      "Express assumption-of-risk language helps overcome the *Tunkl* factor analysis and signals an informed waiver — particularly important for consumer / volunteer hold-harmless forms.",
    recommendation:
      "Add 'Acknowledgment and Assumption of Risk' describing the specific risks and stating the protected party voluntarily assumes them.",
    present_patterns: [
      /(acknowledge|i\s+understand)/i,
      /(assume|assumption\s+of\s+risk)/i,
      /(risk|hazard|danger)/i,
    ],
    default_severity: "warning",
  }),
  presence({
    id: "INS-024",
    name: "Signature + date + minor / guardian recital (when applicable)",
    description:
      "Hold-harmless must be signed and dated; minor-participant forms need a guardian signature recital.",
    citation: insPractice(
      "hh-minor",
      "Minor-participant hold-harmless baseline (state-specific enforceability)",
      "https://www.americanbar.org/groups/family_law/",
    ),
    playbooks: [INS_PLAYBOOK_HOLD_HARMLESS],
    missing_title: "Signature / minor recital missing",
    missing_description: "No signature line / date / minor-or-guardian recital was found.",
    explanation:
      "Without signature + date the document is incomplete; for minor participants, many states limit enforceability of parent-signed releases (e.g., Atkins v. Swimwest Family Fitness Center).",
    recommendation:
      "Add signature + date lines; for minor participants, add 'Parent / Guardian Signature' with a recital acknowledging the parent / guardian has authority.",
    present_patterns: [/(signature|signed|sign\s+here)/i, /(date)/i, /(parent|guardian|minor)/i],
    default_severity: "warning",
  }),
  presence({
    id: "INS-025",
    name: "Severability / partial-enforcement clause",
    description:
      "Hold-harmless should include severability so an over-broad portion does not void the whole.",
    citation: insPractice(
      "hh-severability",
      "Severability / partial-enforcement baseline",
      "https://www.americanbar.org/groups/contract_law/",
    ),
    playbooks: [INS_PLAYBOOK_HOLD_HARMLESS],
    missing_title: "Severability clause missing",
    missing_description: "No severability clause was found.",
    explanation:
      "If a court refuses to enforce an over-broad provision, severability allows the rest to survive (or blue-pencil the provision narrower).",
    recommendation:
      "Add 'Severability' clause stating that if any provision is held unenforceable, the remainder remains in effect.",
    present_patterns: [
      /(severability|severable|partial(ly)?\s+enforce)/i,
      /(remainder|remaining\s+provisions|continue\s+in\s+(full\s+)?force)/i,
    ],
    default_severity: "warning",
  }),
];

// ────────────────────────────────────────────────────────────────────
// Aggregate. 25 rules total.
// ────────────────────────────────────────────────────────────────────

export const INSURANCE_RULES: Rule[] = [
  ...POLICY_SUMMARY_RULES,
  ...ENDORSEMENT_RULES,
  ...INDEMNIFICATION_AGREEMENT_RULES,
  ...HOLD_HARMLESS_RULES,
];

export {
  POLICY_SUMMARY_RULES,
  ENDORSEMENT_RULES,
  INDEMNIFICATION_AGREEMENT_RULES,
  HOLD_HARMLESS_RULES,
};
