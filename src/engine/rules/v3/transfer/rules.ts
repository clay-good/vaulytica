/**
 * Transfer-mechanism ruleset — 20 rules (spec-v3.md §31 / Step 26).
 *
 * SCC Module 2 / 3 unaltered clauses, UK Addendum Tables 1–4, UK
 * IDTA standalone, adequacy-decision currency, TIA reference,
 * onward-transfer terms.
 *
 * Scoped to scc-module-2, scc-module-3, uk-idta-addendum, and the
 * controller-processor playbooks (where transfer mechanisms apply).
 */

import type { Rule } from "../../../finding.js";
import {
  buildLanguageRule,
  buildPresenceRule,
  type LanguageSpec,
  type PresenceSpec,
  type RegulatedRuleConfig,
} from "../_regulated-rule.js";

// Two scopes:
//   SCC_PLAYBOOKS: rules about SCC Module 2/3 clauses (do not run on UK).
//   UK_PLAYBOOKS:  rules about the UK Addendum/IDTA Tables (do not run on SCC).
//   ALL_TRANSFER_PLAYBOOKS: cross-cutting rules (adequacy, TIA, onward).
const SCC_PLAYBOOKS = [
  "scc-module-2",
  "scc-module-3",
  "dpa-controller-processor",
  "dpa-processor-subprocessor",
];
const UK_PLAYBOOKS = ["uk-idta-addendum"];
const ALL_TRANSFER_PLAYBOOKS = [...SCC_PLAYBOOKS, ...UK_PLAYBOOKS];

const CONFIG_SCC: RegulatedRuleConfig = {
  category: "transfer",
  applies_to_playbooks: SCC_PLAYBOOKS,
  cite_for(citation: string) {
    const lower = citation.toLowerCase();
    let url = "https://eur-lex.europa.eu/eli/dec_impl/2021/914/oj";
    if (lower.includes("idta") || lower.includes("addendum") || lower.includes("ico"))
      url =
        "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/international-transfers/international-data-transfer-agreement-and-guidance/";
    else if (lower.includes("edpb"))
      url =
        "https://edpb.europa.eu/our-work-tools/our-documents/recommendations/recommendations-012020-measures-supplement-transfer_en";
    else if (lower.includes("adequacy"))
      url =
        "https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/adequacy-decisions_en";
    return {
      id: `transfer-${citation.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}`,
      source_url: url,
    };
  },
};

const CONFIG_UK: RegulatedRuleConfig = { ...CONFIG_SCC, applies_to_playbooks: UK_PLAYBOOKS };
const CONFIG_ALL: RegulatedRuleConfig = {
  ...CONFIG_SCC,
  applies_to_playbooks: ALL_TRANSFER_PLAYBOOKS,
};

const presence = (s: PresenceSpec): Rule => buildPresenceRule(s, CONFIG_SCC);
const language = (s: LanguageSpec): Rule => buildLanguageRule(s, CONFIG_SCC);
const presenceUk = (s: PresenceSpec): Rule => buildPresenceRule(s, CONFIG_UK);
const languageUk = (s: LanguageSpec): Rule => buildLanguageRule(s, CONFIG_UK);
const presenceAll = (s: PresenceSpec): Rule => buildPresenceRule(s, CONFIG_ALL);
const languageAll = (s: LanguageSpec): Rule => buildLanguageRule(s, CONFIG_ALL);

export const TRANSFER_RULES: Rule[] = [
  // ────────────────────────────────────────────────────────────────
  // EU SCC Module 2/3 mandatory clauses
  // ────────────────────────────────────────────────────────────────
  presence({
    id: "TRANSFER-001",
    name: "SCC Clause 1 — Purpose and Scope present",
    description: "EU SCC Clause 1 (Purpose and Scope) must be present.",
    citation: "EU SCCs Clause 1",
    missing_title: "SCC Clause 1 (Purpose and Scope) missing",
    missing_description: "No reference to SCC Clause 1 / Purpose and Scope was found.",
    explanation:
      "Decision 2021/914 requires Clause 1 (Purpose and Scope) — it sets out the parties' agreement to be bound by the SCCs.",
    recommendation: "Include the full Clause 1 (Purpose and Scope) text unmodified.",
    present_patterns: [/(clause\s*1\b|purpose\s+and\s+scope)/i],
  }),
  presence({
    id: "TRANSFER-002",
    name: "SCC Clause 2 — Effect and Invariability present",
    description: "EU SCC Clause 2 (Effect and Invariability) must be present and unmodified.",
    citation: "EU SCCs Clause 2",
    missing_title: "SCC Clause 2 (Effect and Invariability) missing",
    missing_description: "No reference to SCC Clause 2 / Effect and Invariability was found.",
    explanation:
      "Clause 2 forbids material modification — the parties may add other clauses or business-related terms only if they do not contradict the SCCs.",
    recommendation: "Include the full Clause 2 (Effect and Invariability) text unmodified.",
    present_patterns: [/(clause\s*2\b|effect\s+and\s+invariability|invariability)/i],
  }),
  language({
    id: "TRANSFER-003",
    name: "SCC clauses materially modified",
    description:
      "Flags any 'as modified' / 'notwithstanding' / 'as amended' language attached to SCC clauses — forbidden by Clause 2.",
    citation: "EU SCCs Clause 2",
    bad_title: "SCC clauses appear materially modified",
    bad_description:
      "Detected modification language attached to SCC clauses — forbidden by Clause 2.",
    explanation:
      "Clause 2 forbids modifying the SCC text. 'As modified', 'notwithstanding the SCCs', 'except for', etc. are all red flags.",
    recommendation:
      "Remove any modifying language; place business terms in a separate Annex or Side Letter that does not contradict the SCCs.",
    bad_patterns: [
      /(?:standard\s+contractual\s+clauses|SCCs?).{0,80}(?:as\s+modified|as\s+amended|notwithstanding|except\s+for|with\s+the\s+exception)/is,
      /(?:notwithstanding\s+(?:any\s+)?provision\s+of\s+the\s+SCCs?|modified\s+SCCs?)/i,
    ],
    // A non-derogation savings clause runs the other way: it incorporates the
    // SCCs "in full and without modification" and makes them override
    // conflicting business terms. That is what Clause 2 requires, so reading
    // its "notwithstanding" as modification accuses the compliant form.
    exclude_if: [
      /without\s+(?:any\s+)?modification/i,
      /SCCs?\s+shall\s+(?:govern|prevail|control|take\s+precedence)/i,
    ],
    default_severity: "critical",
  }),
  presence({
    id: "TRANSFER-004",
    name: "SCC Clause 8 — Data Protection Safeguards",
    description: "SCC Module 2 Clause 8 (Data Protection Safeguards) must be present.",
    citation: "EU SCCs Clause 8",
    missing_title: "SCC Clause 8 (Data Protection Safeguards) missing",
    missing_description: "No reference to SCC Clause 8 was found.",
    explanation:
      "Clause 8 contains the bulk of the Module-2 data-protection obligations (instructions, purpose limitation, transparency, accuracy, minimisation, storage limitation, security).",
    recommendation: "Include the full Clause 8 (Data Protection Safeguards) text unmodified.",
    present_patterns: [/clause\s*8\b/i],
  }),
  presence({
    id: "TRANSFER-005",
    name: "SCC Clause 9 — Use of Sub-processors",
    description: "SCC Module 2 Clause 9 (Use of Sub-processors) must be present.",
    citation: "EU SCCs Clause 9",
    missing_title: "SCC Clause 9 (Use of Sub-processors) missing",
    missing_description: "No reference to SCC Clause 9 was found.",
    explanation: "Clause 9 governs the use of sub-processors and the prior-authorisation regime.",
    recommendation:
      "Include the full Clause 9 text and complete Annex III (List of Sub-processors).",
    present_patterns: [/clause\s*9\b/i],
  }),
  presence({
    id: "TRANSFER-006",
    name: "SCC Clause 11 — Redress",
    description: "SCC Module 2 Clause 11 (Redress) must be present.",
    citation: "EU SCCs Clause 11",
    missing_title: "SCC Clause 11 (Redress) missing",
    missing_description: "No reference to SCC Clause 11 was found.",
    explanation:
      "Clause 11 obligates the data importer to inform data subjects of redress mechanisms.",
    recommendation: "Include the full Clause 11 (Redress) text unmodified.",
    present_patterns: [/clause\s*11\b|redress\b/i],
    default_severity: "warning",
  }),
  presence({
    id: "TRANSFER-007",
    name: "SCC Clause 14 — Local Laws (TIA)",
    description:
      "SCC Clause 14 (Local laws and practices affecting compliance) must be present, anchoring the TIA.",
    citation: "EU SCCs Clause 14",
    missing_title: "SCC Clause 14 (TIA / Local Laws) missing",
    missing_description: "No reference to SCC Clause 14 / Transfer Impact Assessment was found.",
    explanation: "Clause 14 anchors the Schrems II Transfer Impact Assessment requirement.",
    recommendation: "Include the full Clause 14 text and document the parties' TIA in an Annex.",
    present_patterns: [
      /(clause\s*14\b|local\s+laws\s+and\s+practices|transfer\s+impact\s+assessment|\bTIA\b)/i,
    ],
  }),
  presence({
    id: "TRANSFER-008",
    name: "SCC Clause 15 — Public Authority Access",
    description:
      "SCC Clause 15 (Obligations of the data importer in case of public authority access) must be present.",
    citation: "EU SCCs Clause 15",
    missing_title: "SCC Clause 15 (Public Authority Access) missing",
    missing_description: "No reference to SCC Clause 15 was found.",
    explanation:
      "Clause 15 requires the data importer to notify and challenge public-authority requests where possible.",
    recommendation: "Include the full Clause 15 text unmodified.",
    present_patterns: [
      /(clause\s*15\b|public\s+authority\s+(?:access|request)|government\s+access\s+request|law\s+enforcement\s+request)/i,
    ],
  }),
  presence({
    id: "TRANSFER-009",
    name: "SCC Clause 16 — Non-Compliance with the Clauses",
    description: "SCC Clause 16 (Non-Compliance with the Clauses and Termination) must be present.",
    citation: "EU SCCs Clause 16",
    missing_title: "SCC Clause 16 (Non-Compliance / Termination) missing",
    missing_description: "No reference to SCC Clause 16 was found.",
    explanation: "Clause 16 governs the parties' rights when the SCCs become untenable.",
    recommendation: "Include the full Clause 16 text unmodified.",
    present_patterns: [/(clause\s*16\b|non[- ]compliance\s+with\s+(?:the\s+)?clauses)/i],
    default_severity: "warning",
  }),
  presence({
    id: "TRANSFER-010",
    name: "SCC Clause 18 — Governing Law and Forum",
    description:
      "SCC Clause 18 (Governing Law / Choice of Forum and Jurisdiction) must be present.",
    citation: "EU SCCs Clause 18",
    missing_title: "SCC Clause 18 (Governing Law / Forum) missing",
    missing_description: "No reference to SCC Clause 18 was found.",
    explanation:
      "Clause 18 sets the governing law (must be an EU Member State allowing third-party-beneficiary rights) and forum.",
    recommendation: "Include the full Clause 18 text and pick a qualifying EU Member State.",
    present_patterns: [
      /(clause\s*18\b|governing\s+law\s+and\s+(?:forum|jurisdiction)|choice\s+of\s+forum)/i,
    ],
  }),

  // ────────────────────────────────────────────────────────────────
  // UK Addendum Tables 1–4
  // ────────────────────────────────────────────────────────────────
  presenceUk({
    id: "TRANSFER-011",
    name: "UK Addendum: Table 1 (Parties)",
    description: "UK Addendum Table 1 (Parties) must be completed.",
    citation: "ICO UK Addendum Mandatory Clauses, Table 1",
    missing_title: "UK Addendum Table 1 (Parties) missing",
    missing_description: "No reference to Table 1 / Parties was found.",
    explanation: "The UK Addendum requires Table 1 to identify the Exporter and Importer.",
    recommendation: "Complete Table 1 with the parties' legal entity names and addresses.",
    present_patterns: [/table\s*1\b.{0,40}part/i, /Table\s*1\s*[—:-]\s*Parties/i],
    default_severity: "warning",
  }),
  presenceUk({
    id: "TRANSFER-012",
    name: "UK Addendum: Table 2 (Selected SCC Modules)",
    description: "UK Addendum Table 2 (Selected SCC Modules) must be completed.",
    citation: "ICO UK Addendum Mandatory Clauses, Table 2",
    missing_title: "UK Addendum Table 2 (Selected SCC Modules) missing",
    missing_description: "No reference to Table 2 / Selected SCC Modules was found.",
    explanation: "Table 2 must identify which EU SCC Modules are being incorporated.",
    recommendation: "Complete Table 2 with the chosen Module (1/2/3/4).",
    present_patterns: [
      /Table\s*2\s*[—:-]\s*(?:Selected\s+)?SCC\s+Modules|table\s*2\b.{0,40}module/i,
    ],
    default_severity: "warning",
  }),
  presenceUk({
    id: "TRANSFER-013",
    name: "UK Addendum: Table 3 (Appendix Information)",
    description: "UK Addendum Table 3 (Appendix Information) must be completed.",
    citation: "ICO UK Addendum Mandatory Clauses, Table 3",
    missing_title: "UK Addendum Table 3 (Appendix Information) missing",
    missing_description: "No reference to Table 3 / Appendix Information was found.",
    explanation: "Table 3 incorporates the EU SCC Annex information into the UK Addendum.",
    recommendation:
      "Complete Table 3 with the SCC Annex information (parties, transfer, supervisory authority, TOMs).",
    present_patterns: [/Table\s*3\s*[—:-]\s*Appendix\s+Information|table\s*3\b.{0,40}appendix/i],
    default_severity: "warning",
  }),
  presenceUk({
    id: "TRANSFER-014",
    name: "UK Addendum: Table 4 (Ending This Addendum)",
    description:
      "UK Addendum Table 4 (Ending This Addendum When the Approved Addendum Changes) must be completed.",
    citation: "ICO UK Addendum Mandatory Clauses, Table 4",
    missing_title: "UK Addendum Table 4 missing",
    missing_description: "No reference to Table 4 / Ending This Addendum was found.",
    explanation: "Table 4 governs each party's rights when the ICO publishes a revised Addendum.",
    recommendation:
      "Complete Table 4 indicating which party (or both) may end the Addendum on a revision.",
    present_patterns: [
      /Table\s*4\s*[—:-]\s*Ending|table\s*4\b.{0,40}(ending|approved\s+addendum)/i,
    ],
    default_severity: "warning",
  }),
  languageUk({
    id: "TRANSFER-015",
    name: "UK Addendum: mandatory clauses modified",
    description: "Flags modification of the UK Addendum mandatory clauses — forbidden.",
    citation: "ICO UK Addendum Mandatory Clauses",
    bad_title: "UK Addendum mandatory clauses appear modified",
    bad_description:
      "Detected modification language attached to the UK Addendum mandatory clauses.",
    explanation:
      "The ICO UK Addendum's Mandatory Clauses cannot be modified — only the Tables may be completed.",
    recommendation: "Remove any modification; restrict edits to Tables 1–4.",
    bad_patterns: [
      /(?:UK\s+Addendum|Mandatory\s+Clauses).{0,80}(?:as\s+modified|as\s+amended|with\s+the\s+exception)/is,
    ],
    default_severity: "critical",
  }),

  // ────────────────────────────────────────────────────────────────
  // UK IDTA standalone
  // ────────────────────────────────────────────────────────────────
  presenceUk({
    id: "TRANSFER-016",
    name: "UK IDTA: Parties identified (Part 1 / Table 1)",
    description: "UK IDTA Part 1 (or UK Addendum Table 1) must identify the Parties.",
    citation: "ICO UK IDTA Part 1 / UK Addendum Table 1",
    missing_title: "UK IDTA / Addendum Parties not identified",
    missing_description: "Neither IDTA Part 1 nor UK Addendum Table 1 was found.",
    explanation:
      "The UK IDTA (standalone) requires Part 1 to identify the parties; the UK Addendum (layered on EU SCCs) uses Table 1 for the same purpose.",
    recommendation:
      "Complete Part 1 (IDTA) or Table 1 (Addendum) with the parties' legal entity names and addresses.",
    present_patterns: [
      /Part\s*1\s*[—:-]\s*Parties|part\s*1\b.{0,40}part/i,
      /Table\s*1\s*[—:-]\s*Parties|table\s*1\b.{0,40}part/i,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Adequacy decisions
  // ────────────────────────────────────────────────────────────────
  languageAll({
    id: "TRANSFER-017",
    name: "Adequacy: reliance on litigation-pending decision (DPF)",
    description:
      "Flags reliance on the EU-US Data Privacy Framework (or UK extension) — a warning given pending litigation.",
    citation: "EU-US Data Privacy Framework",
    bad_title: "Reliance on litigation-pending adequacy decision (DPF)",
    bad_description:
      "Detected reliance on the EU-US Data Privacy Framework as the transfer mechanism.",
    explanation:
      "The EU-US Data Privacy Framework is the operative adequacy decision but is permanently under litigation. v3 treats this as a warning, not a fail.",
    recommendation:
      "Maintain a fallback transfer mechanism (e.g., SCCs + TIA) in case the DPF is invalidated again.",
    bad_patterns: [
      /(EU[- ]US\s+Data\s+Privacy\s+Framework|EU-US\s+DPF|DPF\s+(?:adequacy|certification))/i,
    ],
    default_severity: "warning",
  }),
  presenceAll({
    id: "TRANSFER-018",
    name: "Adequacy decision currency clause",
    description:
      "Where an adequacy decision is relied on, the DPA should anchor the reliance with a fallback for invalidation.",
    citation: "GDPR Art. 45 / Adequacy decisions",
    missing_title: "Adequacy fallback clause missing",
    missing_description:
      "No fallback clause was found in case the adequacy decision is invalidated.",
    explanation:
      "Adequacy decisions can be invalidated (Schrems I, Schrems II). A fallback to SCCs / IDTA prevents transfer disruption.",
    recommendation:
      "Add: 'In the event the relied-upon adequacy decision is invalidated, the parties shall promptly implement the EU SCCs / UK Addendum / UK IDTA as a fallback.'",
    present_patterns: [
      /(adequacy\s+decision\s+is\s+(?:invalidated|revoked)|fallback\s+(?:to\s+)?SCC|substitute\s+(?:transfer\s+)?mechanism)/i,
    ],
    default_severity: "warning",
  }),

  // ────────────────────────────────────────────────────────────────
  // Cross-cutting
  // ────────────────────────────────────────────────────────────────
  presenceAll({
    id: "TRANSFER-019",
    name: "TIA / Transfer Risk Assessment reference",
    description:
      "Where SCCs / IDTA cover transfers to a non-adequate country, the DPA must reference a TIA / TRA.",
    citation: "EDPB Recommendations 01/2020 on Supplementary Measures",
    missing_title: "TIA / Transfer Risk Assessment reference missing",
    missing_description: "No reference to a TIA / Transfer Risk Assessment was found.",
    explanation:
      "EDPB Recommendations 01/2020 require the parties to assess local laws and practices of the recipient country.",
    recommendation:
      "Reference a TIA / TRA in the DPA / SCC Annex and document the supplementary measures where needed.",
    present_patterns: [
      /(transfer\s+(?:impact|risk)\s+assessment|\bTIA\b|\bTRA\b|local\s+laws\s+and\s+practices|supplementary\s+measures)/i,
    ],
  }),
  presenceAll({
    id: "TRANSFER-020",
    name: "Onward-transfer terms (Clause 8.7 / 8.8)",
    description:
      "Where SCCs apply, the DPA should address onward-transfer terms per SCC Clause 8.7 / 8.8.",
    citation: "EU SCCs Clause 8.7 / 8.8",
    missing_title: "Onward-transfer terms missing",
    missing_description: "No reference to onward-transfer terms (Clause 8.7 / 8.8) was found.",
    explanation:
      "SCC Clause 8.7 / 8.8 governs onward transfers to third parties outside the EEA. For the UK Addendum (layered on EU SCCs), Clause 8.8 is incorporated by reference but explicit acknowledgment is best practice.",
    recommendation: "Include the Clause 8.7 / 8.8 text or its substantive equivalent in the DPA.",
    present_patterns: [/(onward\s+transfer|clause\s+8\.7|clause\s+8\.8)/i],
    default_severity: "warning",
  }),
];

if (TRANSFER_RULES.length !== 20) {
  throw new Error(`Transfer ruleset must export exactly 20 rules; got ${TRANSFER_RULES.length}`);
}
