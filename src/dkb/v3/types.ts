/**
 * v3 DKB node types — additions for regulated-agreement families (BAA,
 * DPA, NDA-deep, MSA-deep, transfer mechanisms, insurance/COI,
 * consistency checks). Defined per spec-v3.md §13.
 *
 * Every v3 node carries a `dkb_node_version` (integer, bumped on
 * breaking changes to the node's contract) and a
 * `dkb_node_last_validated_at` (ISO-8601 UTC) used by the source-pinning
 * protocol (§14, Step 20) to detect staleness.
 *
 * The pinned-citation envelope (`PinnedCitation`) is a strict superset
 * of v2's `SourceCitation` adding a `content_hash_at_pin` so the build
 * pipeline can detect when an authority's content has drifted.
 */

export type PinnedCitation = {
  authority: string;
  citation: string;
  source_url: string;
  /** SHA-256 of the authority's normalized text at the moment of pinning. */
  content_hash_at_pin: string;
  fetched_at: string;
};

type V3NodeBase = {
  id: string;
  dkb_node_version: number;
  dkb_node_last_validated_at: string;
  cites: PinnedCitation[];
};

/** A regulator-published model clause set (e.g. HHS sample BAA, EU SCC). */
export type RegulatorModelForm = V3NodeBase & {
  node_type: "regulator_model_form";
  name: string;
  regulator: string;
  jurisdiction: string;
  authoritative_url: string;
  vendored_path: string;
  vendored_content_hash: string;
  clauses: Array<{
    clause_id: string;
    heading?: string;
    required_by_citation: string;
    normalized_text: string;
  }>;
};

/** A single requirement extracted from a statute. */
export type StatutoryClauseRequirement = V3NodeBase & {
  node_type: "statutory_clause_requirement";
  regulator: string;
  jurisdiction: string;
  authority: string;
  citation: string;
  effective_date: string;
  /** What the contract must say or do to satisfy this requirement. */
  requirement: string;
  /** Minimum compliant text or a structural description of compliance. */
  minimum_compliant_text: string;
  applies_to_document_types: string[];
};

export type TransferMechanismKind =
  | "adequacy_decision"
  | "scc_module_1"
  | "scc_module_2"
  | "scc_module_3"
  | "scc_module_4"
  | "uk_idta"
  | "uk_addendum"
  | "swiss_addendum"
  | "bcr"
  | "art_49_derogation";

export type TransferMechanism = V3NodeBase & {
  node_type: "transfer_mechanism";
  kind: TransferMechanismKind;
  name: string;
  /** Which controller/processor roles this mechanism covers. */
  scope: string;
  /** Required ancillary documents (TIA, supplementary measures, etc.). */
  required_ancillary_documents: string[];
  /** Optional litigation/status flag (e.g. DPF) the report should surface. */
  status_note?: string;
};

export type SubprocessorRequirement = V3NodeBase & {
  node_type: "subprocessor_requirement";
  regulator: string;
  jurisdiction: string;
  /** Minimum days of notice the controller must receive. */
  notice_period_days?: number;
  objection_rights: "general" | "specific" | "none";
  /** Whether subprocessor contracts must flow down identical obligations. */
  flow_down_required: boolean;
  /** Whether a publicly maintained subprocessor list is required. */
  list_publication_required: boolean;
  notes?: string;
};

export type InsuranceNorm = V3NodeBase & {
  node_type: "insurance_norm";
  vertical: string;
  coverage_type:
    | "general_liability"
    | "professional_liability"
    | "cyber"
    | "workers_compensation"
    | "umbrella"
    | "auto"
    | "errors_and_omissions";
  minimum_per_occurrence_usd: number;
  minimum_aggregate_usd: number;
  required_endorsements: string[];
  /** AM Best rating threshold, e.g. `A-` or better. */
  minimum_carrier_rating: string;
};

export type ConsistencyCheck = V3NodeBase & {
  node_type: "consistency_check";
  name: string;
  /** Pair of document types the rule operates over, e.g. ["MSA","DPA"]. */
  document_pair: [string, string];
  description: string;
  /** Rule id in `src/engine/consistency/` that implements the check. */
  implementing_rule_id: string;
};

export type V3DkbNode =
  | RegulatorModelForm
  | StatutoryClauseRequirement
  | TransferMechanism
  | SubprocessorRequirement
  | InsuranceNorm
  | ConsistencyCheck;

export type V3NodeType = V3DkbNode["node_type"];
