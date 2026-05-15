/**
 * Cross-document (two-document mode) types. Spec: spec-v3.md §§27, 59.
 *
 * A {@link ConsistencyRule} runs over two or more parsed v2 documents and
 * emits {@link ConsistencyFinding}s that cite every contributing document
 * and quote the conflicting text from each.
 *
 * The single-document engine (`runEngine`) is unchanged; consistency rules
 * are an additive pass that runs after each document's own rule set.
 */

import type { DocumentTree } from "../../ingest/types.js";
import type { ExtractedData } from "../../extract/types.js";
import type { DKB, SourceCitation } from "../../dkb/types.js";
import type { Severity } from "../finding.js";

/** Coarse document family used to scope which consistency rules fire. */
export type DocKind = "msa" | "baa" | "dpa" | "nda" | "sow" | "other";

/** One parsed document in a multi-document bundle. */
export type ConsistencyDocument = {
  /** Caller-stable handle used in finding excerpts. e.g. "msa", "baa". */
  doc_id: string;
  /** Display name of the file the user dropped. */
  source_file_name: string;
  /** Playbook id that ran for this document. Used to derive {@link DocKind}. */
  playbook_id: string;
  tree: DocumentTree;
  extracted: ExtractedData;
};

/** Excerpt from one document inside a multi-document finding. */
export type ConsistencyExcerpt = {
  doc_id: string;
  source_file_name: string;
  text: string;
  section_id?: string;
  start_offset: number;
  end_offset: number;
};

/** Output of a consistency rule. Always cites at least two excerpts. */
export type ConsistencyFinding = {
  /** Unique within this {@link ConsistencyRun}. */
  id: string;
  rule_id: string;
  rule_version: string;
  severity: Severity;
  title: string;
  description: string;
  explanation: string;
  recommendation?: string;
  source_citations: SourceCitation[];
  /** One entry per contributing document. Length ≥ 1; typically 2. */
  excerpts: ConsistencyExcerpt[];
};

export type ConsistencyContext = {
  documents: ConsistencyDocument[];
  dkb: DKB;
};

/**
 * A cross-document rule.
 *
 * `requires` declares the {@link DocKind}s that must be present for the rule
 * to fire. e.g. `["msa", "baa"]` means the bundle must contain at least one
 * document of kind `msa` and at least one of kind `baa`.
 *
 * Rules are pure: no IO, no time, no randomness.
 */
export type ConsistencyRule = {
  id: string;
  version: string;
  name: string;
  category: string;
  default_severity: Severity;
  description: string;
  /** DocKinds that must all be present for the rule to run. */
  requires: DocKind[];
  check(ctx: ConsistencyContext): ConsistencyFinding[];
};

export type ConsistencyExecutionLogEntry = {
  rule_id: string;
  rule_version: string;
  /** False if the rule was skipped because `requires` was not satisfied. */
  ran: boolean;
  /** Number of findings emitted (zero when ran=true but no conflict). */
  findings_count: number;
  elapsed_ms: number;
};

export type ConsistencyRun = {
  /** Consistency engine semver. */
  version: string;
  dkb_version: string;
  documents: Array<{
    doc_id: string;
    source_file_name: string;
    playbook_id: string;
    kind: DocKind;
  }>;
  /** ISO 8601. Excluded from the hash. */
  executed_at: string;
  findings: ConsistencyFinding[];
  execution_log: ConsistencyExecutionLogEntry[];
  /** SHA-256 over the run with `result_hash` and `executed_at` blanked. */
  result_hash: string;
};
