import type { DocumentTree } from "../ingest/types.js";
import type { ExtractedData, DocPosition } from "../extract/types.js";
import type { DKB, SourceCitation } from "../dkb/types.js";

/**
 * Engine core types. Every rule is a pure function from {@link RuleContext}
 * to a single {@link Finding} or `null`. The runner sorts rules
 * lexicographically by id and produces an {@link EngineRun} whose
 * `result_hash` is the basis of the determinism guarantee.
 */

export type Severity = "critical" | "warning" | "info";

export type Excerpt = {
  text: string;
  section_id?: string;
  start_offset: number;
  end_offset: number;
};

export type Finding = {
  /** Unique within this EngineRun. */
  id: string;
  rule_id: string;
  rule_version: string;
  severity: Severity;
  title: string;
  /** One-sentence description of what the finding is. */
  description: string;
  excerpt: Excerpt;
  /** Plain-language explanation for the report reader. */
  explanation: string;
  recommendation?: string;
  source_citations: SourceCitation[];
  /** For stable sorting within a severity bucket. */
  document_position: number;
  classifier_confidence?: number;
  /**
   * Provenance marker (spec-v6 §8). Built-in catalog findings leave this
   * unset (so the field is omitted from the serialized run and the
   * `result_hash` of every existing run is unchanged); findings produced by
   * a user-supplied custom playbook (Part II) set `"custom-playbook"` so the
   * report can distinguish "your standard flagged this" from "Vaulytica's
   * catalog flagged this".
   */
  source?: "catalog" | "custom-playbook";
};

export type PlaybookOverride = {
  severity?: Severity;
  skip?: boolean;
};

export type Playbook = {
  id: string;
  version: string;
  /** Per-rule overrides keyed by rule id. */
  rule_overrides?: Record<string, PlaybookOverride>;
};

export type RuleContext = {
  tree: DocumentTree;
  extracted: ExtractedData;
  dkb: DKB;
  playbook: Playbook;
  options?: Record<string, unknown>;
};

export type Rule = {
  id: string;
  version: string;
  name: string;
  category: string;
  default_severity: Severity;
  description: string;
  /** Ids of DKB entries this rule depends on (statutes, clauses, dark patterns). */
  dkb_citations: string[];
  /**
   * If present and non-empty, the rule runs only when the active playbook
   * id is in this list. If absent, the rule always runs.
   */
  applies_to_playbooks?: string[];
  /** Pure check function. Must not perform IO, read time, or use randomness. */
  check(ctx: RuleContext): Finding | null;
};

export type ExecutionLogEntry = {
  rule_id: string;
  rule_version: string;
  fired: boolean;
  finding_id?: string;
  elapsed_ms: number;
};

export type EngineRun = {
  /** Engine semver. */
  version: string;
  dkb_version: string;
  playbook_id: string;
  playbook_match_confidence?: number;
  playbook_match_reasoning?: string;
  source_file: { name: string; sha256: string; size_bytes: number };
  /** ISO 8601. Recorded for display only — excluded from the hash. */
  executed_at: string;
  /** Sorted by (severity rank, rule_id, document_position). */
  findings: Finding[];
  /** Recorded in execution order (= sorted rule id order). */
  execution_log: ExecutionLogEntry[];
  /** SHA-256 over the run with this field and `executed_at` set to "". */
  result_hash: string;
};

/** Severity → numeric rank for stable sorting. Lower = more severe. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  warning: 1,
  info: 2,
};

/** Build a Finding skeleton with sensible defaults. */
export function makeFinding(args: {
  rule: Rule;
  severity?: Severity;
  title: string;
  description: string;
  position: DocPosition;
  excerptText: string;
  explanation: string;
  recommendation?: string;
  source_citations: SourceCitation[];
  classifier_confidence?: number;
}): Finding {
  const severity = args.severity ?? args.rule.default_severity;
  return {
    id: `${args.rule.id}-${args.position.section_id || "doc"}-${args.position.start}`,
    rule_id: args.rule.id,
    rule_version: args.rule.version,
    severity,
    title: args.title,
    description: args.description,
    excerpt: {
      text: args.excerptText,
      section_id: args.position.section_id,
      start_offset: args.position.start,
      end_offset: args.position.end,
    },
    explanation: args.explanation,
    recommendation: args.recommendation,
    source_citations: args.source_citations,
    document_position: args.position.start,
    classifier_confidence: args.classifier_confidence,
  };
}

/** Look up a DKB source citation by id. Returns `undefined` if absent. */
export function findSource(dkb: DKB, id: string): SourceCitation | undefined {
  return dkb.manifest.sources.find((s) => s.id === id);
}

/** Look up a statutory entry's citation by id, materialized as a SourceCitation. */
export function findStatuteCitation(dkb: DKB, id: string): SourceCitation | undefined {
  const stat = dkb.statutes.find((s) => s.id === id);
  if (!stat) return undefined;
  return {
    id: stat.id,
    source: stat.citation,
    source_url: stat.canonical_url,
    retrieved_at: stat.retrieved_at,
    source_published_at: stat.source_published_at,
    license: "Public domain (US government work)",
    license_url: "https://www.usa.gov/government-works",
  };
}
