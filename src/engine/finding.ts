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

/**
 * Legal-confidence tier (spec-v5 §12/§15, Step 75). Distinguishes a finding
 * grounded in black-letter law from one grounded in a drafting preference:
 *
 * - `established` — black-letter law or model-code text (a statute, a
 *   regulation, a uniform act).
 * - `prevailing-practice` — a widely-followed drafting convention (e.g. a
 *   30-day breach-notice window) that is not itself codified.
 * - `opinion` — a defensible-but-contestable preference the rule encodes.
 *
 * A rule's tier is **set only after a credentialed attorney signs its
 * legal-basis ledger entry** (Steps 76/77, human-gated). Until then the field
 * is unset on both the {@link Rule} and the {@link Finding}, so it is omitted
 * from the serialized run and the `result_hash` of every existing run is
 * unchanged — the same additive discipline as {@link Finding.source}. The
 * machine-mirror test (`tests/integration/legal-basis-ledger.test.ts`) asserts
 * a tier on a Rule is always backed by a matching ledger verdict.
 */
export type RuleTier = "established" | "prevailing-practice" | "opinion";

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
  /**
   * Legal-confidence tier inherited from the rule (spec-v5 §15, Step 75).
   * Copied from {@link Rule.tier} by {@link makeFinding} only when the rule
   * carries one; unset (and so omitted from the serialized run) until the
   * rule's ledger entry is attorney-signed, so `result_hash` is unchanged.
   */
  tier?: RuleTier;
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
  /**
   * Opt-in assertion gate (add-document-vertical-framework). If present, the
   * rule is a candidate only when the named assertion is made (a flag/toggle,
   * e.g. a deadline-computation profile or `--estate-checks`). The gate name
   * must be registered in the vertical registry. An alternative to
   * `applies_to_playbooks` for packs that deepen already-shipped playbooks or
   * attach to opt-in machinery; a non-launch rule must declare exactly one of
   * the two gates. Pure rule metadata — never serialized into `EngineRun`, so
   * it does not affect `result_hash`.
   */
  assertion_gate?: string;
  /**
   * Legal-confidence tier (spec-v5 §15, Step 75). Set inline on the rule
   * **only after** a credentialed attorney signs the rule's legal-basis
   * ledger entry (`docs/legal-basis/`) with a matching `tier`. Unset for an
   * author-asserted rule; the machine-mirror test rejects a tier here that no
   * signed ledger entry backs. See {@link RuleTier}.
   */
  tier?: RuleTier;
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

/**
 * Stamped into the run when classification fell to the generic fallback —
 * no known document family matched, yet contract-lint rules were applied
 * anyway. Present only in that case (assigned like {@link Finding.tier}), so
 * a matched run omits the field and its `result_hash` is unchanged. Because
 * it lives inside the hashed run, a generic-fallback receipt is
 * distinguishable from a matched one forever. (add-document-vertical-framework.)
 */
export type ClassificationNotice = {
  /** Machine tag for the notice kind. Only the generic-fallback case today. */
  reason: "generic-fallback";
  /** Banner text rendered before any finding on every report surface. */
  message: string;
};

/**
 * Court-profile provenance stamped into the hashed run when the
 * filing-format-lint pack fires (add-filing-format-lint). Records which court
 * profile's limits were applied, so a filing receipt proves the basis. Present
 * only when a `--court` profile was selected and a filing playbook matched;
 * omitted otherwise, so every other run's hash is unchanged.
 */
export type FilingProfileStamp = {
  id: string;
  version: string;
  court_name: string;
  brief_kind: "principal" | "reply";
  /** The profile's top-level cited authorities (e.g. "Fed. R. App. P. 32"). */
  authority: string[];
};

export type EngineRun = {
  /** Engine semver. */
  version: string;
  dkb_version: string;
  playbook_id: string;
  playbook_match_confidence?: number;
  playbook_match_reasoning?: string;
  /**
   * Present only when the filing-format-lint pack fired. Inside the hash; see
   * {@link FilingProfileStamp}.
   */
  filing_profile?: FilingProfileStamp;
  /**
   * Privacy regimes the user asserted (`--regime`) when the privacy-notice pack
   * ran (add-privacy-notice-pack). Inside the hash; present only when the pack
   * fired, so a run without an asserted regime is byte-identical. Sorted for
   * determinism.
   */
  asserted_regimes?: string[];
  /**
   * Present only when the document matched no known family and the generic
   * fallback ran. Inside the hash; omitted for matched runs. See
   * {@link ClassificationNotice}.
   */
  classification_notice?: ClassificationNotice;
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
  const finding: Finding = {
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
  // spec-v5 §15: inherit the rule's attorney-signed tier. Assigned only when
  // present so an unsigned rule leaves the field omitted and `result_hash`
  // unchanged (same discipline as `source`).
  if (args.rule.tier !== undefined) finding.tier = args.rule.tier;
  return finding;
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
