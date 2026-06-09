/**
 * Version comparison engine (spec-v6 Part I, Step 89).
 *
 * A comparison is a deterministic diff of two deterministic {@link EngineRun}s
 * the engine already produces — no AI, no server, no new probabilistic step.
 * Given two runs designated `base` and `revised`, it buckets every rule that
 * fired into:
 *
 *  - **resolved**   — fired on base, absent on revised (the edit fixed it).
 *  - **introduced** — absent on base, fired on revised (the edit created it).
 *  - **unchanged**  — fired on both (still open); paired for the clause delta.
 *  - **carried-clean** — evaluated on both, fired on neither (no regression).
 *    Reported as a count rather than a 1,000-rule id list.
 *
 * Findings are matched by `rule_id`: a rule's `check` returns at most one
 * Finding per run (spec — `Finding | null`), so a rule's presence in a run's
 * finding set *is* its firing state. The finding instance ids embed the
 * document offset, which legitimately shifts between versions, so they are
 * never used as the match key.
 *
 * Determinism: the comparison `result_hash` is
 * `SHA-256(base_run_hash + revised_run_hash + canonical(delta))` (spec-v6 §6).
 * Same two runs → same comparison hash, on any machine. A cross-family pair is
 * refused unless the caller explicitly confirms the pairing.
 */

import type { EngineRun, Finding, Severity } from "../engine/finding.js";
import { SEVERITY_RANK } from "../engine/finding.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { ClauseDiff, WordDiffSegment } from "./clause-diff.js";

export type SeverityCounts = {
  critical: number;
  warning: number;
  info: number;
  total: number;
};

/**
 * A finding that fired on both versions, paired with its base counterpart so
 * the report can show a clause-level delta where the triggering text moved.
 */
export type UnchangedPair = {
  rule_id: string;
  /** Representative finding from the revised run (canonical for display). */
  finding: Finding;
  /** The base-side finding for the same rule. */
  base_finding: Finding;
  /** True when the triggering clause text differs between the two versions. */
  clause_changed: boolean;
};

export type ComparisonDelta = {
  resolved: Finding[];
  introduced: Finding[];
  unchanged: UnchangedPair[];
  /** Rules evaluated on both runs that fired on neither (no regression). */
  carried_clean_count: number;
  counts: {
    resolved: SeverityCounts;
    introduced: SeverityCounts;
    unchanged: SeverityCounts;
  };
};

export type RunSummary = {
  name: string;
  result_hash: string;
  dkb_version: string;
  playbook_id: string;
};

export type Comparison = {
  base: RunSummary;
  revised: RunSummary;
  delta: ComparisonDelta;
  /**
   * True when the two runs used different DKB versions. Comparing across DKB
   * versions is not apples-to-apples; the report flags it rather than hiding it.
   */
  dkb_mismatch: boolean;
  /** Whether the family pairing was confirmed by the caller despite a mismatch. */
  family_mismatch: boolean;
  /** SHA-256(base_run_hash + revised_run_hash + canonical(delta)). */
  result_hash: string;
};

export type Comparability = {
  /** Safe to compare without an explicit pairing confirmation. */
  comparable: boolean;
  family_mismatch: boolean;
  dkb_mismatch: boolean;
  /** Human-readable explanation when not comparable, else undefined. */
  reason?: string;
};

/**
 * Decide whether two runs can be compared. A cross-family pair (different
 * matched playbooks) is not comparable without confirmation — comparing an
 * NDA's findings against a lease's produces nonsense. A DKB-version mismatch
 * is flagged but does not block (the caller is warned in the report).
 */
export function comparabilityOf(base: EngineRun, revised: EngineRun): Comparability {
  const family_mismatch = base.playbook_id !== revised.playbook_id;
  const dkb_mismatch = base.dkb_version !== revised.dkb_version;
  const reason = family_mismatch
    ? `The base document matched the "${base.playbook_id}" family but the revised document matched "${revised.playbook_id}". ` +
      `Comparing findings across families produces nonsense. Confirm the pairing only if you are certain both are versions of the same agreement.`
    : undefined;
  return { comparable: !family_mismatch, family_mismatch, dkb_mismatch, reason };
}

/** Thrown by {@link compareRuns} when a cross-family pair is not confirmed. */
export class ComparisonRefusedError extends Error {
  readonly comparability: Comparability;
  constructor(comparability: Comparability) {
    super(comparability.reason ?? "These two documents are not comparable.");
    this.name = "ComparisonRefusedError";
    this.comparability = comparability;
  }
}

/**
 * Compare two runs. Refuses a cross-family pair unless `confirmPairing` is set
 * (spec-v6 §5: "a cross-family compare is refused with a clear message").
 */
export async function compareRuns(
  base: EngineRun,
  revised: EngineRun,
  opts: { confirmPairing?: boolean } = {},
): Promise<Comparison> {
  const comparability = comparabilityOf(base, revised);
  if (!comparability.comparable && !opts.confirmPairing) {
    throw new ComparisonRefusedError(comparability);
  }

  const delta = computeDelta(base, revised);
  const result_hash = await sha256Hex(
    base.result_hash + revised.result_hash + canonicalDelta(delta),
  );

  return {
    base: summarize(base),
    revised: summarize(revised),
    delta,
    dkb_mismatch: comparability.dkb_mismatch,
    family_mismatch: comparability.family_mismatch,
    result_hash,
  };
}

// ---------------------------------------------------------------------------
// Delta computation
// ---------------------------------------------------------------------------

function byRule(run: EngineRun): Map<string, Finding[]> {
  const m = new Map<string, Finding[]>();
  for (const f of run.findings) {
    const arr = m.get(f.rule_id);
    if (arr) arr.push(f);
    else m.set(f.rule_id, [f]);
  }
  return m;
}

function computeDelta(base: EngineRun, revised: EngineRun): ComparisonDelta {
  const baseMap = byRule(base);
  const revMap = byRule(revised);

  const resolved: Finding[] = [];
  const introduced: Finding[] = [];
  const unchanged: UnchangedPair[] = [];

  for (const [rid, bfs] of baseMap) {
    if (!revMap.has(rid)) resolved.push(...bfs);
  }
  for (const [rid, rfs] of revMap) {
    if (!baseMap.has(rid)) introduced.push(...rfs);
  }
  for (const [rid, rfs] of revMap) {
    const bfs = baseMap.get(rid);
    if (!bfs) continue;
    const baseFinding = bfs[0]!;
    for (const rf of rfs) {
      unchanged.push({
        rule_id: rid,
        finding: rf,
        base_finding: baseFinding,
        clause_changed: normalizeClause(baseFinding.excerpt.text) !== normalizeClause(rf.excerpt.text),
      });
    }
  }

  resolved.sort(cmpFinding);
  introduced.sort(cmpFinding);
  unchanged.sort((a, b) => cmpFinding(a.finding, b.finding));

  return {
    resolved,
    introduced,
    unchanged,
    carried_clean_count: countCarriedClean(base, revised),
    counts: {
      resolved: severityCounts(resolved),
      introduced: severityCounts(introduced),
      unchanged: severityCounts(unchanged.map((u) => u.finding)),
    },
  };
}

/** Mirror of the runner's finding sort: (severity rank, rule_id, position). */
function cmpFinding(a: Finding, b: Finding): number {
  const sevA = SEVERITY_RANK[a.severity];
  const sevB = SEVERITY_RANK[b.severity];
  if (sevA !== sevB) return sevA - sevB;
  if (a.rule_id !== b.rule_id) return a.rule_id < b.rule_id ? -1 : 1;
  return a.document_position - b.document_position;
}

/**
 * Count rules evaluated on both runs that fired on neither. A whitespace-only
 * difference does not count as firing — both produced no finding. The count is
 * the "no regression" signal; listing every clean rule would bury the report.
 */
function countCarriedClean(base: EngineRun, revised: EngineRun): number {
  const revSilent = new Set<string>();
  for (const e of revised.execution_log) {
    if (!e.fired) revSilent.add(e.rule_id);
  }
  const counted = new Set<string>();
  let count = 0;
  for (const e of base.execution_log) {
    if (e.fired || counted.has(e.rule_id)) continue;
    counted.add(e.rule_id);
    if (revSilent.has(e.rule_id)) count += 1;
  }
  return count;
}

/** Collapse insignificant whitespace so re-wrapping is not treated as an edit. */
function normalizeClause(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

function severityCounts(findings: Finding[]): SeverityCounts {
  const out: SeverityCounts = { critical: 0, warning: 0, info: 0, total: 0 };
  for (const f of findings) {
    out[f.severity] += 1;
    out.total += 1;
  }
  return out;
}

function summarize(run: EngineRun): RunSummary {
  return {
    name: run.source_file.name,
    result_hash: run.result_hash,
    dkb_version: run.dkb_version,
    playbook_id: run.playbook_id,
  };
}

/**
 * Canonical, substance-only projection of the delta for hashing. Excludes
 * volatile finding fields (offsets, elapsed times); includes the firing
 * decisions and the clause-changed flags that define the comparison.
 */
function canonicalDelta(delta: ComparisonDelta): string {
  const fp = (f: Finding) => ({
    rule_id: f.rule_id,
    rule_version: f.rule_version,
    severity: f.severity,
    section_id: f.excerpt.section_id ?? "",
  });
  return stableStringify({
    resolved: delta.resolved.map(fp),
    introduced: delta.introduced.map(fp),
    unchanged: delta.unchanged.map((u) => ({
      ...fp(u.finding),
      clause_changed: u.clause_changed,
    })),
    carried_clean_count: delta.carried_clean_count,
  });
}

// ---------------------------------------------------------------------------
// JSON report (spec-v6 §6 — "comparison report (DOCX + JSON)")
// ---------------------------------------------------------------------------

export type ComparisonJson = {
  kind: "vaulytica-comparison";
  result_hash: string;
  dkb_mismatch: boolean;
  family_mismatch: boolean;
  base: RunSummary;
  revised: RunSummary;
  summary: {
    resolved: SeverityCounts;
    introduced: SeverityCounts;
    unchanged: SeverityCounts;
    carried_clean_count: number;
  };
  resolved: ComparisonJsonFinding[];
  introduced: ComparisonJsonFinding[];
  unchanged: ComparisonJsonUnchanged[];
  /**
   * Clause-level text redline (spec-v8 Part XVIII), when the caller supplies
   * the two documents. Omitted otherwise — additive, outside `result_hash`.
   */
  clause_diff?: ComparisonJsonClauseDiff;
};

type ComparisonJsonClause = { section: string; heading: string; text: string };

type ComparisonJsonClauseDiff = {
  added: ComparisonJsonClause[];
  removed: ComparisonJsonClause[];
  changed: Array<{
    base: ComparisonJsonClause;
    revised: ComparisonJsonClause;
    /** Inline word-level redline; omitted when the clause was too long to align. */
    word_diff?: WordDiffSegment[];
  }>;
  unchanged_count: number;
  base_clause_count: number;
  revised_clause_count: number;
  truncated: boolean;
};

function jsonClause(c: { id: string; heading: string; text: string }): ComparisonJsonClause {
  return { section: c.id, heading: c.heading, text: c.text };
}

function jsonClauseDiff(d: ClauseDiff): ComparisonJsonClauseDiff {
  return {
    added: d.added.map(jsonClause),
    removed: d.removed.map(jsonClause),
    changed: d.changed.map((p) => ({
      base: jsonClause(p.base),
      revised: jsonClause(p.revised),
      ...(p.word_diff ? { word_diff: p.word_diff } : {}),
    })),
    unchanged_count: d.unchanged_count,
    base_clause_count: d.base_clause_count,
    revised_clause_count: d.revised_clause_count,
    truncated: d.truncated,
  };
}

type ComparisonJsonFinding = {
  rule_id: string;
  severity: Severity;
  title: string;
  section_id: string;
  explanation: string;
};

type ComparisonJsonUnchanged = ComparisonJsonFinding & {
  clause_changed: boolean;
};

function jsonFinding(f: Finding): ComparisonJsonFinding {
  return {
    rule_id: f.rule_id,
    severity: f.severity,
    title: f.title,
    section_id: f.excerpt.section_id ?? "",
    explanation: f.explanation,
  };
}

/**
 * Build the comparison JSON payload object (pure; no Blob). When `clauseDiff`
 * is supplied it is rendered as an additive `clause_diff` field — it never
 * enters `cmp.result_hash`, so passing it changes no existing comparison golden.
 */
export function buildComparisonJsonObject(cmp: Comparison, clauseDiff?: ClauseDiff): ComparisonJson {
  return {
    kind: "vaulytica-comparison",
    result_hash: cmp.result_hash,
    dkb_mismatch: cmp.dkb_mismatch,
    family_mismatch: cmp.family_mismatch,
    base: cmp.base,
    revised: cmp.revised,
    summary: {
      resolved: cmp.delta.counts.resolved,
      introduced: cmp.delta.counts.introduced,
      unchanged: cmp.delta.counts.unchanged,
      carried_clean_count: cmp.delta.carried_clean_count,
    },
    resolved: cmp.delta.resolved.map(jsonFinding),
    introduced: cmp.delta.introduced.map(jsonFinding),
    unchanged: cmp.delta.unchanged.map((u) => ({
      ...jsonFinding(u.finding),
      clause_changed: u.clause_changed,
    })),
    ...(clauseDiff ? { clause_diff: jsonClauseDiff(clauseDiff) } : {}),
  };
}

/** The comparison JSON as a downloadable Blob (human-formatted, 2-space). */
export function buildComparisonJson(cmp: Comparison, clauseDiff?: ClauseDiff): Blob {
  return new Blob([JSON.stringify(buildComparisonJsonObject(cmp, clauseDiff), null, 2)], {
    type: "application/json",
  });
}
