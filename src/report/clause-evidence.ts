/**
 * Clause-evidence coverage surface (spec-v8 §25, Step 146).
 *
 * A deterministic per-report summary of how *defensible* each finding is:
 * which findings carry a quoted excerpt span (the engine pinned the exact
 * clause text it fired on) versus which rest on a bare pattern/structural
 * match with no quoted span. It tells a reviewer where to look first — a
 * finding with a verbatim excerpt is easy to confirm; one without warrants
 * a manual read.
 *
 * No new extraction: it reads the `excerpt` field the engine already
 * records on every {@link Finding}. Lives **outside** the `EngineRun`
 * (it is a projection of the run, computed at report time), so it adds
 * zero `result_hash` churn. Pure and deterministic.
 */

import type { EngineRun, Finding, Severity } from "../engine/finding.js";

export type FindingEvidence = {
  finding_id: string;
  rule_id: string;
  severity: Severity;
  /** True when the finding pinned a non-empty quoted clause span. */
  has_quoted_excerpt: boolean;
  /** Length of the quoted excerpt text (0 when none). */
  excerpt_chars: number;
  section_id?: string;
};

export type ClauseEvidenceSummary = {
  total: number;
  /** Findings with a verbatim quoted excerpt span. */
  quoted: number;
  /** Findings resting on a bare match (no quoted span). */
  bare: number;
  /** quoted / total, in [0, 1]; 1 when there are no findings (vacuous). */
  coverage_ratio: number;
  /** Per-finding detail, in the run's sorted finding order. */
  findings: FindingEvidence[];
};

/** A finding carries quoted evidence when its excerpt has text and a real span. */
function hasQuotedExcerpt(f: Finding): boolean {
  return f.excerpt.text.trim().length > 0 && f.excerpt.end_offset > f.excerpt.start_offset;
}

export function buildClauseEvidence(run: EngineRun): ClauseEvidenceSummary {
  const findings: FindingEvidence[] = run.findings.map((f) => ({
    finding_id: f.id,
    rule_id: f.rule_id,
    severity: f.severity,
    has_quoted_excerpt: hasQuotedExcerpt(f),
    excerpt_chars: f.excerpt.text.trim().length,
    section_id: f.excerpt.section_id,
  }));
  const quoted = findings.filter((e) => e.has_quoted_excerpt).length;
  const total = findings.length;
  return {
    total,
    quoted,
    bare: total - quoted,
    // Round to 4 decimals so the ratio is byte-stable across platforms.
    coverage_ratio: total === 0 ? 1 : Math.round((quoted / total) * 10000) / 10000,
    findings,
  };
}
