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

/**
 * Takes the FINDINGS, not the run.
 *
 * It only ever read `run.findings`, and asking for the whole run meant a
 * bundle — which characterizes every document's findings at once — had to
 * synthesize a fake `EngineRun` to call it. A helper's parameter should be what
 * it uses.
 */
export function buildClauseEvidence(source: EngineRun | readonly Finding[]): ClauseEvidenceSummary {
  const src: readonly Finding[] = Array.isArray(source)
    ? (source as readonly Finding[])
    : (source as EngineRun).findings;
  const findings: FindingEvidence[] = src.map((f) => ({
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

/**
 * One honest sentence about how checkable the findings are.
 *
 * The per-finding table has been in the JSON since spec-v8 §25 and nowhere
 * else, so the only reader who ever learned that a third of a report's findings
 * quote no clause text was one parsing the JSON. The distinction is the
 * difference between "here is the sentence I fired on" and "something in this
 * document matched a pattern": the second is not wrong, it is *unconfirmed*,
 * and the report should say which is which without making a reader count.
 *
 * Same discipline as {@link reviewCoverageSentence}: never claims evidence that
 * is not there, and says nothing at all when there is nothing to characterize.
 */
export function clauseEvidenceSentence(c: ClauseEvidenceSummary): string | undefined {
  if (c.total === 0) return undefined;
  if (c.bare === 0) {
    return `All ${c.total} findings quote the exact clause text they fired on.`;
  }
  if (c.quoted === 0) {
    return `None of the ${c.total} findings quotes clause text — each rests on a pattern or structural match, so confirm every one against the document itself.`;
  }
  return `${c.quoted} of ${c.total} findings quote the exact clause text they fired on; the remaining ${c.bare} rest on a pattern or structural match and warrant a read against the document.`;
}
