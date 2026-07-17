/**
 * Attorney-review coverage (add-attorney-review-ledger, task 3).
 *
 * A render-side projection of `run.findings`: how many of a report's findings
 * cite a rule whose legal basis a credentialed attorney has signed off on. The
 * "attorney-reviewed" signal is `Finding.tier` — set by {@link makeFinding}
 * only when the rule carries an attorney-signed tier (spec-v5 §15), so this
 * needs no access to the build-and-CI-only ledger (the privacy guard forbids
 * `src/` importing it).
 *
 * The count is reported **honestly**: until an attorney signs a rule's ledger
 * entry, every finding is author-asserted and the report says "0 of N" — never
 * a fabricated badge. Lives outside `run`, so `result_hash` is unchanged; it is
 * the same always-emitted-projection discipline as {@link buildClauseEvidence}.
 */

import type { Finding, RuleTier } from "../engine/finding.js";

export type ReviewCoverage = {
  /** Total findings in the report. */
  total: number;
  /** Findings whose rule carries an attorney-signed tier. */
  attorney_reviewed: number;
  /** Reviewed findings broken down by confidence tier. */
  by_tier: Record<RuleTier, number>;
};

/** Count attorney-reviewed findings (those carrying a signed `tier`). Pure. */
export function buildReviewCoverage(findings: readonly Finding[]): ReviewCoverage {
  const by_tier: Record<RuleTier, number> = {
    established: 0,
    "prevailing-practice": 0,
    opinion: 0,
  };
  let reviewed = 0;
  for (const f of findings) {
    if (f.tier === undefined) continue;
    reviewed += 1;
    by_tier[f.tier] += 1;
  }
  return { total: findings.length, attorney_reviewed: reviewed, by_tier };
}

/**
 * One honest sentence for the report body. At the current zero state it names
 * the author-asserted reality plainly; once rules are signed it reports the
 * real count. Never claims review that did not happen.
 */
export function reviewCoverageSentence(c: ReviewCoverage): string {
  if (c.total === 0) return "No findings to review.";
  if (c.attorney_reviewed === 0) {
    return `0 of ${c.total} findings cite an attorney-reviewed rule — every rule applied here is author-asserted, grounded in a cited authority but not yet signed off by a licensed attorney.`;
  }
  return `${c.attorney_reviewed} of ${c.total} findings cite a rule whose legal basis a licensed attorney has signed off on; the remaining ${c.total - c.attorney_reviewed} rest on author-asserted rules.`;
}

/** Short badge label for a per-finding tier. Dormant until a rule is signed. */
export function tierBadgeLabel(tier: RuleTier): string {
  switch (tier) {
    case "established":
      return "attorney-reviewed · established";
    case "prevailing-practice":
      return "attorney-reviewed · prevailing practice";
    case "opinion":
      return "attorney-reviewed · opinion";
  }
}
