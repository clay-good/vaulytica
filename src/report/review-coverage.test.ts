import { describe, expect, it } from "vitest";

import type { Finding, RuleTier } from "../engine/finding.js";
import { buildReviewCoverage, reviewCoverageSentence, tierBadgeLabel } from "./review-coverage.js";

function finding(id: string, tier?: RuleTier): Finding {
  return {
    id,
    rule_id: id,
    rule_version: "1.0.0",
    severity: "warning",
    title: id,
    description: "",
    excerpt: { text: "x", start_offset: 0, end_offset: 1 },
    explanation: "",
    source_citations: [],
    document_position: 0,
    ...(tier ? { tier } : {}),
  };
}

describe("buildReviewCoverage", () => {
  it("reports the honest zero state when no rule is signed", () => {
    const c = buildReviewCoverage([finding("A"), finding("B")]);
    expect(c).toEqual({
      total: 2,
      attorney_reviewed: 0,
      by_tier: { established: 0, "prevailing-practice": 0, opinion: 0 },
    });
  });

  it("counts reviewed findings and breaks them down by tier", () => {
    const c = buildReviewCoverage([
      finding("A", "established"),
      finding("B", "opinion"),
      finding("C"),
    ]);
    expect(c.total).toBe(3);
    expect(c.attorney_reviewed).toBe(2);
    expect(c.by_tier).toEqual({ established: 1, "prevailing-practice": 0, opinion: 1 });
  });

  it("handles the empty report", () => {
    expect(buildReviewCoverage([])).toEqual({
      total: 0,
      attorney_reviewed: 0,
      by_tier: { established: 0, "prevailing-practice": 0, opinion: 0 },
    });
  });
});

describe("reviewCoverageSentence — never claims review that did not happen", () => {
  it("names the author-asserted reality at the zero state", () => {
    const s = reviewCoverageSentence(buildReviewCoverage([finding("A"), finding("B")]));
    expect(s).toContain("0 of 2 findings cite an attorney-reviewed rule");
    expect(s).toContain("author-asserted");
  });

  it("reports the real count once rules are signed", () => {
    const s = reviewCoverageSentence(
      buildReviewCoverage([finding("A", "established"), finding("B")]),
    );
    expect(s).toContain("1 of 2 findings cite a rule whose legal basis a licensed attorney");
    expect(s).toContain("remaining 1");
  });

  it("says nothing to review for an empty report", () => {
    expect(reviewCoverageSentence(buildReviewCoverage([]))).toBe("No findings to review.");
  });
});

describe("tierBadgeLabel", () => {
  it("labels each tier as attorney-reviewed", () => {
    expect(tierBadgeLabel("established")).toBe("attorney-reviewed · established");
    expect(tierBadgeLabel("prevailing-practice")).toBe("attorney-reviewed · prevailing practice");
    expect(tierBadgeLabel("opinion")).toBe("attorney-reviewed · opinion");
  });
});
