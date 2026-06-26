import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";

/**
 * TEMP-001 — Impossible date (critical).
 *
 * Reports any absolute date reference whose raw text contained a
 * calendar-impossible value (Feb 30, April 31, etc.). The dates
 * extractor flags these by setting `iso: undefined` on an
 * `absolute`-type reference.
 */
export const rule: Rule = {
  id: "TEMP-001",
  version: "1.0.0",
  name: "Impossible date",
  category: "temporal",
  default_severity: "critical",
  description: "Detects calendar-impossible dates such as February 30 or April 31.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    const bad = ctx.extracted.dates.filter((d) => d.type === "absolute" && !d.iso);
    if (bad.length === 0) return null;
    const first = bad[0]!;
    const list = bad
      .slice(0, 6)
      .map((d) => d.raw_text)
      .join(", ");
    const extra = bad.length > 6 ? `, …(${bad.length - 6} more)` : "";
    return makeFinding({
      rule,
      title: `Calendar-impossible date${bad.length > 1 ? "s" : ""}: ${bad.length}`,
      description: `The following date${bad.length > 1 ? "s do" : " does"} not exist on the calendar: ${list}${extra}.`,
      excerptText: first.raw_text,
      explanation:
        "A date that is not a real calendar date (e.g., February 30) is a drafting error. It usually points to a typo — for example, intending the last day of the month and writing the wrong number.",
      recommendation:
        "Confirm the intended date with the drafter and correct each impossible date.",
      position: first.position,
      source_citations: [],
    });
  },
};
