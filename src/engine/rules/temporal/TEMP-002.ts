import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";

/** TEMP-002 — Past-dated effective date in a forward-looking contract (info). */
export const rule: Rule = {
  id: "TEMP-002",
  version: "1.0.0",
  name: "Past-dated effective date",
  category: "temporal",
  default_severity: "info",
  description:
    "Flags an Effective Date more than 30 days before the earliest other absolute date in the document.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const abs = ctx.extracted.dates.filter((d) => d.type === "absolute" && d.iso);
    // Back-dating shows up as the earliest date being an OUTLIER before the
    // document's other dates. With only two dates there is nothing to be an
    // outlier from: an effective date and a maturity/expiration date are the
    // contract's TERM, not evidence of back-dating — a five-year loan
    // (2026-03-01 → 2031-03-01) and a one-year insurance policy period
    // (2026-01-01 → 2027-01-01) are not back-dated.
    if (abs.length < 3) return null;
    const sorted = [...abs].sort((a, b) => (a.iso! < b.iso! ? -1 : 1));
    const earliest = new Date(sorted[0]!.iso!);
    const next = new Date(sorted[1]!.iso!);
    const gapDays = (next.getTime() - earliest.getTime()) / 86_400_000;
    if (gapDays <= 30) return null;
    // The gap must also exceed the spread of the remaining dates. Otherwise the
    // "gap" is just the front of a long term (a lease signed a month before it
    // commences and running five years), not a date sitting apart from the
    // document's own cluster.
    const last = new Date(sorted[sorted.length - 1]!.iso!);
    const restSpanDays = (last.getTime() - next.getTime()) / 86_400_000;
    if (gapDays <= restSpanDays) return null;
    return emit(ctx, rule, {
      title: "Earliest dated reference is far before other dates",
      description: `Earliest date ${sorted[0]!.iso} precedes the next date ${sorted[1]!.iso} by ${Math.round(gapDays)} days.`,
      excerpt: sorted[0]!.raw_text,
      explanation:
        "A contract dated significantly before its other date references may be intentionally back-dated. Confirm the intent before signing.",
      position: sorted[0]!.position ?? topPosition(ctx),
    });
  },
};
