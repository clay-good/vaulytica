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
    if (abs.length < 2) return null;
    const sorted = [...abs].sort((a, b) => (a.iso! < b.iso! ? -1 : 1));
    const earliest = new Date(sorted[0]!.iso!);
    const next = new Date(sorted[1]!.iso!);
    const gapDays = (next.getTime() - earliest.getTime()) / 86_400_000;
    if (gapDays <= 30) return null;
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
