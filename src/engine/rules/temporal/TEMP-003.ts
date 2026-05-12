import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** TEMP-003 — Deadline-to-term inconsistency (warning). */
export const rule: Rule = {
  id: "TEMP-003",
  version: "1.0.0",
  name: "Deadline-to-term inconsistency",
  category: "temporal",
  default_severity: "warning",
  description: "Flags when a notice period exceeds the stated contract term.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const term = firstParagraphMatch(
      ctx,
      /\bterm\s+of\s+(\d{1,4})\s+(day|days|month|months|year|years)\b/i,
    );
    const notice = firstParagraphMatch(
      ctx,
      /\b(\d{1,3})\s+days?\s+(?:prior\s+)?(?:written\s+)?notice\b/i,
    );
    if (!term || !notice) return null;
    const termDays = toDays(parseInt(term.match[1]!, 10), term.match[2]!);
    const noticeDays = parseInt(notice.match[1]!, 10);
    if (noticeDays <= termDays) return null;
    return emit(ctx, rule, {
      title: "Notice period exceeds the contract term",
      description: `Notice period ${noticeDays} days > term ${termDays} days.`,
      excerpt: notice.match[0],
      explanation:
        "If the notice required to terminate is longer than the contract itself, the termination right is effectively unavailable.",
      position: notice.position,
    });
  },
};

function toDays(n: number, unit: string): number {
  const u = unit.toLowerCase();
  if (u.startsWith("day")) return n;
  if (u.startsWith("month")) return n * 30;
  if (u.startsWith("year")) return n * 365;
  return n;
}
