import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** TERM-001 — Termination for convenience present (info). */
export const rule: Rule = {
  id: "TERM-001",
  version: "1.0.0",
  name: "Termination for convenience present",
  category: "termination",
  default_severity: "info",
  description: "Detects termination-for-convenience and surfaces the notice period.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\bterminate\b[\s\S]{0,80}\bfor\s+convenience\b[\s\S]{0,80}?(\d{1,3})\s+days/i,
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    const days = parseInt(hit.match[1] ?? "0", 10);
    return emit(ctx, rule, {
      title: `Termination for convenience: ${days} days' notice`,
      description: hit.match[0],
      excerpt: hit.text.slice(0, 240),
      explanation:
        "Termination for convenience permits exit without cause; the notice period determines how quickly the parties can unwind.",
      position: hit.position,
    });
  },
};
