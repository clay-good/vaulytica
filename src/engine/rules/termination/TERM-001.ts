import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** TERM-001 — Termination for convenience present (info). */
export const rule: Rule = {
  id: "TERM-001",
  version: "1.1.0",
  name: "Termination for convenience present",
  category: "termination",
  default_severity: "info",
  description: "Detects termination-for-convenience and surfaces the notice period.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // "For convenience" is as often written as its unambiguous synonyms —
      // "without cause", "for any reason" / "for any or no reason", "with or
      // without cause". ("At any time" is excluded: it also heads a for-CAUSE
      // clause — "may terminate at any time for cause".) The day count is
      // typically parenthesized — "thirty (30) days" — so the ")" between the
      // digit and "days" is tolerated; without that the rule fired only on a
      // bare "30 days" and missed the standard drafting form entirely. The count
      // must still be a termination NOTICE period (followed by "notice"), so an
      // unrelated invoice-dispute deadline in the same paragraph is not grabbed.
      /\bterminate\b[\s\S]{0,80}\b(?:for\s+convenience|without\s+cause|for\s+any\s+(?:or\s+no\s+)?reason|with\s+or\s+without\s+cause)\b[\s\S]{0,80}?\(?(\d{1,3})\)?\s+days?['’]?\s*(?:(?:prior|written|advance|business|calendar)\s+){0,4}notice/i,
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
