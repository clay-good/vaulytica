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
      // The day count must be a termination NOTICE period — it must be followed
      // by "notice" (allowing "prior written notice" etc.). Without this the
      // rule grabbed the first "N days" after "for convenience", so an unrelated
      // invoice-dispute deadline in the same paragraph ("… for convenience.
      // Invoices not disputed within 30 days …") was reported as the notice.
      /\bterminate\b[\s\S]{0,80}\bfor\s+convenience\b[\s\S]{0,80}?(\d{1,3})\s+days?['’]?\s*(?:(?:prior|written|advance|business|calendar)\s+){0,4}notice/i,
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
