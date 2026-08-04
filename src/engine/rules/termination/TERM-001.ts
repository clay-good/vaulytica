import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

// "For convenience" is as often written as its unambiguous synonyms — "without
// cause", "for any reason" / "for any or no reason", "with or without cause".
// ("At any time" is excluded: it also heads a for-CAUSE clause — "may terminate
// at any time for cause".)
const CONVENIENCE =
  "(?:for\\s+convenience|without\\s+cause|for\\s+any\\s+(?:or\\s+no\\s+)?reason|with\\s+or\\s+without\\s+cause)";
// The count is parenthesized in the standard form ("thirty (30) days"), so the
// ")" between the digit and "days" is tolerated, and it must be a termination
// NOTICE period (followed by "notice") so an unrelated invoice deadline in the
// same paragraph is not grabbed.
const NOTICE = "\\(?(\\d{1,3})\\)?\\s+days?['’]?\\s*(?:(?:prior|written|advance|business|calendar)\\s+){0,4}notice";
// The notice period is stated in EITHER order: trigger-first ("terminate for
// convenience upon thirty (30) days' notice") and, just as often, count-first
// ("Upon thirty (30) days' notice, either party may terminate for convenience").
// The count-first branch uses `[^.]` gaps so it stays within one sentence and
// cannot link an unrelated notice count from a neighbouring sentence to the
// convenience-termination clause.
const CONVENIENCE_NOTICE = new RegExp(
  `\\bterminate\\b[\\s\\S]{0,80}\\b${CONVENIENCE}\\b[\\s\\S]{0,80}?${NOTICE}` +
    `|${NOTICE}[^.]{0,60}?\\bterminate\\b[^.]{0,40}\\b${CONVENIENCE}\\b`,
  "i",
);

/** TERM-001 — Termination for convenience present (info). */
export const rule: Rule = {
  id: "TERM-001",
  version: "1.2.0",
  name: "Termination for convenience present",
  category: "termination",
  default_severity: "info",
  description: "Detects termination-for-convenience and surfaces the notice period.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, CONVENIENCE_NOTICE);
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    const days = parseInt(hit.match[1] ?? hit.match[2] ?? "0", 10);
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
