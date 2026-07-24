import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

/** CHOICE-008 — Jury trial waiver (info). */
export const rule: Rule = {
  id: "CHOICE-008",
  version: "1.1.0",
  name: "Jury trial waiver",
  category: "choice-and-venue",
  default_severity: "info",
  description: "Detects jury-trial waivers.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      // American drafting writes "waive any right to a JURY TRIAL" far more often
      // than the formal "trial by jury"; only the latter was recognized, so the
      // dominant form of this waiver went unreported entirely.
      /\bwaive[\s\S]{0,40}(?:right\s+to\s+)?(?:a\s+)?(?:trial\s+by\s+jury|jury\s+trial)\b|\bjury\s+trial\s+waiver\b/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Jury trial waiver present",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 240),
      explanation:
        "Jury waivers are enforceable in most US jurisdictions but unenforceable in some contexts (e.g., California for pre-dispute employment waivers). Confirm enforceability against the governing-law jurisdiction.",
      position: hit.position,
    });
  },
};
