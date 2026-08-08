import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

/** CHOICE-008 — Jury trial waiver (info). */
export const rule: Rule = {
  id: "CHOICE-008",
  version: "1.2.0",
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
      //
      // v1.2.0 widens the active-form window from 40 to a sentence-bounded 80
      // ([^.] never crosses a period) so the boilerplate "waives, to the fullest
      // extent permitted by law, any right … to a trial by jury" reaches its
      // object, and adds a passive branch ("the right to a jury trial is hereby
      // waived") tempered so a negated "jury trial is NOT waived" cannot match.
      /\bwaive[^.]{0,80}(?:right\s+to\s+)?(?:a\s+)?(?:trial\s+by\s+jury|jury\s+trial)\b|\bjury\s+trial\s+waiver\b|(?:trial\s+by\s+jury|jury\s+trial)(?:(?!\bnot\b|\bnever\b|\bno\b)[^.]){0,40}\bwaived\b/i,
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
