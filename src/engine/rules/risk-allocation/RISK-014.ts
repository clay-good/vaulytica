import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** RISK-014 — Confidentiality term length (info). */
export const rule: Rule = {
  id: "RISK-014",
  version: "1.1.0",
  name: "Confidentiality term length",
  category: "risk-allocation",
  default_severity: "info",
  description: "Surfaces the post-termination confidentiality term length.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // `[^.;\n]` so the survival term is tied to confidentiality in ONE
      // sentence — otherwise an unrelated survival clause in a later sentence
      // (e.g. indemnification surviving for 10 years) was reported as the
      // confidentiality term length. The anchor is `confidential(?:ity)?` (not
      // just the noun "confidentiality") and the duration verb includes "remain
      // confidential" / "(be) kept | held | maintained confidential" — the
      // dominant "Confidential Information shall remain confidential for five
      // (5) years" phrasing, which the survive/continue/remain-in-effect-only
      // list missed.
      /\bconfidential(?:ity)?[^.;\n]{0,200}?(?:survive|continue|remain\s+in\s+effect|remain\s+confidential|(?:be\s+)?(?:kept|held|maintained)\s+(?:strictly\s+)?(?:in\s+)?confiden\w*)[^.;\n]{0,40}?(?:for|until)\s+(?:a\s+period\s+of\s+)?(\w+\s+\(\d+\)|\d+)\s+(year|years|month|months)/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Confidentiality term length stated",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 240),
      explanation:
        "Typical post-termination confidentiality terms run 3–5 years for general information, with a perpetual duty for trade secrets. Verify the term matches the sensitivity of the information.",
      position: hit.position,
    });
  },
};
