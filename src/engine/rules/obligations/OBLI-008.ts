import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * OBLI-008 — Efforts-standard used without definition (info,
 * obligations).
 *
 * "Best efforts," "reasonable efforts," and "commercially reasonable
 * efforts" carry meaningfully different obligation strengths in
 * commercial drafting — and the case law on each is materially
 * different. *Bloor v. Falstaff* (2d Cir. 1979) treated "best
 * efforts" as the most demanding; *Bloor* progeny generally hold
 * "commercially reasonable efforts" as the middle term and
 * "reasonable efforts" the weakest. Without an explicit definition,
 * the parties can disagree about which standard applies and what
 * conduct satisfies it.
 *
 * The rule fires when one or more efforts-standard phrases appear
 * and the document does not contain a definition (`"best efforts"
 * means …`) for any of them.
 */
export const rule: Rule = {
  id: "OBLI-008",
  version: "1.0.0",
  name: "Efforts standard undefined",
  category: "obligations",
  default_severity: "info",
  description:
    "Surfaces uses of best / reasonable / commercially reasonable efforts that lack an explicit definition in the document.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(best\s+efforts|reasonable\s+(?:best\s+)?efforts|commercially\s+reasonable\s+efforts|good\s+faith\s+efforts|diligent\s+efforts)\b/i,
    );
    if (!hit) return null;
    const phrase = hit.match[1] ?? hit.match[0];

    // Check the document for a definition of the matched phrase.
    let defined = false;
    const defPattern = new RegExp(
      `["“”']?${phrase}["“”']?\\s+(?:means|shall\\s+mean|is\\s+defined\\s+as)\\b`,
      "i",
    );
    forEachParagraph(ctx.tree, (p) => {
      if (defPattern.test(p.text)) defined = true;
    });
    if (defined) return null;

    return emit(ctx, rule, {
      title: `Efforts standard "${phrase}" undefined`,
      description: `The contract uses "${phrase}" without defining it.`,
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 30), hit.match.index + 280),
      explanation:
        "Efforts-standard phrases carry different obligation strengths in commercial drafting. *Bloor v. Falstaff* (2d Cir. 1979) and its progeny treat `best efforts` as the most demanding, `commercially reasonable efforts` as the middle term, and `reasonable efforts` as the weakest — but without an in-document definition, the parties can dispute which standard applies and what conduct satisfies it.",
      recommendation: `Either delete the qualifier (let the obligation be absolute) or add an explicit definition of "${phrase}" — typically a list of required actions ("including obtaining all consents, devoting professional staff, and absorbing reasonable costs") plus carve-outs ("but not requiring litigation, financial harm, etc.").`,
      position: hit.position,
    });
  },
};
