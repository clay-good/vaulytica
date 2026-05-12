import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/**
 * OBLI-009 — Residuals clause swallows confidentiality (warning,
 * obligations).
 *
 * Detects the "residuals" carve-out in NDAs — a clause that permits
 * the recipient (or its representatives) to freely use information
 * retained in "unaided memory." Practitioners (Dentons, Venable,
 * Galkin Law) flag this as a Trojan horse: it shifts the burden to
 * the discloser to prove not only use of confidential information
 * but that the use fell *outside* the residuals safe harbor, and
 * can effectively license trade secrets via human memory.
 *
 * The clause is unfortunately common in M&A diligence NDAs; the
 * rule surfaces it for explicit review.
 */
export const rule: Rule = {
  id: "OBLI-009",
  version: "1.0.0",
  name: "Residuals clause swallows confidentiality",
  category: "obligations",
  default_severity: "warning",
  description:
    "Detects the residuals / unaided-memory carve-out that can swallow an NDA's confidentiality obligation.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:Residuals|unaided\s+memory|retained\s+in\s+the\s+(?:unaided\s+)?memor(?:y|ies)\s+of)|general\s+(?:knowledge|know-?how)[,\s]+skills(?:\s+and\s+experience)?\b/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Residuals clause present",
      description: hit.match[0],
      excerpt: hit.text.slice(Math.max(0, hit.match.index - 40), hit.match.index + 280),
      explanation:
        "A residuals clause lets the recipient (or its representatives) use information retained in 'unaided memory' regardless of the underlying confidentiality obligation. In practice the clause is a near-total carve-out — the discloser cannot easily prove the use fell *outside* the residuals safe harbor, and trade secrets can be transferred via human memory. Particularly dangerous in M&A diligence NDAs where executives review competitive information and then return to their day jobs.",
      recommendation:
        "Strike the residuals clause, or narrow it dramatically — limit to general industry know-how, exclude trade secrets and PII expressly, exclude information memorized in bad faith, and limit to natural persons who actually had access (not 'Representatives').",
      position: hit.position,
    });
  },
};
