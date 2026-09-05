import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** IPDATA-003 — License grant scope (info). */
export const rule: Rule = {
  id: "IPDATA-003",
  version: "1.1.0",
  name: "License grant scope",
  category: "ip-and-data",
  default_severity: "info",
  description:
    "Surfaces the scope of an IP license grant (exclusive / transferable / territory / term).",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\bgrants?\s+(?:to\s+\w+\s+)?a\s+(?:non[- ]exclusive|exclusive|royalty[- ]free|perpetual|worldwide|sublicensable)[\s\S]{0,200}\blicen[cs]e\b/i,
    );
    if (!hit) return null;
    // Negated-detector guard: a no-license clause reuses the same "grants a
    // <scope> license" shape but grants nothing — "does NOT grant a perpetual
    // license", "NOTHING herein grants a non-exclusive license", "NEITHER party
    // grants a royalty-free license". Surfacing those as a stated grant is
    // wrong. Suppress an immediately-preceding "not" (does/shall/will not grant)
    // or a "nothing"/"neither" governing the clause; an unrelated earlier "not"
    // ("the parties have not agreed on price, Licensor grants …") is left to
    // fire because it does not sit next to the verb.
    const before = hit.text.slice(Math.max(0, hit.match.index - 40), hit.match.index);
    if (/\bnot\s+$/i.test(before) || /\b(?:nothing|neither)\b[^.;]{0,35}$/i.test(before)) {
      return null;
    }
    return emit(ctx, rule, {
      title: "License grant scope stated",
      description: hit.match[0].slice(0, 240),
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Verify the four classic license dimensions: exclusive vs. non-exclusive, transferable vs. non-transferable, geographic territory, and term.",
      position: hit.position,
    });
  },
};
