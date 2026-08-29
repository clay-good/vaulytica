import type { Rule, RuleContext, Finding } from "../../finding.js";
import { describesCovenantElsewhere, emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

/** PERS-001 — Non-compete present (info). */
export const rule: Rule = {
  id: "PERS-001",
  version: "1.2.0",
  name: "Non-compete present",
  category: "personnel",
  default_severity: "info",
  description: "Detects non-compete; surfaces geographic and temporal scope.",
  dkb_citations: ["stat-16-cfr-910", "stat-ca-bp-16600"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      // The dominant non-compete forms carried none of the original tokens and
      // went undetected (audit): the bare "Employee shall not compete", the
      // noun "non-competition" (the old `\bnon[- ]compete\b` stopped at the
      // word boundary and missed the "-ition" ending), and the "engage in a
      // business that competes" object. `non[- ]?compet(?:e|ition)` admits
      // non-compete / noncompete / non-competition while still excluding
      // "non-competitive" (bids, pricing). The negation the covenant itself
      // carries ("shall NOT compete") sits INSIDE each match, so the
      // unnegated-window guard only suppresses a genuine disclaimer ("this is
      // NOT a non-compete") — not the covenant.
      /\bnon[- ]?compet(?:e|ition)\b|\bcovenant\s+not\s+to\s+compete\b|\b(?:shall|will|agrees?)\s+not[,\s]+(?:to[,\s]+)?(?:directly\s+or\s+indirectly[,\s]+)?compete\b|\bshall\s+not[^.;]{0,80}?\b(?:own|manage|operate|control|engage\s+in|carry\s+on|be\s+employed\s+by|work\s+for|render\s+services?|participate\s+in)\b[^.;]{0,120}?\b(?:(?:competing|competitive)\s+(?:business|enterprise|activit\w*|venture|firm|company)|business\s+that\s+competes)\b/i,
      50,
      // A covenant the document merely DESCRIBES — "the non-competition
      // covenants each of you will sign" in a conflict-waiver letter — is not
      // one this document imposes.
      (paragraph, index) => describesCovenantElsewhere(paragraph, index),
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Non-compete clause present",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Non-competes are unenforceable in some jurisdictions (e.g., California, Bus. & Prof. Code § 16600). The FTC's 2024 rule that would have banned most worker non-competes (16 C.F.R. Part 910) was set aside nationwide in Ryan LLC v. FTC (N.D. Tex. Aug. 20, 2024) and never took effect — the FTC dismissed its appeals in September 2025 — so enforceability turns on state law, with the FTC retaining only case-by-case FTC Act § 5 enforcement. Verify against the governing-law jurisdiction.",
      position: hit.position,
    });
  },
};
