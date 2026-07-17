import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

/** PERS-001 — Non-compete present (info). */
export const rule: Rule = {
  id: "PERS-001",
  version: "1.0.0",
  name: "Non-compete present",
  category: "personnel",
  default_severity: "info",
  description: "Detects non-compete; surfaces geographic and temporal scope.",
  dkb_citations: ["stat-16-cfr-910", "stat-ca-bp-16600"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      /\bnon[- ]compete\b|\bcovenant\s+not\s+to\s+compete\b/i,
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
