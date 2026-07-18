import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** RISK-004 — Indemnity cap vs. LoL cap interaction (warning). */
export const rule: Rule = {
  id: "RISK-004",
  version: "1.0.0",
  name: "Indemnity vs. LoL cap interaction",
  category: "risk-allocation",
  default_severity: "warning",
  description:
    "Flags when an indemnity is carved out of the liability cap, creating uncapped exposure.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const carveOut = firstParagraphMatch(
      ctx,
      // `[^.;\n]` after "except for" so the indemnity carve-out must be in the
      // SAME sentence as the exception — otherwise a later, unrelated "indemnif"
      // mention (e.g. a clause stating indemnity IS inside the cap) satisfied the
      // pattern and produced a false "indemnity carved out of the cap".
      /\b(?:limitation\s+of\s+liability|aggregate\s+liability)\b[\s\S]{0,400}\b(?:except\s+for|excluding|other\s+than)\b[^.;\n]{0,200}\bindemnif/i,
    );
    if (!carveOut) return null;
    return emit(ctx, rule, {
      title: "Indemnity carved out of the liability cap",
      description:
        "The limitation-of-liability clause appears to except indemnification, potentially creating uncapped indemnity exposure.",
      excerpt: carveOut.text.slice(0, 320),
      explanation:
        "When indemnity is carved out of the LoL cap, the indemnifying party may face uncapped exposure on third-party claims. Verify a separate indemnity-specific cap exists, or that the carve-out is intended.",
      position: carveOut.position,
    });
  },
};
