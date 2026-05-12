import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** RISK-008 — Consequential damages waiver mutuality (warning). */
export const rule: Rule = {
  id: "RISK-008",
  version: "1.0.0",
  name: "Consequential damages waiver mutuality",
  category: "risk-allocation",
  default_severity: "warning",
  description: "Flags when only one party benefits from the consequential-damages waiver.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\bneither\s+party\s+(?:will|shall)\s+be\s+liable[\s\S]{0,200}\b(?:consequential|special|incidental|punitive)\s+damages?\b/i,
    );
    if (hit) return null;
    const oneSided = firstParagraphMatch(
      ctx,
      /\b(?:Provider|Vendor|Company)\s+(?:will|shall)\s+not\s+be\s+liable[\s\S]{0,200}\b(?:consequential|special|incidental|punitive)\s+damages?\b/i,
    );
    if (!oneSided) return null;
    return emit(ctx, rule, {
      title: "Consequential-damages waiver appears one-sided",
      description: "Only one party is named as protected from consequential damages.",
      excerpt: oneSided.text.slice(0, 280),
      explanation:
        "Consequential-damages waivers are usually mutual. A one-sided version shifts risk significantly toward the unprotected party.",
      position: oneSided.position,
    });
  },
};
