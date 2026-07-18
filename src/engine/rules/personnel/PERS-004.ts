import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** PERS-004 — Anti-poaching language (warning). */
export const rule: Rule = {
  id: "PERS-004",
  version: "1.0.0",
  name: "Anti-poaching / no-hire between parties",
  category: "personnel",
  default_severity: "warning",
  description:
    "Flags mutual no-hire clauses between parties (antitrust risk in competitor contexts).",
  dkb_citations: ["stat-ftc-act-section-5", "stat-15-usc-45"],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // `[^.;\n]` (not `[\s\S]`) so the object must sit in the SAME sentence as
      // the no-hire trigger — otherwise an unrelated "will not hire <thing>"
      // clause borrowed "employees"/"other party" from the next sentence and was
      // misreported as an anti-poaching clause.
      /\b(?:no[- ]hire|will\s+not\s+hire|will\s+not\s+employ)\b[^.;\n]{0,80}\b(?:other\s+party|employees?)\b/i,
    );
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Anti-poaching / no-hire clause present",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Mutual no-hire clauses between competitors raise antitrust scrutiny under FTC Act § 5. DOJ has prosecuted no-poach agreements between competitors.",
      position: hit.position,
    });
  },
};
