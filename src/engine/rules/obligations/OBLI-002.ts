import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";

const RECIPROCAL_PATTERNS = [
  /\bconfidential/i,
  /\bindemnif/i,
  /\brepresentation/i,
  /\bwarrant/i,
] as const;

/** OBLI-002 — Reciprocity asymmetry (info). */
export const rule: Rule = {
  id: "OBLI-002",
  version: "1.0.0",
  name: "Reciprocity asymmetry",
  category: "obligations",
  default_severity: "info",
  description: "For typically-mutual obligations, flags when only one party bears the obligation.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const parties = ctx.extracted.parties;
    if (parties.length < 2) return null;
    const partySet = new Set(parties.map((p) => p.name.toLowerCase()));
    for (const pattern of RECIPROCAL_PATTERNS) {
      const seenObligors = new Set<string>();
      for (const o of ctx.extracted.obligations) {
        if (!pattern.test(o.action)) continue;
        const o2 = o.obligor.toLowerCase().trim();
        if (partySet.has(o2)) seenObligors.add(o2);
      }
      if (seenObligors.size === 1 && partySet.size >= 2) {
        return emit(ctx, rule, {
          title: `Asymmetric obligation under '${pattern.source}'`,
          description: `Only ${[...seenObligors][0]} bears this typically-mutual obligation.`,
          excerpt: `Obligation kind matching ${pattern}`,
          explanation:
            "Obligations like confidentiality, indemnity, and representations are usually mutual. A one-sided version is sometimes intentional but worth confirming.",
          position: topPosition(ctx),
        });
      }
    }
    return null;
  },
};
