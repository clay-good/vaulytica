import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** RISK-013 — Force majeure clause present (info). */
export const rule: Rule = {
  id: "RISK-013",
  version: "1.0.0",
  name: "Force majeure clause present",
  category: "risk-allocation",
  default_severity: "info",
  description: "Detects force-majeure language and surfaces its scope.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, /\bforce\s+majeure\b|\bact\s+of\s+god\b/i);
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Force majeure clause present",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Force-majeure clauses excuse performance during specified events beyond a party's control. Scope varies widely; pandemics, supply-chain disruption, and government action are common modern additions.",
      position: hit.position,
    });
  },
};
