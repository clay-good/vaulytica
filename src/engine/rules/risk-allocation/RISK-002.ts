import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, allMatches, topPosition } from "../_helpers.js";

/** RISK-002 — Indemnity mutuality (warning). */
export const rule: Rule = {
  id: "RISK-002",
  version: "1.0.0",
  name: "Indemnity mutuality",
  category: "risk-allocation",
  default_severity: "warning",
  description: "Compares each party's indemnity scope; flags significant asymmetry.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const parties = ctx.extracted.parties;
    if (parties.length < 2) return null;
    const lines = allMatches(ctx, /[A-Z][^.]*\bindemnif[^.]*\./);
    if (lines.length === 0) return null;
    const counts = new Map<string, number>();
    for (const p of parties) counts.set(p.name.toLowerCase(), 0);
    for (const line of lines) {
      for (const p of parties) {
        if (line.match[0].toLowerCase().includes(p.name.toLowerCase())) {
          counts.set(p.name.toLowerCase(), (counts.get(p.name.toLowerCase()) ?? 0) + 1);
        }
      }
    }
    const values = [...counts.values()];
    const max = Math.max(...values);
    const min = Math.min(...values);
    if (max === 0 || max - min < 2) return null;
    return emit(ctx, rule, {
      title: "Indemnity appears asymmetric",
      description: `Indemnity sentence counts by party: ${[...counts.entries()].map(([k, v]) => `${k}=${v}`).join(", ")}.`,
      excerpt: lines[0]!.match[0].slice(0, 200),
      explanation:
        "One party appears to bear materially more indemnity scope than the other. Confirm the asymmetry is intentional and reciprocated by other consideration (e.g., a fee discount).",
      position: lines[0]?.position ?? topPosition(ctx),
    });
  },
};
