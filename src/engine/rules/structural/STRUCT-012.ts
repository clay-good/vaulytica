import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";

/** STRUCT-012 — Conflicting or duplicate headings (info). */
export const rule: Rule = {
  id: "STRUCT-012",
  version: "1.0.0",
  name: "Conflicting or duplicate headings",
  category: "structural",
  default_severity: "info",
  description: "Flags duplicate section headings at the same level.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const byLevel = new Map<string, number>();
    const dups: string[] = [];
    const walk = (sections: typeof ctx.tree.sections): void => {
      for (const s of sections) {
        const key = `${s.level}::${s.heading.trim().toLowerCase()}`;
        const n = (byLevel.get(key) ?? 0) + 1;
        byLevel.set(key, n);
        if (n === 2) dups.push(s.heading.trim());
        walk(s.children);
      }
    };
    walk(ctx.tree.sections);
    if (dups.length === 0) return null;
    return emit(ctx, rule, {
      title: `Duplicate headings: ${dups.length}`,
      description: dups.join(", "),
      excerpt: dups[0]!,
      explanation:
        "Two sections at the same level sharing a heading make cross-references ambiguous. Renumber or rename one of them.",
      position: topPosition(ctx),
    });
  },
};
