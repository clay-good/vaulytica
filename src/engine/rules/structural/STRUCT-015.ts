import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import type { SectionOutlineNode } from "../../../extract/types.js";

/**
 * STRUCT-015 — Numbered section gaps (info, structural).
 *
 * Walks the section outline and reports any gap in the
 * dotted-decimal numbering (Section 1, 2, 4 → missing 3). A gap is
 * almost always the residue of a deleted section that the
 * renumbering pass missed; the rule is conservative and only fires
 * on sibling-level integer gaps where at least three numbered
 * siblings exist (so two siblings + one stray don't trigger noise).
 */
export const rule: Rule = {
  id: "STRUCT-015",
  version: "1.0.0",
  name: "Numbered section gaps",
  category: "structural",
  default_severity: "info",
  description:
    "Flags gaps in dotted-decimal section numbering — typically a deleted section that the renumbering pass missed.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    type Gap = { parent_label: string; missing: number[]; section_id: string };
    const gaps: Gap[] = [];

    const walk = (siblings: readonly SectionOutlineNode[], parentLabel: string): void => {
      const numbered = siblings
        .map((s) => ({ node: s, n: parseLeafInt(s.numbered_label) }))
        .filter((x): x is { node: SectionOutlineNode; n: number } => x.n !== null);
      if (numbered.length >= 3) {
        const ns = numbered.map((x) => x.n);
        const min = Math.min(...ns);
        const max = Math.max(...ns);
        const missing: number[] = [];
        const present = new Set(ns);
        for (let i = min + 1; i < max; i++) {
          if (!present.has(i)) missing.push(i);
        }
        if (missing.length > 0) {
          gaps.push({
            parent_label: parentLabel || "(document root)",
            missing,
            section_id: numbered[0]!.node.id,
          });
        }
      }
      for (const s of siblings) walk(s.children, s.numbered_label ?? parentLabel);
    };
    walk(ctx.extracted.outline.nodes, "");

    if (gaps.length === 0) return null;
    const first = gaps[0]!;
    const summary = gaps
      .slice(0, 4)
      .map((g) => `${g.parent_label}: missing ${g.missing.join(", ")}`)
      .join("; ");
    const extra = gaps.length > 4 ? `; …(${gaps.length - 4} more)` : "";
    return makeFinding({
      rule,
      title: `Numbered section gap${gaps.length === 1 ? "" : "s"}: ${gaps.length}`,
      description: `Section-number gaps detected — ${summary}${extra}.`,
      excerptText: first.parent_label,
      explanation:
        "A gap in dotted-decimal section numbering (Section 1, 2, 4 with no 3) almost always means a section was deleted without renumbering the rest. The gap can break cross-references and create reader confusion about whether a section is missing or just renumbered.",
      recommendation:
        "Confirm whether the missing number is intentional (some drafters reserve numbers for future use) or a renumbering miss. If the latter, renumber and audit cross-references.",
      position: { section_id: first.section_id, start: 0, end: 0 },
      source_citations: [],
    });
  },
};

/** Pull the leaf integer out of a dotted-decimal label like "1.2.3" → 3. Returns null for non-numeric labels. */
function parseLeafInt(label: string | undefined): number | null {
  if (!label) return null;
  // Strip leading text (e.g., "Section 4.2" → "4.2").
  const m = label.match(/(\d+(?:\.\d+)*)/);
  if (!m) return null;
  const parts = m[1]!.split(".");
  const last = parts[parts.length - 1]!;
  const n = parseInt(last, 10);
  return Number.isFinite(n) ? n : null;
}
