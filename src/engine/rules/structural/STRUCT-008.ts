import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";

/**
 * STRUCT-008 — Section numbering integrity (info).
 *
 * Detects skipped, duplicate, or out-of-order numbers in dotted-decimal
 * outlines. Only top-level numeric labels are checked; mixed-style
 * outlines (Article I / Section 2) are tolerated.
 */
export const rule: Rule = {
  id: "STRUCT-008",
  version: "1.0.0",
  name: "Section numbering integrity",
  category: "structural",
  default_severity: "info",
  description: "Detects skipped, duplicate, or out-of-order numbers in numbered sections.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    const issues: { numbered_label: string; reason: string; sectionId: string }[] = [];
    const numericTop = ctx.extracted.outline.nodes
      .map((n) => n)
      .filter((n) => n.numbered_label && /^\d+(?:\.\d+)*$/.test(n.numbered_label));
    let expected = 1;
    const seen = new Set<string>();
    for (const node of numericTop) {
      const label = node.numbered_label!;
      const top = parseInt(label.split(".")[0]!, 10);
      if (seen.has(label)) {
        issues.push({ numbered_label: label, reason: "duplicate", sectionId: node.id });
      } else if (top < expected) {
        issues.push({ numbered_label: label, reason: "out-of-order", sectionId: node.id });
      } else if (top > expected) {
        issues.push({ numbered_label: label, reason: `skipped ${expected}..${top - 1}`, sectionId: node.id });
      }
      seen.add(label);
      expected = top + 1;
    }
    if (issues.length === 0) return null;
    const first = issues[0]!;
    return makeFinding({
      rule,
      title: `Section numbering issues: ${issues.length}`,
      description: issues.map((i) => `${i.numbered_label} (${i.reason})`).join("; "),
      excerptText: first.numbered_label,
      explanation:
        "Skipped, duplicate, or out-of-order section numbers usually mean a section was added or removed without renumbering. Cross-references made by number can silently break.",
      recommendation: "Renumber sections so they are contiguous and unique.",
      position: { section_id: first.sectionId, start: 0, end: 0 },
      source_citations: [],
    });
  },
};
