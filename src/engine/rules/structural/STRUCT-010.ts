import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/** STRUCT-010 — TOC parity (info). */
export const rule: Rule = {
  id: "STRUCT-010",
  version: "1.0.0",
  name: "TOC parity",
  category: "structural",
  default_severity: "info",
  description: "Verifies every Table-of-Contents entry resolves to a real section.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // Heuristic: a section titled "Table of Contents" or "Contents" whose
    // paragraphs are short lines that should match section headings.
    let tocText = "";
    const headings = new Set<string>();
    const walk = (sections: typeof ctx.tree.sections): void => {
      for (const s of sections) {
        headings.add(s.heading.toLowerCase().trim());
        walk(s.children);
      }
    };
    walk(ctx.tree.sections);

    forEachParagraph(ctx.tree, (p) => {
      if (/^(table of contents|contents)$/i.test(p.section.heading.trim())) {
        tocText += "\n" + p.text;
      }
    });
    if (!tocText) return null;

    const candidateLines = tocText
      .split(/\n+/)
      .map((l) => l.replace(/\s*\.{2,}.*$/, "").trim())
      .filter((l) => l.length > 2 && l.length < 120);
    const missing = candidateLines.filter((line) => !headings.has(line.toLowerCase()));
    if (missing.length === 0) return null;

    return emit(ctx, rule, {
      title: `TOC entries with no matching section: ${missing.length}`,
      description: missing.slice(0, 6).join("; "),
      excerpt: missing[0]!,
      explanation:
        "A Table of Contents line that does not match any heading suggests the document was renumbered or restructured without updating the TOC.",
      position: topPosition(ctx),
    });
  },
};
