import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * Compare a Table-of-Contents line to a heading on equal terms.
 *
 * The two are the same text typed twice, so they differ in every way two
 * typings of the same text can differ: case, the kind of dash, a trailing
 * period the drafter put in one place and not the other, and the run of
 * whitespace Word leaves behind when its tab-leader page number is flattened
 * to plain text.
 */
function normalizeEntry(text: string): string {
  return text
    .toLowerCase()
    .replace(/[\u2010-\u2015]/g, "-")
    .replace(/[\s\u00a0]+/g, " ")
    .replace(/[.:;,]+$/, "")
    .trim();
}

/**
 * A Word TOC field renders its page number against a TAB STOP, and the leader
 * is a tab-leader character, not literal periods. Flattened to text, "1.
 * Services" comes back as "1. Services\t3" — or, once whitespace collapses,
 * "1. Services 3". So the page number, not the entry, is what fails to match a
 * heading.
 *
 * This is the shape the rule can actually meet: the TOC parity check only ever
 * runs on a document that HAS headings, which in practice means DOCX, which in
 * practice means Word wrote the TOC. Before this was handled, a document whose
 * TOC was entirely correct had EVERY line of it reported as unresolved.
 *
 * The stripped form is tried IN ADDITION to the literal one, never instead of
 * it, so a heading that legitimately ends in a number ("Exhibit 3", "Schedule
 * 2") still matches itself.
 */
function withoutPageNumber(line: string): string {
  return line.replace(/[\s.\u00b7_-]+\d{1,4}$/, "");
}

/** STRUCT-010 — TOC parity (info). */
export const rule: Rule = {
  id: "STRUCT-010",
  version: "1.1.0",
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
        headings.add(normalizeEntry(s.heading));
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
    const missing = candidateLines.filter(
      (line) =>
        !headings.has(normalizeEntry(line)) &&
        !headings.has(normalizeEntry(withoutPageNumber(line))),
    );
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
