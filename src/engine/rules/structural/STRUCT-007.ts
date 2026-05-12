import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";

/**
 * STRUCT-007 — Cross-reference resolution (warning).
 *
 * Reports every cross-reference (`Section 4.2`, `Article III`, etc.)
 * that cannot be resolved against the document outline. Common after
 * sections are inserted or deleted without updating references.
 */
export const rule: Rule = {
  id: "STRUCT-007",
  version: "1.0.0",
  name: "Cross-reference resolution",
  category: "structural",
  default_severity: "warning",
  description: "Flags Section / Article / § references that don't resolve to an existing heading.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    const broken = ctx.extracted.crossrefs.filter((c) => c.unresolved);
    if (broken.length === 0) return null;
    const first = broken[0]!;
    const list = broken.slice(0, 8).map((b) => b.raw_text).join(", ");
    const extra = broken.length > 8 ? `, …(${broken.length - 8} more)` : "";
    return makeFinding({
      rule,
      title: `Unresolved cross-references: ${broken.length}`,
      description: `The following references do not resolve to any section: ${list}${extra}.`,
      excerptText: first.raw_text,
      explanation:
        "A broken cross-reference can mean the referenced section was renumbered or deleted, or that a section reference was made up. Either way the reader has no way to follow the citation.",
      recommendation: "Update each broken reference to point to the correct section, or delete it if it is no longer applicable.",
      position: first.position,
      source_citations: [],
    });
  },
};
