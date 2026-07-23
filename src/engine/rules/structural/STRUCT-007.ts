import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";

/**
 * STRUCT-007 — Cross-reference resolution (warning).
 *
 * Reports every cross-reference (`Section 4.2`, `Article III`, etc.)
 * that cannot be resolved against the document outline. Common after
 * sections are inserted or deleted without updating references.
 */
// An Exhibit / Schedule / Attachment reference keys into a namespace the
// section outline never models, so the extractor leaves it unresolved BY
// DESIGN (resolving "Schedule 4.2" to Section 4.2 would be a wrong-entity
// link). Reporting it here as a reference that "does not resolve to any
// section" both mislabels it and duplicates STRUCT-016/STRUCT-018, which own
// attachment presence — a well-formed SOW referencing Attachments 1–3 drew
// three findings for one drafting fact.
const ATTACHMENT_REF = /^(?:Exhibit|Schedule|Attachment)\b/i;

export const rule: Rule = {
  id: "STRUCT-007",
  version: "1.1.0",
  name: "Cross-reference resolution",
  category: "structural",
  default_severity: "warning",
  description: "Flags Section / Article / § references that don't resolve to an existing heading.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    const broken = ctx.extracted.crossrefs.filter(
      (c) => c.unresolved && !ATTACHMENT_REF.test(c.raw_text),
    );
    if (broken.length === 0) return null;
    const first = broken[0]!;
    const list = broken
      .slice(0, 8)
      .map((b) => b.raw_text)
      .join(", ");
    const extra = broken.length > 8 ? `, …(${broken.length - 8} more)` : "";
    return makeFinding({
      rule,
      title: `Unresolved cross-references: ${broken.length}`,
      description: `The following references do not resolve to any section: ${list}${extra}.`,
      excerptText: first.raw_text,
      explanation:
        "A broken cross-reference can mean the referenced section was renumbered or deleted, or that a section reference was made up. Either way the reader has no way to follow the citation.",
      recommendation:
        "Update each broken reference to point to the correct section, or delete it if it is no longer applicable.",
      position: first.position,
      source_citations: [],
    });
  },
};
