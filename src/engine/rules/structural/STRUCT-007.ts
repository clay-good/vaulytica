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

// A document that names the General Data Protection Regulation cites its
// articles by bare number — "processors acting on our instructions under
// Article 28 agreements", "Article 6(1)(f)" — because in that document the
// regulation is the only thing called an Article. `crossrefs.ts` already reads
// "Article 32 GDPR" and "Article 28 of the Regulation" as external; the bare
// form carries no qualifier to read, and every GDPR privacy notice and DPA
// writes it that way.
//
// Narrow on both sides: only in a document that names the regulation, and only
// for an ARABIC article number. An agreement's own internal divisions are
// "Article III", and a genuinely broken reference to one still reports.
// The formal citation is the regulation's NUMBER, not its nickname:
// "Regulation (EU) 2016/679" is how an Article 30 record, a set of standard
// contractual clauses, and any document drafted by a European lawyer names it.
// A record of processing activities citing its own legal bases — "Article
// 6(1)(b)", "Article 6(1)(a)", "Article 30(4)" — reported five broken internal
// references to Articles a register does not have.
const NAMES_GDPR =
  /\b(?:general\s+data\s+protection\s+regulation|GDPR)\b|\bRegulation\s*\(EU\)\s*2016\/679\b/i;
const GDPR_ARTICLE_REF = /^Articles?\s+\d/i;

function documentText(ctx: RuleContext): string {
  const parts: string[] = [];
  const walk = (sections: RuleContext["tree"]["sections"]): void => {
    for (const section of sections) {
      for (const p of section.paragraphs) for (const r of p.runs) parts.push(r.text);
      walk(section.children);
    }
  };
  walk(ctx.tree.sections);
  return parts.join(" ");
}

export const rule: Rule = {
  id: "STRUCT-007",
  version: "1.3.0",
  name: "Cross-reference resolution",
  category: "structural",
  default_severity: "warning",
  description: "Flags Section / Article / § references that don't resolve to an existing heading.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    const citesGdpr = NAMES_GDPR.test(documentText(ctx));
    const broken = ctx.extracted.crossrefs.filter(
      (c) =>
        c.unresolved &&
        !ATTACHMENT_REF.test(c.raw_text) &&
        !(citesGdpr && GDPR_ARTICLE_REF.test(c.raw_text)),
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
