import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";

const DEF_HEADING = /\b(definitions?|defined\s+terms|glossary)\b/i;

/**
 * STRUCT-004 — Defined terms section identifiable (info).
 *
 * Fires when neither a Definitions section nor any inline-defined term
 * can be located. Informational; some short agreements legitimately have
 * no defined terms.
 */
export const rule: Rule = {
  id: "STRUCT-004",
  version: "1.1.0",
  name: "Defined terms section identifiable",
  category: "structural",
  default_severity: "info",
  description:
    "Looks for a Definitions / Defined Terms / Glossary section or any inline-defined term.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    // A cover-block field ("Effective Date: January 1, 2026") constitutes a
    // term for STRUCT-006's purposes, but it is not a Definitions section or
    // an inline definition — a document whose only "definition" is a date
    // header has still set out no defined terms in this rule's sense.
    if (ctx.extracted.definitions.entries.some((e) => e.form !== "field-label")) return null;

    let hasHeading = false;
    const walk = (sections: typeof ctx.tree.sections): void => {
      for (const s of sections) {
        if (DEF_HEADING.test(s.heading)) hasHeading = true;
        walk(s.children);
      }
    };
    walk(ctx.tree.sections);
    if (hasHeading) return null;

    const firstSectionId = ctx.tree.sections[0]?.id ?? "";
    return makeFinding({
      rule,
      title: "No defined terms detected",
      description: "Vaulytica did not find a Definitions section or any inline-defined terms.",
      excerptText: "(no definitions located)",
      explanation:
        'Most non-trivial contracts capitalize defined terms and either set them out in a Definitions section or define them inline ("X" means …). Their absence is not by itself a problem, but downstream rules that check for use of specific defined terms will be skipped.',
      position: { section_id: firstSectionId, start: 0, end: 0 },
      source_citations: [],
    });
  },
};
