import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";

/** STRUCT-012 — Conflicting or duplicate headings (info). */
/**
 * A SIGNATURE or NOTARY block's label is not a section. A brief's firm name
 * ("HOLLOWAY & NANDAKUMAR LLP") heads its caption and its signature block; a
 * SAFE's company name heads both signature blocks; a deed's "STATE OF TEXAS,
 * COUNTY OF TRAVIS" heads each acknowledgment. Set in heading type — a PDF's
 * larger font, a DOCX's bold heading — each repeat was a "duplicate heading",
 * and the rule's reason, an ambiguous cross-reference, cannot apply: nothing
 * refers to a signature block by its party's name.
 */
const ENTITY_NAME =
  /\b(?:LLC|L\.L\.C\.|LLP|L\.L\.P\.|L\.?P\.|PLLC|INC\.?|INCORPORATED|CORP\.?|CORPORATION|COMPANY|CO\.|LTD\.?|LIMITED|P\.C\.|N\.A\.)\s*,?$/i;
const NOTARY_VENUE =
  /^(?:(?:STATE|State|COMMONWEALTH|Commonwealth)\s+(?:OF|of)\s+[A-Z][A-Za-z ]+(?:,?\s*(?:COUNTY|County)\s+(?:OF|of)\s+[A-Z][A-Za-z ]+)?|(?:COUNTY|County|PARISH|Parish)\s+(?:OF|of)\s+[A-Z][A-Za-z ]+)\s*\)?$/;

function isBlockLabel(heading: string, parties: ReadonlySet<string>): boolean {
  return (
    ENTITY_NAME.test(heading) ||
    NOTARY_VENUE.test(heading) ||
    parties.has(heading.replace(/,\s*$/, "").toLowerCase())
  );
}

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
    const parties = new Set(ctx.extracted.parties.map((p) => p.name.trim().toLowerCase()));
    const walk = (sections: typeof ctx.tree.sections): void => {
      for (const s of sections) {
        if (isBlockLabel(s.heading.trim(), parties)) {
          walk(s.children);
          continue;
        }
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
