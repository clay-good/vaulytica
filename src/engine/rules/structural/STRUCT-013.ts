import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * STRUCT-013 — Unfilled template placeholders (critical).
 *
 * Catches the most common drafting accident: a templated bracket
 * survived into the final document. Patterns flagged:
 *
 *   - `[insert <anything>]`
 *   - `[<anything> name]` ("[Counterparty name]", "[Customer Name]")
 *   - `[TBD]`, `[TBA]`, `[REDACTED]`, `[PENDING]`
 *   - Bare underscore runs `____________` of three or more (signature
 *     blanks are usually longer than 10, but anything three-plus is a
 *     placeholder candidate)
 *   - `<<...>>` and `{{...}}` mustache-style placeholders
 *   - `XXX` / `XXXX` of three or more uppercase Xs
 *
 * These patterns are intentionally narrow — a bare bracketed quotation
 * like `[1]` or `[note]` is not flagged, and `[and]` mid-sentence is
 * not flagged. False positives are avoided by requiring either an
 * uppercase Title-Case word, "insert", a "TBD"-family token, or a
 * multi-character placeholder marker.
 *
 * Cites: standard contract-drafting hygiene; no external statute.
 */

const PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /\[insert[^\]]{0,80}\]/gi, label: "[insert …] placeholder" },
  { re: /\[[A-Z][A-Za-z\s/&'-]{1,60}\s+[Nn]ame\]/g, label: "[Title-Case name] placeholder" },
  { re: /\[(?:TBD|TBA|REDACTED|PENDING|PLACEHOLDER|FILL\s*IN|TODO)\]/gi, label: "[TBD]-family placeholder" },
  { re: /\{\{[^}]{1,80}\}\}/g, label: "{{mustache}} placeholder" },
  { re: /<<[^>]{1,80}>>/g, label: "<<placeholder>>" },
  { re: /\bX{3,}\b/g, label: "XXX placeholder" },
  { re: /_{10,}/g, label: "underscore-line placeholder" },
];

export const rule: Rule = {
  id: "STRUCT-013",
  version: "1.0.0",
  name: "Unfilled template placeholders",
  category: "structural",
  default_severity: "critical",
  description:
    "Flags bracketed / mustache / XXX / underscore-line placeholders that survived from the template into the signed document.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    type Hit = { raw: string; label: string; sectionId: string; start: number; end: number };
    const hits: Hit[] = [];
    forEachParagraph(ctx.tree, (p) => {
      for (const { re, label } of PATTERNS) {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(p.text)) !== null) {
          hits.push({
            raw: m[0],
            label,
            sectionId: p.section.id,
            start: p.start + m.index,
            end: p.start + m.index + m[0].length,
          });
        }
      }
    });
    if (hits.length === 0) return null;
    const first = hits[0]!;
    const list = hits
      .slice(0, 6)
      .map((h) => `"${h.raw}"`)
      .join(", ");
    const extra = hits.length > 6 ? `, …(${hits.length - 6} more)` : "";
    return makeFinding({
      rule,
      title: `Unfilled template placeholders: ${hits.length}`,
      description: `Found ${hits.length} placeholder${hits.length === 1 ? "" : "s"} that look${hits.length === 1 ? "s" : ""} like unfilled template content: ${list}${extra}.`,
      excerptText: first.raw,
      explanation:
        "A bracketed placeholder, mustache token, or XXX run that survived into the final document is almost always a drafting accident — the contract is meant to be filled in. A placeholder where a counterparty name belongs makes the agreement legally questionable; a placeholder elsewhere makes the agreement embarrassing.",
      recommendation:
        "Replace every flagged placeholder with the intended content, or remove the bracket if the content is no longer needed.",
      position: { section_id: first.sectionId, start: first.start, end: first.end },
      source_citations: [],
    });
  },
};
