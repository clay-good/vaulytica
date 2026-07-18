import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * RISK-009 — Uncapped liability detection (critical).
 *
 * Detects "unlimited liability" or "no cap on liability" language.
 * Cross-references CUAD's "Uncapped Liability" category.
 */
const UNCAPPED =
  /\b(?:unlimited\s+liability|no\s+(?:limitation|cap)\s+on\s+liability|liability\b[^.;\n]{0,40}?\b(?:is|shall\s+be)\s+unlimited|without\s+(?:any\s+)?(?:cap|limitation)\s+on\s+(?:its\s+)?liability|(?:liable|responsible)\s+for\s+all\s+damages[^.]*?without\s+limitation|all\s+damages[^.]*?without\s+(?:any\s+)?(?:cap|limit(?:ation)?))/i;

export const rule: Rule = {
  id: "RISK-009",
  version: "1.0.0",
  name: "Uncapped liability detection",
  category: "risk-allocation",
  default_severity: "critical",
  description: "Flags clauses that disclaim or remove any cap on a party's liability.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    type Hit = {
      text: string;
      sectionId: string;
      /** Match offset within the paragraph text (`local`) and in the document (`start`). */
      local: number;
      start: number;
      end: number;
      raw: string;
    };
    let firstHit: Hit | null = null;
    forEachParagraph(ctx.tree, (p) => {
      if (firstHit) return;
      const m = UNCAPPED.exec(p.text);
      if (!m) return;
      firstHit = {
        text: p.text,
        raw: m[0],
        sectionId: p.section.id,
        local: m.index,
        start: p.start + m.index,
        end: p.start + m.index + m[0].length,
      };
    });
    if (!firstHit) return null;
    const hit: Hit = firstHit;

    // Slice the excerpt with the PARAGRAPH-LOCAL match offset — the previous
    // code sliced with the document-absolute `hit.start` into the local
    // `hit.text`, yielding an empty (or garbled) excerpt for any clause not in
    // the document's first ~240 chars, so this critical finding shipped with no
    // supporting text.
    const excerpt = hit.text.slice(
      Math.max(0, hit.local - 40),
      Math.min(hit.text.length, hit.local + 200),
    );
    return makeFinding({
      rule,
      title: "Uncapped or unlimited liability",
      description: `Phrase '${hit.raw}' appears in the document.`,
      excerptText: excerpt,
      explanation:
        "An uncapped or unlimited liability clause exposes a party to an open-ended financial risk. Even mutually agreed-upon caps usually carve out specific categories (fraud, willful misconduct, IP indemnity); a blanket 'no cap' is unusual outside those carve-outs.",
      recommendation:
        "Confirm the scope is intended. If not, add a per-claim and aggregate cap, and enumerate the carve-outs explicitly.",
      position: { section_id: hit.sectionId, start: hit.start, end: hit.end },
      source_citations: [],
    });
  },
};
