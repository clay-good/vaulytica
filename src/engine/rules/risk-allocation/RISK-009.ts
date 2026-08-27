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
  /\b(?:unlimited\s+liability|no\s+(?:limitation|cap)\s+on\s+liability|liability\b[^.;\n]{0,40}?\b(?:is|shall\s+be)\s+unlimited|without\s+(?:any\s+)?(?:cap|limitation)\s+on\s+(?:its\s+)?liability|(?:liable|responsible)\s+for\s+all\s+damages[^.]*?without\s+limitation|all\s+damages[^.]*?without\s+(?:any\s+)?(?:cap|limit(?:ation)?)|no\s+(?:limit|limitation|cap)\s+on\s+(?:the\s+[A-Za-z]+['’]?s?\s+|its\s+|any\s+|your\s+|such\s+)?liability|\bliability\s+(?:of\s+(?:the\s+)?[A-Za-z]+\s+)?shall\s+not\s+be\s+limited\b|\bliability\b[^.;\n]{0,40}?\b(?:is|are)\s+not\s+limited\b)/i;

/**
 * The present tense states it as often as the modal: "Guarantor's liability
 * IS NOT LIMITED in amount" is the operative sentence of every unlimited
 * guaranty and of any agreement that declines to cap, and the branch above
 * read only "shall not be limited".
 *
 * A CARVE-OUT from the cap is not the absence of one.
 *
 * "The Sellers' aggregate liability shall not exceed the Escrow Amount, except
 * that liability for Fraud is unlimited" is the single most standard sentence
 * in M&A indemnification, and every professional agreement — buyer-favorable
 * and seller-favorable alike — carves fraud, wilful misconduct, and the
 * indemnity out of the cap. Reading the carve-out as uncapped liability
 * reports the presence of a cap as its absence, at `critical`.
 *
 * The test is what the unlimited language is ABOUT: a named carve-out subject
 * within the clause, not liability at large. A clause that really does leave a
 * party's liability uncapped names no exception.
 */
const CARVE_OUT_SUBJECT =
  /\b(?:fraud|fraudulent|wil[l]?ful\s+misconduct|gross\s+negligence|intentional\s+(?:breach|misconduct)|criminal|bodily\s+injury|death|indemnification\s+obligations?|confidentiality\s+obligations?|fundamental\s+representations?|misappropriation)\b/i;
/** The connective that introduces an exception to the cap just stated. */
const CARVE_OUT_LEAD =
  /\b(?:except|excluding|other\s+than|save\s+for|provided\s+that|but\s+not)\b/i;

export const rule: Rule = {
  id: "RISK-009",
  version: "1.3.0",
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
      // Look back from the match to the start of its clause: an exception
      // connective plus a named carve-out subject means the sentence is
      // stating the cap's exception, not the absence of a cap.
      const lead = p.text.slice(Math.max(0, m.index - 160), m.index + m[0].length);
      if (CARVE_OUT_LEAD.test(lead) && CARVE_OUT_SUBJECT.test(lead)) return;
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
