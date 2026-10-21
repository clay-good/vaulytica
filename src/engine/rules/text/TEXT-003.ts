import type { Finding, Rule, RuleContext } from "../../finding.js";
import { emit } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";
import { carriesFormatting } from "./_match.js";

/** A disclaimer of the implied warranty of merchantability, which § 2-316(2) requires to be conspicuous. */
const MERCHANTABILITY_DISCLAIMER =
  /\b(?:disclaim\w*|exclud\w*|waive\w*|no)\b[^.]{0,200}\bmerchantab\w*|\bmerchantab\w*[^.]{0,200}\b(?:disclaim\w*|exclud\w*|waive\w*)\b/i;

/** A heading that names the disclaimer: a heading in contrasting type is one way to be conspicuous. */
const DISCLAIMER_HEADING = /warrant|disclaim/i;

/** Most of the letters are capitals. */
function inCapitals(text: string): boolean {
  const letters = text.replace(/[^A-Za-z]/g, "");
  if (letters.length < 20) return false;
  return letters.replace(/[^A-Z]/g, "").length / letters.length >= 0.9;
}

/**
 * TEXT-003 — A warranty disclaimer in plain body type (info).
 *
 * U.C.C. § 2-316(2) requires a written exclusion of the implied warranty of
 * merchantability to be conspicuous, and § 1-201(b)(10) says what that
 * means: a heading in capitals or contrasting type, or body text in larger
 * or contrasting type, capitals, or color. A Word file shows which of those
 * it used. A disclaimer set in regular, mixed-case body type with no
 * heading naming it, and no bold, is reported; one with any of them is not.
 *
 * Whether a court finds a clause conspicuous is the court's call, and the
 * finding never says the disclaimer fails. Liability caps are not read: they
 * fall under § 2-719, which sets no conspicuousness requirement. Read only
 * where the file carries formatting.
 */
export const rule: Rule = {
  id: "TEXT-003",
  version: "1.0.0",
  name: "Warranty disclaimer in plain type",
  category: "mandated-text",
  default_severity: "info",
  description:
    "Notes a disclaimer of the warranty of merchantability that a Word file sets in regular, mixed-case body type, with no bold, capitals or heading naming it.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    if (!carriesFormatting(ctx)) return null;
    let hit: Finding | null = null;
    forEachParagraph(ctx.tree, (p) => {
      if (hit || !MERCHANTABILITY_DISCLAIMER.test(p.text)) return;
      if (DISCLAIMER_HEADING.test(p.section.heading ?? "")) return;
      if (p.paragraph.runs.some((r) => r.formatting?.bold)) return;
      if (inCapitals(p.text)) return;
      hit = emit(ctx, rule, {
        title: "Warranty disclaimer is in plain body type",
        description:
          "This paragraph disclaims the warranty of merchantability in regular, mixed-case type, with no bold, no capitals, and no heading naming it.",
        excerpt: p.text,
        explanation:
          "U.C.C. § 2-316(2) requires a written exclusion of merchantability to be conspicuous; § 1-201(b)(10) counts a heading in capitals or contrasting type, or body text in larger, contrasting or capital type. Whether a clause is conspicuous is for a court, and this does not say the disclaimer fails; it says the file shows none of those markers.",
        recommendation:
          'Give the disclaimer a heading in bold or capitals ("DISCLAIMER OF WARRANTIES"), or set its text in capitals or bold.',
        position: {
          section_id: p.section.id,
          paragraph_id: p.paragraph.id,
          start: p.start,
          end: p.end,
        },
      });
    });
    return hit;
  },
};
