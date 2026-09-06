import Decimal from "decimal.js";
import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";
import { parseWordPhrase } from "../../../extract/amounts.js";

/**
 * FIN-001 — Word-numeral amount mismatch (critical).
 *
 * Detects pairs like `one million dollars ($1,000,000)` where the numeral
 * in parentheses does not match the spelled-out amount. This is one of
 * the most consequential drafting errors a contract can carry: most
 * jurisdictions resolve the ambiguity in favor of the spelled-out form,
 * but the dispute itself can be expensive.
 */

const PAIR =
  /\b((?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million|billion|trillion|and|[-\s])+)\s+(?:dollars?|euros?|pounds?\s+sterling|pounds?)?\s*\(\s*[$€£¥₹₩₽]?\s*([\d,]+(?:\.\d+)?)\s*(k|m|mm|b|bn)?\s*\)/gi;

export const rule: Rule = {
  id: "FIN-001",
  version: "1.1.0",
  name: "Word-numeral amount mismatch",
  category: "financial",
  default_severity: "critical",
  description:
    "For every '<spelled-out amount> ($<numeral>)' pair, verifies the word and numeral describe the same amount.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    type Mismatch = {
      raw: string;
      word: Decimal;
      numeral: Decimal;
      sectionId: string;
      start: number;
      end: number;
    };
    let firstMismatch: Mismatch | null = null;

    forEachParagraph(ctx.tree, (p) => {
      if (firstMismatch) return;
      PAIR.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = PAIR.exec(p.text)) !== null) {
        const word = parseWordPhrase((m[1] ?? "").toLowerCase());
        const numeral = parseNumeral(m[2] ?? "", m[3]);
        if (!word || !numeral) continue;
        if (!word.equals(numeral)) {
          firstMismatch = {
            raw: m[0],
            word,
            numeral,
            sectionId: p.section.id,
            start: p.start + m.index,
            end: p.start + m.index + m[0].length,
          };
          break;
        }
      }
    });

    if (!firstMismatch) return null;
    const fm: Mismatch = firstMismatch;
    return makeFinding({
      rule,
      title: "Word/numeral amount mismatch",
      description: `Spelled-out amount ${fm.word.toString()} does not match numeral ${fm.numeral.toString()}.`,
      excerptText: fm.raw,
      explanation:
        "When a contract states an amount in words followed by a numeral in parentheses, the two forms must match. Courts in most US jurisdictions resolve a conflict in favor of the spelled-out form, but the inconsistency itself is a drafting error worth catching before signature.",
      recommendation:
        "Verify the intended amount with the drafter and correct whichever form is wrong.",
      position: { section_id: fm.sectionId, start: fm.start, end: fm.end },
      source_citations: [],
    });
  },
};

/**
 * Magnitude suffixes the PAIR regex tolerates. They MUST be applied
 * (fix-rule-detection-fidelity): the regex always accepted "$1M" but the
 * suffix was never multiplied in, so "one million dollars ($1M)" fired a
 * false CRITICAL ("1000000 does not match numeral 1") on a perfectly
 * consistent, commonly drafted amount.
 */
const MAGNITUDES: Record<string, string> = {
  k: "1000",
  m: "1000000",
  mm: "1000000",
  b: "1000000000",
  bn: "1000000000",
};

function parseNumeral(raw: string, suffix?: string): Decimal | null {
  try {
    const base = new Decimal(raw.replace(/,/g, ""));
    const scale = suffix ? MAGNITUDES[suffix.toLowerCase()] : undefined;
    return scale ? base.mul(scale) : base;
  } catch {
    return null;
  }
}
