import Decimal from "decimal.js";
import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * FIN-001 — Word-numeral amount mismatch (critical).
 *
 * Detects pairs like `one million dollars ($1,000,000)` where the numeral
 * in parentheses does not match the spelled-out amount. This is one of
 * the most consequential drafting errors a contract can carry: most
 * jurisdictions resolve the ambiguity in favor of the spelled-out form,
 * but the dispute itself can be expensive.
 */

const PAIR = /\b((?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million|billion|trillion|and|[-\s])+)\s+(?:dollars?|euros?|pounds?\s+sterling|pounds?)?\s*\(\s*[$€£¥]?\s*([\d,]+(?:\.\d+)?)\s*(?:k|m|mm|b|bn)?\s*\)/gi;

const NUMBER_WORDS: Record<string, number> = {
  zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7,
  eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13,
  fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17, eighteen: 18,
  nineteen: 19, twenty: 20, thirty: 30, forty: 40, fifty: 50, sixty: 60,
  seventy: 70, eighty: 80, ninety: 90,
};
const WORD_SCALES: Record<string, string> = {
  hundred: "100",
  thousand: "1000",
  million: "1000000",
  billion: "1000000000",
  trillion: "1000000000000",
};

export const rule: Rule = {
  id: "FIN-001",
  version: "1.0.0",
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
        const word = parseWords(m[1] ?? "");
        const numeral = parseNumeral(m[2] ?? "");
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
      recommendation: "Verify the intended amount with the drafter and correct whichever form is wrong.",
      position: { section_id: fm.sectionId, start: fm.start, end: fm.end },
      source_citations: [],
    });
  },
};

function parseWords(phrase: string): Decimal | null {
  const tokens = phrase.toLowerCase().replace(/-/g, " ").split(/\s+/).filter((t) => t && t !== "and");
  if (tokens.length === 0) return null;
  let current = new Decimal(0);
  let total = new Decimal(0);
  let recognized = false;
  for (const tok of tokens) {
    if (tok in NUMBER_WORDS) {
      current = current.plus(NUMBER_WORDS[tok]!);
      recognized = true;
    } else if (tok in WORD_SCALES) {
      const scale = WORD_SCALES[tok]!;
      if (tok === "hundred") {
        current = current.equals(0) ? new Decimal(100) : current.mul(100);
      } else {
        total = total.plus((current.equals(0) ? new Decimal(1) : current).mul(scale));
        current = new Decimal(0);
      }
      recognized = true;
    } else {
      return null;
    }
  }
  return recognized ? total.plus(current) : null;
}

function parseNumeral(raw: string): Decimal | null {
  try {
    return new Decimal(raw.replace(/,/g, ""));
  } catch {
    return null;
  }
}
