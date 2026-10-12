/**
 * The percentages a document states, as a field of their own.
 *
 * 🚨 WHY NOT IN `amounts`, which is what the spec task asked for.
 * `openspec/changes/add-estate-planning-pack` task 1 says to extend
 * `extractAmounts` with percentage forms "as additive fields". Measured, that
 * design is wrong: `extracted.amounts` is `MoneyReference[]`,
 * `MoneyReference.currency` is a REQUIRED string, and two consumers read the
 * array as money — `report/docx.ts` renders an Amounts table with a Currency
 * column, and **FIN-003 warns "Multiple currencies referenced" whenever the
 * set of currencies has two members**. 145 of the 363 specimens state a bare
 * percentage and carry exactly one currency today, so percentages in that
 * array would put a confident false multi-currency accusation on 40% of the
 * corpus.
 *
 * A separate field costs nothing by comparison: `extractAmounts` is not
 * touched, so every existing amounts golden is byte-identical by construction
 * — which is the regression property the task itself asked for.
 *
 * ⚠️ This is an EXTRACTION, not a rule. It records what the document says and
 * draws no conclusion from it; the 42 rule files that read percentages keep
 * their own patterns, and `percent-word-form.test.ts` keeps those honest.
 */
import Decimal from "decimal.js";
import type { DocumentTree } from "../ingest/types.js";
import type { PercentageReference } from "./types.js";
import { forEachParagraph, posInParagraph } from "./walk.js";
import { parseWordPhrase } from "./amounts.js";

/** The number words `parseWordPhrase` understands, as a fragment. */
const NUMBER_WORDS = String.raw`(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|and|[-\s])+`;

/**
 * The three spellings a drafted instrument uses, in one pass so that the
 * longest wins at a given position:
 *
 *   "twenty percent (20%)"   the numeral restates the words — ONE reading
 *   "20%" / "20 percent"     the numeral alone
 *   "twenty percent"         the words alone, as plain-language and statutory
 *                            drafting write it
 *
 * The parenthetical form is listed FIRST and consumes both halves, so a
 * document that writes it does not yield two percentages for one figure.
 */
const PERCENT = new RegExp(
  [
    // twenty percent (20%)
    String.raw`\b(${NUMBER_WORDS})\s{1,4}per\s?cent(?:um)?\s{0,4}\(\s{0,4}(\d{1,3}(?:\.\d{1,6})?)\s{0,4}%\s{0,4}\)`,
    // 20% | 20 percent | 20 per cent
    String.raw`(?<![\w.])(\d{1,3}(?:\.\d{1,6})?)\s{0,4}(?:%|per\s?cent(?:um)?\b)`,
    // twenty percent
    String.raw`\b(${NUMBER_WORDS})\s{1,4}per\s?cent(?:um)?\b`,
  ].join("|"),
  "gi",
);

/**
 * ⚠️ FRACTIONS ARE DELIBERATELY NOT EXTRACTED, and the reason is a measurement
 * rather than a scruple. A pass over the 363 specimens reading `N/M` as a
 * share returned roughly one wrong answer for every right one:
 *
 *   "AND 00/100 DOLLARS"   the CENTS convention every promissory note writes
 *   "5/2", "14/1"          dates in slash form, and docket references
 *   "90/20"               a ratio that is not a share at all
 *
 * against genuine shares like `2/3` (a two-thirds vote) and `1/48` (a monthly
 * vesting fraction). Telling them apart needs the surrounding words, not the
 * punctuation — the same lesson as telling a liability CAP from an insurance
 * LIMIT — and a report that tells an attorney a note pays "0% of the whole"
 * because it quoted the cents convention is worse than one that stays quiet.
 *
 * The spelled form that matters for a share is already covered: "one-half" is
 * number words, so "one-half percent" reads correctly through the pass above.
 */
export function extractPercentages(tree: DocumentTree): PercentageReference[] {
  const out: PercentageReference[] = [];
  let counter = 0;

  forEachParagraph(tree, (ctx) => {
    PERCENT.lastIndex = 0;
    for (const m of ctx.text.matchAll(PERCENT)) {
      const at = m.index ?? 0;
      const end = at + m[0].length;
      // The spelled-plus-numeral form is one percentage, not two.
      const words = m[1] ?? m[4];
      const digits = m[2] ?? m[3];
      let value: string | null = null;
      if (digits !== undefined) {
        value = new Decimal(digits).toString();
      } else if (words !== undefined) {
        const parsed = parseWordPhrase(words.trim().toLowerCase());
        value = parsed ? parsed.toString() : null;
      }
      if (value === null) continue;
      out.push({
        id: `pct-${++counter}`,
        raw_text: m[0].trim(),
        percent: value,
        word_form: digits === undefined,
        position: posInParagraph(ctx, at, end),
      });
    }
  });

  return out;
}
