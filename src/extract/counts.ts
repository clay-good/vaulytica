/**
 * A period written in words, and why a recognizer that reads only digits is
 * reading only some of its documents.
 *
 * "sixty (60) days" is the dominant form in a drafted instrument, and
 * `parenthetical-numeral.test.ts` made every period recognizer tolerate the
 * ")" that convention puts between the digits and the noun. But the numeral is
 * only ever a CHECK on the words, and the plain-language style guides that
 * every consumer notice and a growing share of commercial drafting now follow
 * drop it: "thirty days' written notice", "a thirty-day cure period". The
 * words are the third spelling of the same period, exactly as "must" is the
 * third spelling of "shall" — and a pattern written `(\d{1,3})\)?\s+days`
 * cannot see it.
 *
 * Found by the corpus relation in `spelled-period.test.ts`: rewrite every
 * "thirty (30) days" and every "30 days" as "thirty days" — the same period,
 * said the way a plain-language drafter says it — and diff the findings. On 48
 * of 285 specimens they moved. TERM-001 lost the convenience-termination
 * notice period on 24 of them; the cure-period pair lost it on 14; and where a
 * presence rule went blind an ABSENCE finding took its place — a contract that
 * says "we will notify you within seventy-two hours" was told it names no
 * breach deadline.
 *
 * Kept as ONE fragment for the same reason as {@link INSTRUMENT_NOUN}: four
 * separate hand-written word tables already existed in the tree (`amounts.ts`,
 * `dates.ts`, `FIN-001`, `FIN-005`), agreeing with each other only loosely,
 * and the next rule to need one would have written a fifth.
 */

const ONES = "one|two|three|four|five|six|seven|eight|nine";
const TEENS = "ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen";
const TENS = "twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety";
/** "twenty-four", "forty five", "ninety". */
const TENS_COMBO = `(?:${TENS})(?:[-\\s](?:${ONES}))?`;
/** Everything below a hundred, longest alternative first. */
const SMALL = `(?:${TENS_COMBO}|${TEENS}|${ONES})`;
/** "one hundred twenty", "one hundred and eighty", "hundred". */
const HUNDREDS = `(?:(?:${ONES})\\s+)?hundred(?:\\s+and)?(?:\\s+${SMALL})?`;
/** A count spelled out. Hundreds first so "one hundred twenty" is not "one". */
const WORDS = `(?:${HUNDREDS}|${SMALL})`;

/**
 * A period count in any of its three spellings, with NO capturing group of its
 * own so a caller's group indices do not move: wrap it as `(${PERIOD_COUNT})`
 * and read the span with {@link countValue}.
 *
 * The alternatives are ordered longest-first so "thirty (30)" is consumed
 * whole rather than leaving "(30)" for the following `\s+days?` to choke on.
 * Each spelled alternative carries its own `\b`: without it "of|ten days"
 * reads as a ten-day period. The bare numeral is NOT written `\(?\s*\d{1,3}`
 * — the optional paren with a free `\s*` behind it lets a match begin on the
 * space before the digits, and every excerpt built from the span then carries
 * a leading blank.
 */
export const PERIOD_COUNT = `(?:\\b(?:${WORDS})\\s*\\(\\s*\\d{1,3}\\s*\\)|\\b(?:${WORDS})|\\(\\s*\\d{1,3}\\s*\\)|\\d{1,3})`;

/**
 * The number words, in ONE place.
 *
 * Four identical copies of this table shipped in the tree — here, in
 * `amounts.ts`, in `dates.ts` and in `FIN-001` — and two byte-identical
 * parsers over it. A table that exists four times is a table that will
 * eventually disagree with itself, which is the defect this whole family of
 * repairs keeps finding at one remove.
 *
 * `zero` is in the table and NOT in {@link PERIOD_COUNT}: a zero-day period is
 * not a thing a contract states, but "zero dollars" is, and the money parsers
 * share this table.
 */
export const NUMBER_WORDS: Record<string, number> = {
  zero: 0,
  one: 1,
  two: 2,
  three: 3,
  four: 4,
  five: 5,
  six: 6,
  seven: 7,
  eight: 8,
  nine: 9,
  ten: 10,
  eleven: 11,
  twelve: 12,
  thirteen: 13,
  fourteen: 14,
  fifteen: 15,
  sixteen: 16,
  seventeen: 17,
  eighteen: 18,
  nineteen: 19,
  twenty: 20,
  thirty: 30,
  forty: 40,
  fifty: 50,
  sixty: 60,
  seventy: 70,
  eighty: 80,
  ninety: 90,
};

/**
 * The multiplier words. `hundred` MULTIPLIES what precedes it; the rest set a
 * new place value — which is why the two are separated rather than folded into
 * one table, and why every parser over them treats `hundred` specially.
 */
export const WORD_SCALES: Record<string, string> = {
  hundred: "100",
  thousand: "1000",
  million: "1000000",
  billion: "1000000000",
  trillion: "1000000000000",
};

/**
 * The number a {@link PERIOD_COUNT} span states.
 *
 * The digits win wherever both spellings are present, because in "thirty (30)"
 * the numeral is the form the drafter meant to be read literally. A span this
 * fragment cannot have produced yields 0 — the same value the `parseInt` these
 * calls replaced returned for a missing group.
 */
export function countValue(raw: string): number {
  const digits = /\d{1,3}/.exec(raw);
  if (digits) return Number(digits[0]);
  let n = 0;
  for (const token of raw.toLowerCase().split(/[-\s]+/)) {
    if (token === "" || token === "and") continue;
    if (token === "hundred") {
      n = (n || 1) * 100;
      continue;
    }
    const value = NUMBER_WORDS[token];
    if (value === undefined) return 0;
    n += value;
  }
  return n;
}
