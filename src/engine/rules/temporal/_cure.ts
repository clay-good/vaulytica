/**
 * Shared cure-period matcher for the sibling rules TEMP-008 (presence) and
 * TEMP-009 (length). They must agree on what counts as a breach-cure period, so
 * both import this single regex rather than maintaining parallel copies that
 * drift.
 *
 * The trigger is anchored to a breach/default so an unrelated "sole remedy" or
 * "correct the invoice" is not read as a cure period. "cure" is drafted
 * interchangeably as "remedy" / "correct"; the informal "fix" is excluded. The
 * `\b` before the verb keeps "procure such breach-free …" from matching.
 *
 * The day count sits on EITHER side of the trigger:
 *   - trigger-first: "cure such breach within thirty (30) days"
 *   - count-first:   "thirty (30) days to cure the breach", "a 5-day cure period"
 * The count is parenthesized in the standard form ("thirty (30) days") and may
 * be hyphen-joined in the adjacent form ("5-day"), so both are tolerated.
 */
const CURE_TRIGGER =
  "(?:cure|remed(?:y|ies)|correct)\\s+(?:such\\s+|the\\s+|any\\s+|its\\s+)?(?:breach|default|failure|violation|non[-\\s]?performance)|opportunity\\s+to\\s+(?:cure|remedy|correct)|cure\\s+period";
// The reversed (count-first) branch also accepts a bare "to cure / remedy /
// correct" with no explicit breach noun — "shall have 90 days to cure" — which
// the count-first drafting frequently leaves implicit.
const REVERSED_ANCHOR = `to\\s+(?:cure|remed(?:y|ies)|correct)\\b|${CURE_TRIGGER}`;
const DAYS = "\\(?(\\d{1,3})\\)?[-\\s]days?";

// In the count-first branch the count must sit CLOSE to the cure phrase
// ("30-day cure period", "30 days to cure", "30 days from notice to cure") — a
// wide gap would let it grab an unrelated leading count, e.g. read "60 days
// prior written notice and a 30-day cure period" as a 60-day cure period. A
// short window keeps it locked onto the adjacent count (the real 30).
export const CURE_PERIOD = new RegExp(
  `\\b(?:${CURE_TRIGGER})[\\s\\S]{0,80}?${DAYS}|${DAYS}\\b[\\s\\S]{0,20}?(?:${REVERSED_ANCHOR})`,
  "i",
);

/** The cure-period length in days from a `CURE_PERIOD` match (either branch). */
export function curePeriodDays(m: RegExpMatchArray): number {
  return parseInt(m[1] ?? m[2] ?? "0", 10);
}
