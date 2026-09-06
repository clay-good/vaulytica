/**
 * The first absolute date in a span of text, in every ordering a contract
 * writes one.
 *
 * `src/extract/dates.ts` has read four orderings since it was written — ISO,
 * month-first prose, day-first prose ("1 March 2029", "the 1st of March,
 * 2029"), and the formal-instrument form ("this 4th day of October 2029") —
 * because a deed, a will and any English or Commonwealth agreement date
 * themselves the last two ways. The critical-dates register and the report
 * exports each carried their OWN copy of an anchor parser that read only
 * month-first prose, each labelled "mirrors" the other, and neither read a
 * day-first date or even an ordinal suffix.
 *
 * The cost is not a missing finding; it is a resolved deadline turning into
 * "verify manually". Restating the corpus in day-first order — the same dates,
 * the way the rest of the common law writes them — left the findings identical
 * and moved SEVEN specimens' registers: a survival end date, four notice
 * periods and a cure window each lost the anchor they were computed from.
 * That register ships its own hash, so a silent downgrade there is a silent
 * change to a published artifact.
 *
 * One parser now, imported by both consumers. It deliberately does NOT try to
 * be `dates.ts`: it answers one question — the first absolute date in this
 * span — which is all an anchor resolution needs.
 */

const MONTHS =
  "January|February|March|April|May|June|July|August|September|October|November|December|" +
  "Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec";

const ISO = /\b(\d{4})-(\d{2})-(\d{2})\b/;
/** "January 1, 2026", "Jan. 1st 2026" — the ordinal suffix is as common as not. */
const MONTH_FIRST = new RegExp(
  String.raw`\b(${MONTHS})\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})\b`,
  "i",
);
/** "the 15th day of September, 2029" — how a deed or a will dates itself. */
const DAY_OF_MONTH = new RegExp(
  String.raw`\b(?:the|this)\s+(\d{1,2})(?:st|nd|rd|th)\s+day\s+of\s+(${MONTHS})\.?,?\s+(\d{4})\b`,
  "i",
);
/** "1 March 2029", "the 1st of March, 2029". */
const DAY_FIRST = new RegExp(
  String.raw`\b(?:the\s+)?(\d{1,2})(?:st|nd|rd|th)?\s+(?:of\s+)?(${MONTHS})\.?,?\s+(\d{4})\b`,
  "i",
);
const US_NUMERIC = /\b(\d{1,2})\/(\d{1,2})\/(\d{2,4})\b/;

/**
 * Month name (full or abbreviated, with or without a trailing period) → its
 * number. `dates.ts` carried a second copy inside a function; one owner now.
 */
export const MONTH_NUM: Record<string, number> = {
  january: 1,
  jan: 1,
  february: 2,
  feb: 2,
  march: 3,
  mar: 3,
  april: 4,
  apr: 4,
  may: 5,
  june: 6,
  jun: 6,
  july: 7,
  jul: 7,
  august: 8,
  aug: 8,
  september: 9,
  sep: 9,
  sept: 9,
  october: 10,
  oct: 10,
  november: 11,
  nov: 11,
  december: 12,
  dec: 12,
};

/** Same two-digit-year pivot as `dates.ts`: 00–69 → 2000s, 70–99 → 1900s. */
const TWO_DIGIT_YEAR_PIVOT = 70;

export function validIso(y: number, m: number, d: number): boolean {
  if (m < 1 || m > 12 || d < 1 || d > 31) return false;
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

export function toIso(y: number, m: number, d: number): string {
  return `${String(y).padStart(4, "0")}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
}

/** The number a month NAME states, or undefined if it is not a month. */
export const monthNumber = (raw: string): number | undefined =>
  MONTH_NUM[raw.toLowerCase().replace(/\./g, "")];

/**
 * The first absolute date in `text` as ISO, or undefined.
 *
 * The orderings are tried in a fixed sequence rather than by position, which
 * is the behaviour both copies already had: ISO, then month-first prose, then
 * the two day-first prose forms, then the US numeric shorthand. The
 * formal-instrument form is tried before the bare day-first one because
 * "the 15th day of September, 2029" satisfies both and only the first reading
 * consumes the scaffold — the ISO they produce is identical either way, but
 * trying the specific form first keeps that independent of the other's shape.
 */
export function firstAbsoluteIso(text: string): string | undefined {
  const iso = ISO.exec(text);
  if (iso && validIso(+iso[1]!, +iso[2]!, +iso[3]!)) return toIso(+iso[1]!, +iso[2]!, +iso[3]!);

  const monthFirst = MONTH_FIRST.exec(text);
  if (monthFirst) {
    const mo = monthNumber(monthFirst[1]!);
    if (mo !== undefined && validIso(+monthFirst[3]!, mo, +monthFirst[2]!)) {
      return toIso(+monthFirst[3]!, mo, +monthFirst[2]!);
    }
  }

  for (const re of [DAY_OF_MONTH, DAY_FIRST]) {
    const m = re.exec(text);
    if (!m) continue;
    const mo = monthNumber(m[2]!);
    if (mo !== undefined && validIso(+m[3]!, mo, +m[1]!)) return toIso(+m[3]!, mo, +m[1]!);
  }

  const us = US_NUMERIC.exec(text);
  if (us) {
    let y = +us[3]!;
    if (us[3]!.length === 2) y = y < TWO_DIGIT_YEAR_PIVOT ? 2000 + y : 1900 + y;
    if (validIso(y, +us[1]!, +us[2]!)) return toIso(y, +us[1]!, +us[2]!);
  }
  return undefined;
}
