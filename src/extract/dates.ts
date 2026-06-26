import type { DocumentTree } from "../ingest/types.js";
import type { DateReference } from "./types.js";
import { forEachParagraph, posInParagraph } from "./walk.js";

/**
 * Extract every date reference from the document. Categories:
 *
 * 1. Absolute dates: `2025-01-01`, `1/1/2025`, `01/01/25`, `January 1, 2025`.
 * 2. Relative dates: `thirty (30) days after the Effective Date`,
 *    `within 60 days of the date hereof`. Disjunctive ranges
 *    (`thirty to sixty days after …`) keep both bounds.
 * 3. Named-anchor references: bare uses of defined date terms such as
 *    `the Effective Date` or `the Commencement Date`. (The actual
 *    definition is resolved by the definitions extractor, not here.)
 * 4. Fiscal periods: `fiscal Q2 2025`, `FY2025-Q3` — no calendar-unit
 *    anchor exists, so these are surfaced for manual verification.
 */

const MONTHS =
  "January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec";

/**
 * Two-digit-year century pivot. A bare two-digit year `YY < PIVOT`
 * resolves to `2000 + YY`, otherwise `1900 + YY`. This follows the
 * POSIX `strptime` convention (years 69–99 → 1969–1999, 00–68 →
 * 2000–2068); 70 is the documented boundary. It is a heuristic: a
 * decades-old trust instrument or a far-future refinancing date can sit
 * on the wrong side of it, so a two-digit year is a candidate for
 * surrounding-context confirmation, not a guarantee.
 */
const TWO_DIGIT_YEAR_PIVOT = 70;

const ISO = /\b(\d{4})-(\d{2})-(\d{2})\b/g;
const US_NUMERIC = /\b(\d{1,2})\/(\d{1,2})\/(\d{2,4})\b/g;
const PROSE = new RegExp(String.raw`\b(${MONTHS})\.?\s+(\d{1,2}),?\s+(\d{4})\b`, "gi");

const NUMBER_WORDS: Record<string, number> = {
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
  hundred: 100,
};

/**
 * Disjunctive / range deadlines: "thirty to sixty days after the
 * Effective Date", "30 to 60 days of …". Captured before the single
 * RELATIVE pass; the matched span suppresses the single-bound pass so
 * the same phrase is not double-counted. A range whose upper bound is
 * unresolved is reported verify-manually, never guessed to one date.
 */
// The optional numeral chain between the count word and the unit uses BOUNDED
// whitespace (`\s{0,8}`, not `\s*`): four adjacent unbounded `\s*` over the same
// whitespace run is polynomial backtracking (ReDoS) — `\s` matches Unicode
// whitespace (NBSP, etc.) that `normalize` does NOT collapse (it folds only
// `[ \t\r\n]`), so a crafted run of hundreds of NBSPs would otherwise hang the
// extractor (spec-v8 §5: bound, never timeout). Eight is far beyond any real
// inter-token gap (post-normalization ≤ 2), so the match is byte-identical on
// every realistic input — verified — while backtracking is now linear.
// The count word itself is bounded (`\w{1,40}`, not `\w+`): an unbounded `\w+`
// overlaps the later `(\d+)` over a long digit run (`\w` matches digits), which
// is O(n^2) on a giant pasted number; no count word/numeral exceeds 40 chars.
const RANGE_RELATIVE = new RegExp(
  String.raw`\b(?:within\s+|between\s+)?(\w{1,40}(?:[-\s]\w{1,40})?)\s{0,8}\(?\s{0,8}(\d+)?\s{0,8}\)?\s{0,8}(?:to|-|–|—|and|or)\s+(\w{1,40}(?:[-\s]\w{1,40})?)\s{0,8}\(?\s{0,8}(\d+)?\s{0,8}\)?\s{0,8}(day|days|week|weeks|month|months|year|years|business\s+day|business\s+days)\s+(?:after|before|of|from|following|prior\s+to)\s+(?:the\s+)?([A-Z][\w\s]{2,40}?)(?=[.,;)]|$)`,
  "gi",
);

const RELATIVE = new RegExp(
  String.raw`\b(?:within\s+)?(\w{1,40}(?:[-\s]\w{1,40})?)\s{0,8}\(?\s{0,8}(\d+)?\s{0,8}\)?\s{0,8}(day|days|week|weeks|month|months|year|years|business\s+day|business\s+days)\s+(?:after|before|of|from|following|prior\s+to)\s+(?:the\s+)?([A-Z][\w\s]{2,40}?)(?=[.,;)]|$)`,
  "gi",
);

/**
 * Named date anchors. The vocabulary is a small, inspectable, citable
 * alias set rather than an opaque literal: each phrase is a defined
 * date term that real agreements use as the reference point for
 * relative deadlines. Keep these in canonical "<Phrase> Date" form so
 * obligation/cross-document resolution sees one stable anchor per
 * concept. (v7 §5: broaden anchor-alias breadth.)
 */
const ANCHOR_ALIASES =
  "Effective|Closing|Commencement|Termination|Expiration|Renewal|Execution|Signing|Start|Term Start|Delivery|Acceptance|Go-Live|Hire|Grant|Vesting|Maturity|Funding|Disbursement|Completion|Onboarding";

const NAMED_ANCHOR = new RegExp(String.raw`\bthe\s+(${ANCHOR_ALIASES})\s+Date\b`, "gi");

/** Bare "Date Hereof" / "date hereof" — an anchor with no "Date" suffix. */
const DATE_HEREOF = /\bthe\s+(Date\s+Hereof)\b/gi;

/**
 * Fiscal periods: "fiscal Q2 2025", "FY2025-Q3", "FY 2025", "fiscal
 * year 2025". No calendar-unit anchor exists; financial documents use
 * them for payment and reporting deadlines, so capture them rather than
 * fall silent. Normalized to an `FYyyyy[-Qn]` label.
 */
const FISCAL_PERIOD =
  /\b(?:fiscal\s+(?:year\s+)?|FY\s*)(\d{4})(?:[-\s]?Q([1-4]))?\b|\bfiscal\s+Q([1-4])\s+(\d{4})\b/gi;

export function extractDates(tree: DocumentTree): DateReference[] {
  const out: DateReference[] = [];
  let counter = 0;
  const nextId = (): string => `date-${++counter}`;

  forEachParagraph(tree, (ctx) => {
    ISO.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = ISO.exec(ctx.text)) !== null) {
      const iso = `${m[1]}-${m[2]}-${m[3]}`;
      const valid = isValidIso(iso);
      out.push({
        id: nextId(),
        type: "absolute",
        raw_text: m[0],
        iso: valid ? iso : undefined,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
    US_NUMERIC.lastIndex = 0;
    while ((m = US_NUMERIC.exec(ctx.text)) !== null) {
      const mm = parseInt(m[1]!, 10);
      const dd = parseInt(m[2]!, 10);
      let yyyy = parseInt(m[3]!, 10);
      if (m[3]!.length === 2) yyyy = yyyy < TWO_DIGIT_YEAR_PIVOT ? 2000 + yyyy : 1900 + yyyy;
      const iso = `${yyyy.toString().padStart(4, "0")}-${mm.toString().padStart(2, "0")}-${dd.toString().padStart(2, "0")}`;
      out.push({
        id: nextId(),
        type: "absolute",
        raw_text: m[0],
        iso: isValidIso(iso) ? iso : undefined,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
    PROSE.lastIndex = 0;
    while ((m = PROSE.exec(ctx.text)) !== null) {
      const month = monthNumber(m[1]!);
      const day = parseInt(m[2]!, 10);
      const year = parseInt(m[3]!, 10);
      const iso =
        month !== null
          ? `${year.toString().padStart(4, "0")}-${month.toString().padStart(2, "0")}-${day.toString().padStart(2, "0")}`
          : undefined;
      out.push({
        id: nextId(),
        type: "absolute",
        raw_text: m[0],
        iso: iso && isValidIso(iso) ? iso : undefined,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
    // Disjunctive / range deadlines first; record spans so the
    // single-bound RELATIVE pass below does not double-count them.
    const rangeSpans: Array<[number, number]> = [];
    RANGE_RELATIVE.lastIndex = 0;
    while ((m = RANGE_RELATIVE.exec(ctx.text)) !== null) {
      const lower = countOf(m[1], m[2]);
      const upper = countOf(m[3], m[4]);
      const unit = (m[5] ?? "").toLowerCase().replace(/\s+/g, " ").trim();
      const anchor = (m[6] ?? "").trim();
      if (lower === null || upper === null) continue;
      const direction = /\bbefore\b|\bprior\s+to\b/i.test(m[0]) ? -1 : 1;
      const lo = lower * unitToDays(unit) * direction;
      const hi = upper * unitToDays(unit) * direction;
      const calUnit = unitToCalendar(unit);
      rangeSpans.push([m.index, m.index + m[0].length]);
      out.push({
        id: nextId(),
        type: "relative",
        raw_text: m[0],
        anchor,
        offset_days: Math.min(lo, hi),
        offset_days_max: Math.max(lo, hi),
        offset_unit: calUnit,
        offset_count: Math.min(lower, upper) * direction,
        offset_count_max: Math.max(lower, upper) * direction,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
    RELATIVE.lastIndex = 0;
    while ((m = RELATIVE.exec(ctx.text)) !== null) {
      const start = m.index;
      const end = m.index + m[0].length;
      if (rangeSpans.some(([s, e]) => start < e && end > s)) continue;
      const wordCount = m[1] ? parseWordNumber(m[1]) : null;
      const numericCount = m[2] ? parseInt(m[2], 10) : null;
      const unit = (m[3] ?? "").toLowerCase().replace(/\s+/g, " ").trim();
      const anchor = (m[4] ?? "").trim();
      const count = numericCount ?? wordCount;
      const direction = /\bbefore\b|\bprior\s+to\b/i.test(m[0]) ? -1 : 1;
      const days = count !== null ? count * unitToDays(unit) * direction : undefined;
      out.push({
        id: nextId(),
        type: "relative",
        raw_text: m[0],
        anchor,
        offset_days: days,
        ...(count !== null
          ? { offset_unit: unitToCalendar(unit), offset_count: count * direction }
          : {}),
        position: posInParagraph(ctx, start, end),
      });
    }
    NAMED_ANCHOR.lastIndex = 0;
    while ((m = NAMED_ANCHOR.exec(ctx.text)) !== null) {
      out.push({
        id: nextId(),
        type: "named-anchor",
        raw_text: m[0].replace(/^the\s+/i, ""),
        anchor: `${titleCaseAnchor(m[1]!)} Date`,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
    DATE_HEREOF.lastIndex = 0;
    while ((m = DATE_HEREOF.exec(ctx.text)) !== null) {
      out.push({
        id: nextId(),
        type: "named-anchor",
        raw_text: m[0].replace(/^the\s+/i, ""),
        anchor: "Date Hereof",
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
    FISCAL_PERIOD.lastIndex = 0;
    while ((m = FISCAL_PERIOD.exec(ctx.text)) !== null) {
      // Two alternations: "FY2025[-Q3]" (m1=year, m2=quarter) or
      // "fiscal Q3 2025" (m3=quarter, m4=year).
      const year = m[1] ?? m[4];
      const quarter = m[2] ?? m[3];
      if (!year) continue;
      const label = quarter ? `FY${year}-Q${quarter}` : `FY${year}`;
      out.push({
        id: nextId(),
        type: "fiscal-period",
        raw_text: m[0],
        fiscal_period: label,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
  });

  return out;
}

/**
 * Resolve a count from a word-slot and an optional parenthetical digit
 * slot, e.g. ("thirty", "30") → 30, ("thirty", undefined) → 30,
 * ("30", undefined) → 30. Returns null when neither resolves.
 */
function countOf(wordGroup: string | undefined, digitGroup: string | undefined): number | null {
  if (digitGroup) return parseInt(digitGroup, 10);
  if (!wordGroup) return null;
  const w = parseWordNumber(wordGroup);
  if (w !== null) return w;
  return /^\d+$/.test(wordGroup.trim()) ? parseInt(wordGroup.trim(), 10) : null;
}

/** Title-case a (possibly multi-word, hyphenated) anchor alias. */
function titleCaseAnchor(raw: string): string {
  return raw
    .split(/(\s+|-)/)
    .map((part) =>
      /^\s+$/.test(part) || part === "-"
        ? part
        : part.charAt(0).toUpperCase() + part.slice(1).toLowerCase(),
    )
    .join("");
}

function monthNumber(name: string): number | null {
  const map: Record<string, number> = {
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
  const v = map[name.toLowerCase().replace(/\./g, "")];
  return v ?? null;
}

function isValidIso(iso: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso);
  if (!m) return false;
  const y = +m[1]!;
  const mo = +m[2]!;
  const d = +m[3]!;
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return false;
  const date = new Date(Date.UTC(y, mo - 1, d));
  return date.getUTCFullYear() === y && date.getUTCMonth() === mo - 1 && date.getUTCDate() === d;
}

function parseWordNumber(raw: string): number | null {
  const parts = raw.toLowerCase().split(/[-\s]+/);
  let total = 0;
  let recognized = false;
  for (const p of parts) {
    const v = NUMBER_WORDS[p];
    if (v === undefined) continue;
    recognized = true;
    if (v === 100) total = (total || 1) * 100;
    else total += v;
  }
  return recognized ? total : null;
}

function unitToDays(unit: string): number {
  if (unit.startsWith("business day")) return 1;
  if (unit.startsWith("day")) return 1;
  if (unit.startsWith("week")) return 7;
  if (unit.startsWith("month")) return 30;
  if (unit.startsWith("year")) return 365;
  return 1;
}

/**
 * Map a matched unit token to the canonical calendar unit the v9
 * critical-dates derivation uses for month-end / leap-year-correct
 * arithmetic. "business day(s)" is preserved distinctly so the register
 * can surface it verify-manually (no holiday calendar is asserted).
 */
function unitToCalendar(unit: string): "days" | "weeks" | "months" | "years" | "business-days" {
  if (unit.startsWith("business day")) return "business-days";
  if (unit.startsWith("week")) return "weeks";
  if (unit.startsWith("month")) return "months";
  if (unit.startsWith("year")) return "years";
  return "days";
}
