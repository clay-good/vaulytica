import Decimal from "decimal.js";
import type { DocumentTree } from "../ingest/types.js";
import type { MoneyReference } from "./types.js";
import { forEachParagraph, posInParagraph } from "./walk.js";

/**
 * Extract every monetary reference. Normalization rules:
 *
 * - Numeric form: `$1,500,000.00`, `USD 1.5MM`, `EUR 200k`, `£500`,
 *   `1,500,000 USD`. Multiplier suffixes recognized: `k` (×1e3),
 *   `m`, `mm`, `mn` (×1e6), `b`, `bn` (×1e9).
 * - Word form: `one million five hundred thousand dollars`.
 *
 * Currency defaults to USD when the symbol is `$` and is otherwise
 * resolved from the ISO 4217 hint or the symbol. Decimal arithmetic uses
 * `decimal.js` to avoid binary float imprecision.
 */

Decimal.set({ precision: 50 });

/**
 * Magnitude bound (spec-v8 §9). An amount whose integer-digit count exceeds
 * this — a `"999…999 billion"` with fifty digits — is adversarial, not a real
 * figure (a $1 quadrillion contract has 16 digits), and drives unbounded
 * `decimal.js` work. Such an amount, or one that resolves to NaN/±Infinity, is
 * dropped from the extracted stream with no `MoneyReference` emitted. The
 * extracted-data stream is not part of `result_hash` and no rule reads a
 * fifty-digit amount, so this is zero-churn against the goldens.
 */
const MAX_AMOUNT_DIGITS = 30;

const CURRENCY_SYMBOLS: Record<string, string> = {
  $: "USD",
  "€": "EUR",
  "£": "GBP",
  "¥": "JPY",
  "₹": "INR",
  "₩": "KRW",
  "₽": "RUB",
};

const CURRENCY_CODES = new Set([
  "USD",
  "EUR",
  "GBP",
  "JPY",
  "CAD",
  "AUD",
  "NZD",
  "CHF",
  "CNY",
  "INR",
  "KRW",
  "BRL",
  "MXN",
  "ZAR",
  "SGD",
  "HKD",
  "SEK",
  "NOK",
  "DKK",
  "RUB",
]);

const CUR = String.raw`[$€£¥₹₩₽]|\b(?:USD|EUR|GBP|JPY|CAD|AUD|NZD|CHF|CNY|INR|KRW|BRL|MXN|ZAR|SGD|HKD|SEK|NOK|DKK|RUB)\b`;
// Digit counts are BOUNDED (`{0,40}`/`{1,40}`, not `*`/`+`): in RANGE_NUMERIC
// the amount is followed by a REQUIRED range connector, so an unbounded `\d+`
// matches a whole pasted digit run, fails to find the connector, then
// backtracks the run from every start position — O(n²) (a ReDoS hang). Forty
// digits comfortably exceeds MAX_AMOUNT_DIGITS (30), so any number long enough
// to be bounded here is dropped by `computeAmount` regardless: byte-identical
// extraction on every real amount, linear on a hostile digit run.
const AMT = String.raw`[\d]{1,3}(?:,\d{3}){0,40}(?:\.\d{1,40})?|\d{1,40}(?:\.\d{1,40})?`;
const SCALE = String.raw`k|kk|m|mm|mn|bn|b`;

// Whitespace gaps are BOUNDED (`\s{0,8}`, not `\s*`): an optional currency
// prefix leaves `\s*` as the first real token, so a global exec-loop over a long
// whitespace run rescans the remainder from every start position before the
// required amount fails — O(n²) per pass. `\s` matches NBSP (which `normalize`
// keeps), so a crafted NBSP run is a reachable hang. No real money expression
// has > 8 chars between the symbol, digits, and scale, so this is byte-identical.
const NUMERIC = new RegExp(String.raw`(${CUR})?\s{0,8}(${AMT})\s{0,8}(${SCALE})?`, "gi");

/**
 * Range amounts: "$100k to $200k", "between USD 50,000 and USD 100,000".
 * Matched before the single NUMERIC pass; the span suppresses the
 * single-amount pass so the same phrase is not double-counted. The
 * lower bound becomes `amount`, the upper becomes `range_max`, so a cap
 * rule reads the controlling (upper) bound. (v7 §6.)
 */
const RANGE_NUMERIC = new RegExp(
  String.raw`(between\s+)?(${CUR})?\s{0,8}(${AMT})\s{0,8}(${SCALE})?\s{0,8}(to|through|–|—|-|and)\s{1,8}(${CUR})?\s{0,8}(${AMT})\s{0,8}(${SCALE})?`,
  "gi",
);

/** Trailing per-unit qualifier: "per user", "/ user, per month", "per incident". */
const PER_UNIT = /^\s*(?:per|\/)\s+([a-z][\w]*(?:[\s,/-]+(?:per\s+)?[a-z][\w]*){0,3})/i;

/**
 * Deferred currency override controlling clause: "all amounts are in
 * CAD unless otherwise stated", "all fees stated in EUR". Resolved in a
 * second pass so ambiguous `$`-symbol amounts that appeared before the
 * clause adopt the controlling currency. (v7 §6.)
 */
const CURRENCY_OVERRIDE =
  /\ball\s+(?:amounts?|fees?|payments?|sums?|figures?|prices?|charges?)\s+(?:are\s+|is\s+|stated\s+|expressed\s+|denominated\s+|shall\s+be\s+|will\s+be\s+|to\s+be\s+)*in\s+(USD|EUR|GBP|JPY|CAD|AUD|NZD|CHF|CNY|INR|KRW|BRL|MXN|ZAR|SGD|HKD|SEK|NOK|DKK|RUB)\b/i;

const SCALES: Record<string, string> = {
  k: "1000",
  kk: "1000000",
  m: "1000000",
  mm: "1000000",
  mn: "1000000",
  b: "1000000000",
  bn: "1000000000",
};

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
};

const WORD_SCALES: Record<string, string> = {
  hundred: "100",
  thousand: "1000",
  million: "1000000",
  billion: "1000000000",
  trillion: "1000000000000",
};

// The inner separator is a SINGLE `[-\s]` (not `[-\s]+`): a `(?:…|[-\s]+)+`
// shape is catastrophic backtracking (ReDoS) — for a run of hyphens/spaces it
// degenerates to `([-\s]+)+`, with 2^(n-1) ways to partition the run, so a
// fill-in line like `ten ------------------` would hang the extractor. With a
// single-char separator each space/hyphen is one deterministic iteration; the
// matched language and greedy match are identical (verified), so no golden
// churn — but the match is now linear instead of exponential.
// The trailing separator before the currency word is BOUNDED (`\s{1,8}`, not
// `\s+`): the group's `[-\s]` and an unbounded trailing `\s+` both consume a
// whitespace run, which is O(n^2) on a long NBSP run (NBSP survives normalize);
// no real gap before "dollars" exceeds 8 chars, so the match is unchanged.
const WORD_FORM = new RegExp(
  String.raw`\b((?:(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million|billion|trillion|and|[-\s])+))\s{1,8}(dollars?|euros?|pounds?\s+sterling|pounds?)\b`,
  "gi",
);

export function extractAmounts(tree: DocumentTree): MoneyReference[] {
  const out: MoneyReference[] = [];
  let counter = 0;
  const nextId = (): string => `money-${++counter}`;
  /** Indices in `out` whose currency came from a bare `$` symbol (ambiguous). */
  const dollarSourced: number[] = [];
  let overrideCurrency: string | null = null;

  forEachParagraph(tree, (ctx) => {
    if (overrideCurrency === null) {
      const ov = CURRENCY_OVERRIDE.exec(ctx.text);
      if (ov) overrideCurrency = ov[1]!.toUpperCase();
    }
    // Range amounts first; record spans so the single NUMERIC pass does
    // not double-count either endpoint.
    const rangeSpans: Array<[number, number]> = [];
    RANGE_NUMERIC.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = RANGE_NUMERIC.exec(ctx.text)) !== null) {
      const between = m[1];
      const connector = (m[5] ?? "").toLowerCase();
      // "and" is only a range connector after "between" — otherwise
      // "€500 and £1,000" is a currency list, not a range.
      if (connector === "and" && !between) continue;
      const lo = computeAmount(m[2], m[3], m[4]);
      const hi = computeAmount(m[6] ?? m[2], m[7], m[8]);
      if (!lo || !hi) continue;
      rangeSpans.push([m.index, m.index + m[0].length]);
      const idx = out.length;
      out.push({
        id: nextId(),
        raw_text: m[0],
        amount: lo.amount,
        currency: lo.currency,
        word_form: false,
        range_max: hi.amount,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
      if (lo.fromDollar) dollarSourced.push(idx);
    }
    // Numeric.
    NUMERIC.lastIndex = 0;
    while ((m = NUMERIC.exec(ctx.text)) !== null) {
      const start = m.index;
      const end = m.index + m[0].length;
      if (rangeSpans.some(([s, e]) => start < e && end > s)) continue;
      const computed = computeAmount(m[1], m[2], m[3]);
      if (!computed) continue;
      const perUnit = PER_UNIT.exec(ctx.text.slice(end));
      const idx = out.length;
      out.push({
        id: nextId(),
        raw_text: m[0],
        amount: computed.amount,
        currency: computed.currency,
        word_form: false,
        ...(perUnit ? { per_unit: perUnit[1]!.trim().replace(/\s+/g, " ") } : {}),
        position: posInParagraph(ctx, start, end),
      });
      if (computed.fromDollar) dollarSourced.push(idx);
    }
    // Word form.
    WORD_FORM.lastIndex = 0;
    while ((m = WORD_FORM.exec(ctx.text)) !== null) {
      const phrase = m[1]!.toLowerCase();
      const currencyWord = m[2]!.toLowerCase();
      const amount = parseWordPhrase(phrase);
      if (amount === null) continue;
      const currency = currencyWord.startsWith("euro")
        ? "EUR"
        : currencyWord.startsWith("pound")
          ? "GBP"
          : "USD";
      out.push({
        id: nextId(),
        raw_text: m[0],
        amount: amount.toString(),
        currency,
        word_form: true,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
  });

  // Deferred currency override: ambiguous `$`-symbol amounts adopt the
  // controlling currency declared by a document-level clause.
  if (overrideCurrency && overrideCurrency !== "USD") {
    for (const idx of dollarSourced) {
      out[idx]!.currency = overrideCurrency;
    }
  }

  return out;
}

/**
 * Compute a money value from an optional currency token, a numeric
 * string, and an optional scale suffix. Returns null when the number is
 * absent or unparseable; `fromDollar` marks an ambiguous `$`-symbol
 * source (USD by default, but reassignable by a currency-override clause).
 */
function computeAmount(
  symOrCode: string | undefined,
  rawNum: string | undefined,
  scaleRaw: string | undefined,
): { amount: string; currency: string; fromDollar: boolean } | null {
  if (!symOrCode || !rawNum) return null;
  const cleaned = rawNum.replace(/,/g, "");
  // Magnitude guard (spec-v8 §9): drop adversarial / unbounded values.
  if ((cleaned.match(/\d/g)?.length ?? 0) > MAX_AMOUNT_DIGITS) return null;
  const scale = scaleRaw?.toLowerCase();
  let amount: Decimal;
  try {
    amount = new Decimal(cleaned);
  } catch {
    return null;
  }
  if (scale && SCALES[scale]) amount = amount.mul(SCALES[scale]!);
  if (!amount.isFinite()) return null;
  return {
    amount: amount.toString(),
    currency: resolveCurrency(symOrCode),
    fromDollar: symOrCode === "$",
  };
}

function resolveCurrency(symOrCode: string): string {
  const upper = symOrCode.toUpperCase();
  if (CURRENCY_CODES.has(upper)) return upper;
  return CURRENCY_SYMBOLS[symOrCode] ?? "USD";
}

function parseWordPhrase(phrase: string): Decimal | null {
  const tokens = phrase
    .replace(/-/g, " ")
    .split(/\s+/)
    .filter((t) => t && t !== "and");
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
