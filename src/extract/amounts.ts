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

const CURRENCY_SYMBOLS: Record<string, string> = {
  "$": "USD",
  "€": "EUR",
  "£": "GBP",
  "¥": "JPY",
  "₹": "INR",
  "₩": "KRW",
  "₽": "RUB",
};

const CURRENCY_CODES = new Set([
  "USD", "EUR", "GBP", "JPY", "CAD", "AUD", "NZD", "CHF", "CNY", "INR",
  "KRW", "BRL", "MXN", "ZAR", "SGD", "HKD", "SEK", "NOK", "DKK", "RUB",
]);

const NUMERIC = /([$€£¥₹₩₽]|\b(?:USD|EUR|GBP|JPY|CAD|AUD|NZD|CHF|CNY|INR|KRW|BRL|MXN|ZAR|SGD|HKD|SEK|NOK|DKK|RUB)\b)?\s*([\d]{1,3}(?:,\d{3})*(?:\.\d+)?|\d+(?:\.\d+)?)\s*(k|kk|m|mm|mn|bn|b)?/gi;

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

const WORD_FORM = new RegExp(
  String.raw`\b((?:(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million|billion|trillion|and|[-\s]+)+))\s+(dollars?|euros?|pounds?\s+sterling|pounds?)\b`,
  "gi",
);

export function extractAmounts(tree: DocumentTree): MoneyReference[] {
  const out: MoneyReference[] = [];
  let counter = 0;
  const nextId = (): string => `money-${++counter}`;

  forEachParagraph(tree, (ctx) => {
    // Numeric.
    NUMERIC.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = NUMERIC.exec(ctx.text)) !== null) {
      const symOrCode = m[1];
      const rawNum = m[2];
      const scale = m[3]?.toLowerCase();
      if (!symOrCode || !rawNum) continue;
      const currency = resolveCurrency(symOrCode);
      const baseStr = rawNum.replace(/,/g, "");
      let amount: Decimal;
      try {
        amount = new Decimal(baseStr);
      } catch {
        continue;
      }
      if (scale && SCALES[scale]) amount = amount.mul(SCALES[scale]!);
      out.push({
        id: nextId(),
        raw_text: m[0],
        amount: amount.toString(),
        currency,
        word_form: false,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
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

  return out;
}

function resolveCurrency(symOrCode: string): string {
  const upper = symOrCode.toUpperCase();
  if (CURRENCY_CODES.has(upper)) return upper;
  return CURRENCY_SYMBOLS[symOrCode] ?? "USD";
}

function parseWordPhrase(phrase: string): Decimal | null {
  const tokens = phrase.replace(/-/g, " ").split(/\s+/).filter((t) => t && t !== "and");
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
