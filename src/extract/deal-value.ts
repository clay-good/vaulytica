/**
 * Deal-value extraction (add-negotiation-ladder-playbooks).
 *
 * Finds the document's **explicitly labeled** total contract value, for use
 * when a negotiation playbook's `size_bands` need a deal value and the user did
 * not pass `--deal-value`. This is deliberately NOT a "largest amount" guess —
 * that would fabricate a deal size the document never stated. It fires only
 * when a bounded total-value label ("total contract value", "not to exceed", …)
 * is immediately followed by a currency amount, and returns `null` otherwise,
 * so an unlabeled document honestly falls back to the base ladder.
 *
 * Pure and deterministic: same tree → same result. No wall clock, no network.
 * The value is advisory (it selects an advisory-posture band, never a finding),
 * and the report always names the label it came from so the reader can see
 * exactly what was matched and override it with `--deal-value`.
 */

import type { DocumentTree } from "../ingest/types.js";
import { flattenText } from "../ingest/types.js";

/**
 * Bounded set of phrases that explicitly label a document's total value. Kept
 * small and specific so a stray "$1,000 fee" is never read as the deal size.
 */
export const DEAL_VALUE_LABELS: readonly string[] = [
  "total contract value",
  "total consideration",
  "aggregate consideration",
  "aggregate purchase price",
  "total purchase price",
  "aggregate fees",
  "total fees",
  "not to exceed",
];

const SCALE_WORDS: Record<string, number> = {
  thousand: 1e3,
  k: 1e3,
  million: 1e6,
  m: 1e6,
  billion: 1e9,
  b: 1e9,
};

// A US-dollar amount with optional thousands separators, decimal, and a scale
// word/suffix. Non-global: we exec it against a short window after a label.
const AMOUNT =
  /\$\s?([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]+)?|[0-9]+(?:\.[0-9]+)?)\s*(thousand|million|billion|k|m|b)?\b/i;

/** How far after a label to look for the amount (chars) — capped further by the sentence boundary. */
const WINDOW = 60;
/**
 * The text between the label and the amount must be a *connector* — whitespace,
 * a colon/dash/comma, and at most a short linking verb ("is", "of", "shall
 * be", "equals", …). Anything else (", less the …", "excludes …", "under this
 * Agreement is …") means the nearby amount is not the labeled total, so we bail
 * to the honest default rather than misattribute it. Honesty-first: a legitimate
 * total behind an unusual clause is a false negative (base default), never a
 * false positive that fabricates a deal size.
 */
const CONNECTOR =
  /^[\s]*[:=,–—-]?[\s]*(?:is|of|shall be|will be|equals?|amounts? to|totall?ing)?[\s]*$/i;

export type DealValue = {
  /** The resolved numeric deal value (USD). */
  value: number;
  /** The label phrase it was matched from, e.g. "total contract value". */
  label: string;
};

/**
 * The document's labeled total value, or `null` when none is stated. When
 * several labels match, the earliest in document order wins (ties broken by the
 * longer, more-specific label), so the result is a deterministic total order.
 */
/** Parse a `$` amount + optional scale into a positive number, or null. */
function amountValue(digits: string | undefined, scaleTok: string | undefined): number | null {
  if (digits === undefined) return null;
  const num = Number(digits.replace(/,/g, ""));
  const scale = scaleTok ? (SCALE_WORDS[scaleTok.toLowerCase()] ?? 1) : 1;
  const value = num * scale;
  return Number.isFinite(value) && value > 0 ? value : null;
}

/**
 * The parenthetical / amount-first form common in purchase agreements —
 * `$5,000,000 (the "Total Contract Value")`. The label must stand ALONE inside
 * the parentheses (optionally `the` and quotes), so `$500 (a late fee)` and
 * `$500 (not the total contract value)` do not match.
 */
const PAREN_FORM = new RegExp(
  `\\$\\s?([0-9]{1,3}(?:,[0-9]{3})*(?:\\.[0-9]+)?|[0-9]+(?:\\.[0-9]+)?)\\s*(thousand|million|billion|k|m|b)?\\s*\\(\\s*(?:the\\s+)?["']?(${DEAL_VALUE_LABELS.join("|")})["']?\\s*\\)`,
  "gi",
);

export function extractDealValue(tree: DocumentTree): DealValue | null {
  const text = flattenText(tree);
  const lower = text.toLowerCase();
  const candidates: (DealValue & { idx: number })[] = [];
  const consider = (value: number, label: string, idx: number): void => {
    candidates.push({ value, label, idx });
  };

  // Form 1 — label first: "total contract value is $5,000,000".
  for (const label of DEAL_VALUE_LABELS) {
    for (let from = 0; ; ) {
      const idx = lower.indexOf(label, from);
      if (idx === -1) break;
      from = idx + label.length;
      let window = text.slice(idx + label.length, idx + label.length + WINDOW);
      // Stay within the labeled clause: a sentence terminator (a period NOT part
      // of a decimal, a semicolon, or a newline) ends it. An amount in a LATER
      // sentence — a stray fee, an unrelated figure, a real total stated
      // elsewhere — must never be read as this label's total.
      const boundary = /[;\n]|\.(?!\d)/.exec(window);
      if (boundary) window = window.slice(0, boundary.index);
      const m = AMOUNT.exec(window);
      if (!m || m[1] === undefined) continue;
      // The amount must be joined to the label by only a connector — otherwise
      // it is some other figure that merely shares the sentence.
      if (!CONNECTOR.test(window.slice(0, m.index))) continue;
      const value = amountValue(m[1], m[2]);
      if (value !== null) consider(value, label, idx);
    }
  }

  // Form 2 — amount first, parenthetically labeled.
  PAREN_FORM.lastIndex = 0;
  for (let pm = PAREN_FORM.exec(text); pm !== null; pm = PAREN_FORM.exec(text)) {
    const value = amountValue(pm[1], pm[2]);
    if (value !== null && pm[3]) consider(value, pm[3].toLowerCase(), pm.index);
  }

  if (candidates.length === 0) return null;
  // Earliest match in the document wins; on a tie, the longer (more specific)
  // label. Deterministic total order across both detection forms.
  candidates.sort((a, b) => a.idx - b.idx || b.label.length - a.label.length);
  const best = candidates[0]!;
  return { value: best.value, label: best.label };
}
