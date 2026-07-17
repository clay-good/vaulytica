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

/** How far after a label to look for the amount (chars). */
const WINDOW = 60;

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
export function extractDealValue(tree: DocumentTree): DealValue | null {
  const text = flattenText(tree);
  const lower = text.toLowerCase();
  let best: (DealValue & { idx: number }) | null = null;
  for (const label of DEAL_VALUE_LABELS) {
    for (let from = 0; ; ) {
      const idx = lower.indexOf(label, from);
      if (idx === -1) break;
      from = idx + label.length;
      const window = text.slice(idx + label.length, idx + label.length + WINDOW);
      const m = AMOUNT.exec(window);
      if (!m || m[1] === undefined) continue;
      const num = Number(m[1].replace(/,/g, ""));
      const scale = m[2] ? (SCALE_WORDS[m[2].toLowerCase()] ?? 1) : 1;
      const value = num * scale;
      if (!Number.isFinite(value) || value <= 0) continue;
      // Earliest label wins; on a tie (same index, e.g. overlapping labels),
      // prefer the longer, more specific label.
      if (
        best === null ||
        idx < best.idx ||
        (idx === best.idx && label.length > best.label.length)
      ) {
        best = { value, label, idx };
      }
    }
  }
  return best ? { value: best.value, label: best.label } : null;
}
