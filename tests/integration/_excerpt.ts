/**
 * What counts as "the excerpt text" when checking that a quote is really in
 * the document.
 *
 * 🚨 Two files assert that invariant — `excerpt-is-evidence.test.ts` and
 * `format-invariance.test.ts` — and each had its own containment check. The
 * moment `truncate()` began marking a cut quote with an ellipsis (9.710.0),
 * one of them was updated and the other failed, which is the whole argument
 * for a single owner: a rule stated twice is a rule that will be half-updated.
 */

/**
 * The part of an excerpt that must appear in the document, verbatim.
 *
 * A TRAILING ellipsis is a mark, not a quote: rules cut a long clause to a
 * display length, and before 9.710.0 the cut was silent — 196 of the corpus's
 * 1,445 excerpts ended mid-word, the report quoting the client's contract and
 * stopping at "…remove Halcyon bran". The mark comes off before the check.
 *
 * A LEADING ellipsis is the same kind of mark at the other end, and it was
 * added for the same reason (9.890.0). Rules quoted a paragraph's FIRST N
 * characters while their span pointed at the match, so a match beyond
 * character N was reported with a quote that did not contain the flagged
 * language — 94 of 1,116 corpus findings. `hitExcerpt` windows the quote
 * around the match instead, and a window that does not start at the
 * paragraph's beginning says so.
 *
 * 🚨 This EXTENDS the convention, it does not relax it. The property this file
 * exists to protect is that a quote is contiguous document text: an ellipsis
 * at either END marks where contiguous text was cut, while one in the MIDDLE
 * would mean two passages joined into a sentence the document never says. Only
 * the interior case is a splice, and it is still rejected.
 */
export function excerptNeedle(text: string): { needle: string; spliced: boolean } {
  const withoutHead = text.startsWith("…") ? text.slice(1) : text;
  const needle = withoutHead.endsWith("…") ? withoutHead.slice(0, -1) : withoutHead;
  return { needle, spliced: needle.includes("…") };
}
