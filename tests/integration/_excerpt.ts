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
 * An ellipsis ANYWHERE ELSE is a spliced quote — two passages joined into a
 * sentence the document never says — and callers must reject it, which is why
 * this returns it rather than silently stripping every occurrence.
 */
export function excerptNeedle(text: string): { needle: string; spliced: boolean } {
  const needle = text.endsWith("…") ? text.slice(0, -1) : text;
  return { needle, spliced: needle.includes("…") };
}
