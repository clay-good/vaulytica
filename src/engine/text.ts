/**
 * Text utilities shared by the engine and the report layer.
 *
 * 🚨 **A truncated quotation that does not say it was truncated.** Rules build
 * a finding's excerpt with `text.slice(0, 240)`, and the report quotes that
 * excerpt verbatim as the clause the rule fired on. **196 of the corpus's
 * 1,445 excerpts ended mid-word with nothing to mark the cut** — a report
 * quoting the client's own contract and stopping at "…remove Halcyon bran",
 * "…and profession", "…promptly notifies Ve".
 *
 * The correct behaviour already existed THREE times — `src/report/v3/_dx.ts`
 * and `cross-doc-rules.ts` held byte-identical copies of it, and
 * `exports.ts` a third variant — while the fifty-five rule sites that actually
 * quote the document used none of them.
 */

/**
 * `text` cut to at most `limit` characters, with an ellipsis when it was
 * actually cut. Returns the string unchanged when it already fits, so an
 * excerpt that was never truncated is byte-identical to before.
 *
 * Surrogate-aware: a cut that would land between the two code units of an
 * astral character (an emoji, a CJK extension) steps back one, so the result
 * is never a lone surrogate.
 */
export function truncate(text: string, limit: number): string {
  if (text.length <= limit) return text;
  let end = limit - 1;
  const lastUnit = text.charCodeAt(end - 1);
  if (lastUnit >= 0xd800 && lastUnit <= 0xdbff) end -= 1;
  return text.slice(0, end) + "…";
}

/**
 * `"1 day"` / `"2 days"` — a count and its noun, pluralized.
 *
 * Owned here beside {@link truncate} because three modules had written it:
 * `report/v3/_dx.ts` (which re-exports it, as it already does for
 * `truncate`), `report/bundle.ts`, and the deadlines calendar's composition
 * line. `_dx.ts` pulls in the `docx` library, so a CSV or `.ics` writer cannot
 * import from it without dragging a DOCX dependency into a text path — which
 * is what made a fourth copy tempting.
 */
export function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? "" : "s"}`;
}
