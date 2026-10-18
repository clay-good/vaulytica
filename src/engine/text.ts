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

/**
 * A money reference as a reader should see it: the range's two bounds where
 * there are two, and the per-unit qualifier kept attached.
 *
 * Lives here, with `truncate` and `plural`, because BOTH human report surfaces
 * print it and neither may import the other — `html.ts` pulling `docx.ts` in
 * would drag the whole `docx` library into the emailable report's bundle. It
 * was defined privately in `docx.ts` while the HTML report had no amounts
 * table at all; the moment the HTML gained one, a second copy was the obvious
 * and wrong next step.
 */
export function amountCell(a: { amount: string; range_max?: string; per_unit?: string }): string {
  const value = a.range_max ? `${a.amount} \u2013 ${a.range_max}` : a.amount;
  return a.per_unit ? `${value} per ${a.per_unit}` : value;
}

/**
 * A QUOTE, shortened so it still ends on a word.
 *
 * 🚨 `truncate` above cuts at the character limit, which is right for a label
 * and wrong for evidence. 83 rules build their excerpt through
 * `matchedSentence`, which snaps to word boundaries; **28 quote
 * `truncate(hit.text, 280)` directly**, and on `architect-agreement.txt` that
 * put seven of nine excerpts in front of a reader ending mid-word — "…survives
 * termination of this Agreement, excep…", "…employer's liability of $1,000,000;
 * and professio…". `excerptWindow`'s own docstring already says why that
 * matters: "a finding that quotes half a word reads as a broken tool, whatever
 * it says next."
 *
 * ⚠️ Backs up only as far as a word's length (24 characters, matching
 * `WORD_SNAP_MAX` in `_helpers.ts`), and not at all when there is no space to
 * retreat to. A single long token — a URL, a 300-character defined term — must
 * still be shown, and collapsing it to nothing would be worse than cutting it.
 */
export function truncateQuote(text: string, limit: number): string {
  if (text.length <= limit) return text;
  const hard = truncate(text, limit);
  const body = hard.slice(0, -1);
  const lastSpace = body.lastIndexOf(" ");
  if (lastSpace < 0 || body.length - lastSpace > 24) return hard;
  // Trailing punctuation before an ellipsis reads as a typo ("due,…").
  return `${body.slice(0, lastSpace).replace(/(?<![\s,;:.])[\s,;:.]+$/, "")}…`;
}
