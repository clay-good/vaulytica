/**
 * PLEADING PAPER numbers its lines in the left margin.
 *
 * A court filing is typed on paper with 28 numbered lines down the left edge,
 * and a PDF text layer emits each number as the first token of its line. The
 * catalog covers complaints, motions, briefs and judgments, so this is the
 * shape a large part of it arrives in — and prefixing the corpus with line
 * numbers moved a finding on 207 of 311 specimens, the widest divergence any
 * probe in this repository has produced except the f-ligatures.
 *
 * The hard part is telling a margin number from a clause number, because
 * "3 The Borrower shall…" is both. Three things separate them, and all three
 * are required here:
 *
 *   - DENSITY. A margin number is on EVERY line; a clause number is on the
 *     first line of a clause and nowhere else. This is the discriminator that
 *     does the real work.
 *   - NO PUNCTUATION. A clause number carries a period or a parenthesis
 *     ("3.", "(3)"); a margin number is bare.
 *   - A CYCLE. Margin numbers run 1…N and reset, with the same N every time,
 *     because N is the page. A numbered outline never resets.
 *
 * Removing the numbers is the whole repair: what is left is the document.
 */

/** `24 The Borrower shall…` or a bare `24` on an otherwise empty line. */
const NUMBERED_LINE = /^(\d{1,2})(?:[ \t]+(.*))?$/;

/** Shortest page a filing is set on, and the longest — 25, 28 and 32 all occur. */
const MIN_CYCLE = 10;
const MAX_CYCLE = 40;
/** Below this there is no cycle to see, so the shape cannot be established. */
const MIN_NUMBERED_LINES = 20;
/** A margin number is on every line; a few unnumbered ones survive a paste. */
const MIN_DENSITY = 0.85;

export function stripPleadingLineNumbers(text: string): string {
  const lines = text.split("\n");
  const content = lines.filter((l) => l.trim().length > 0);
  if (content.length < MIN_NUMBERED_LINES) return text;

  const numbered = content.map((l) => NUMBERED_LINE.exec(l.trimStart()));
  const hits = numbered.filter((m): m is RegExpExecArray => m !== null);
  if (hits.length < MIN_NUMBERED_LINES) return text;
  if (hits.length / content.length < MIN_DENSITY) return text;

  // The sequence must step by one and reset at one consistent page length.
  const values = hits.map((m) => Number(m[1]));
  let cycle: number | null = null;
  for (let i = 1; i < values.length; i += 1) {
    const prev = values[i - 1]!;
    const cur = values[i]!;
    if (cur === prev + 1) continue;
    if (cur !== 1) return text;
    if (prev < MIN_CYCLE || prev > MAX_CYCLE) return text;
    if (cycle !== null && prev !== cycle) return text;
    cycle = prev;
  }
  // A single page never resets, so a cycle is not required — but the numbers
  // must at least have run far enough to be margin numbers rather than a list.
  if (cycle === null && values[values.length - 1]! < MIN_CYCLE) return text;

  return lines
    .map((line) => {
      const m = NUMBERED_LINE.exec(line.trimStart());
      return m ? (m[2] ?? "") : line;
    })
    .join("\n");
}
