/**
 * The hyphen a wrapped line ends on.
 *
 * A justified column — a PDF, a mail client, a hard-wrapped paste — breaks a
 * long word across the line and marks the break with a hyphen: "confiden-" on
 * one line, "tial" on the next. It also, unchanged, carries the hyphen a
 * drafter actually wrote: "month-to-" / "month", "non-" / "disclosure". The
 * two are the same character in the same position and mean opposite things.
 *
 * The paste path already joined those lines WITHOUT a space, which restores a
 * real compound and leaves a soft hyphenation as one token — and its own
 * comment said so, naming the residue it left behind: "agree-ment" is one
 * token that the matcher's hyphen folding reads correctly and that no RULE
 * regex in the catalog matches. The PDF path did not even do that much: it
 * joined with a space, so the halves arrived as "confiden- tial".
 *
 * Measured by hard-wrapping all 312 specimens at 72 columns with the hyphen a
 * justified column would insert: findings moved on ~30 of them and one
 * re-routed outright — a UK contract of employment fell to `generic-fallback`,
 * so not one employment rule ran on it.
 *
 * The break is resolved on EVIDENCE FROM THE DOCUMENT ITSELF, never on a guess
 * about English. If the two halves joined without the hyphen form a word the
 * document uses somewhere else, the hyphen was the wrapper's and it goes; if
 * they do not, the hyphen was the drafter's and it stays. A contract that
 * hyphenates "confiden-tial" says "Confidential" thirty other times, and one
 * that writes "non-disclosure" does not write "nondisclosure" anywhere. The
 * default — no evidence either way — is to KEEP the hyphen, which is exactly
 * what the paste path did before this module existed, so nothing a document
 * already produced can change without positive evidence that it was wrong.
 */

const WORD = /[a-z]+/g;

/**
 * Every whole word of `text`, lowercased.
 *
 * Split on non-letters, so "non-disclosure" contributes "non" and
 * "disclosure" and never "nondisclosure" — the joined form can only be
 * evidence when the document really writes it as one word somewhere.
 */
export function documentVocabulary(text: string): ReadonlySet<string> {
  const out = new Set<string>();
  const lower = text.toLowerCase();
  WORD.lastIndex = 0;
  for (let m = WORD.exec(lower); m !== null; m = WORD.exec(lower)) out.add(m[0]);
  return out;
}

/** A line ending in a letter then a hyphen, and the word that hyphen ends. */
const ENDS_HYPHENATED = /(?:^|[\s([{"'])([A-Za-z]+)-$/;
/** The first word of the following line, when it starts with a lowercase letter. */
const STARTS_LOWER_WORD = /^([a-z]+)/;

/**
 * Join the lines of one paragraph, resolving each end-of-line hyphen.
 *
 * Lines that do not end in a hyphen are joined with a single space, as they
 * always were.
 */
export function joinWrappedLines(
  lines: readonly string[],
  vocabulary: ReadonlySet<string>,
): string {
  let out = "";
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!;
    if (i === 0) {
      out = line;
      continue;
    }
    const head = ENDS_HYPHENATED.exec(out);
    const tail = STARTS_LOWER_WORD.exec(line);
    if (head && tail && vocabulary.has((head[1]! + tail[1]!).toLowerCase())) {
      // The document uses the joined word elsewhere: the hyphen was the
      // wrapper's, and it goes along with the line break.
      out = out.slice(0, -1) + line;
      continue;
    }
    // No evidence: keep the hyphen and the halves adjacent (a real compound is
    // restored), or join with a space when there is no hyphen at all.
    out += (/\w-$/.test(out) ? "" : " ") + line;
  }
  return out.trim();
}
