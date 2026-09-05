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
/** A compound written UNBROKEN — no whitespace around its hyphen. */
const COMPOUND = /[a-z]+-[a-z]+/g;

/**
 * Every whole word of `text`, lowercased.
 *
 * Split on non-letters, so "non-disclosure" contributes "non" and
 * "disclosure" and never "nondisclosure" — the joined form can only be
 * evidence when the document really writes it as one word somewhere.
 */
export function documentVocabulary(text: string): ReadonlySet<string> {
  const out = new Set<string>();
  // Neither half of a wrapped pair is a word this document uses: drop both.
  // "responsibili-" and the "ty" under it are the wrapper's fragments, and a
  // vocabulary that vouches for them makes every test below vacuous. The
  // pattern needs WHITESPACE after the hyphen, which is what a line break
  // leaves and what an ordinary compound ("third-party") never has.
  const lower = text
    .replace(/[A-Za-z]+-\s+[A-Za-z]+/g, " ")
    .replace(/[A-Za-z]+-(?=\s|$)/g, " ")
    .toLowerCase();
  WORD.lastIndex = 0;
  for (let m = WORD.exec(lower); m !== null; m = WORD.exec(lower)) out.add(m[0]);
  // The compounds the document writes UNBROKEN, kept whole and alongside their
  // halves: "non-renewal" is the document saying, in its own words, that this
  // hyphen is the drafter's.
  COMPOUND.lastIndex = 0;
  for (let m = COMPOUND.exec(lower); m !== null; m = COMPOUND.exec(lower)) out.add(m[0]);
  return out;
}

/**
 * Whether a hyphen at a line break was the WRAPPER's rather than the drafter's.
 *
 * Two independent pieces of evidence, both drawn from the document itself and
 * neither of them a table of English:
 *
 *  1. **The document writes this compound unbroken somewhere.** Checked
 *     first, and it settles the case outright: "non-renewal" in a
 *     distribution agreement is the document telling you whose hyphen it is.
 *
 *  2. **The halves joined are a word the document uses elsewhere.** A
 *     contract that hyphenates "Confiden-tial" says "Confidential" thirty
 *     other times; one that writes "non-disclosure" never writes
 *     "nondisclosure".
 *
 * What neither test can reach, measured and left alone rather than guessed at:
 * a compound used EXACTLY ONCE, broken at its own hyphen, whose halves the
 * document never uses separately. "non-renewal" in a distribution agreement
 * that says "renewal" nowhere else is, on the evidence available, identical to
 * "responsibili-ty". Two further rules were tried and both cost more than they
 * paid: a TAIL test ("the tail of a syllable break is a suffix, not a word")
 * fixed 20 of the 21 specimens still owed and joined an engagement letter's
 * "electronic-discovery" into "electronicdiscovery", and a HEAD test needs a
 * dictionary to know that "electronic" is a word when the document never uses
 * it alone. The 21 are recorded in `format-invariance.test.ts` instead.
 */
function softBreak(head: string, tail: string, vocabulary: ReadonlySet<string>): boolean {
  const h = head.toLowerCase();
  const t = tail.toLowerCase();
  // The document writes this compound unbroken somewhere: the hyphen is the
  // drafter's, and it says so in its own words.
  if (vocabulary.has(`${h}-${t}`)) return false;
  // The document uses the joined word elsewhere: the hyphen was the wrapper's.
  return vocabulary.has(h + t);
}

/** A line ending in a letter then a hyphen, and the word that hyphen ends. */
const ENDS_HYPHENATED = /(?:^|[\s([{"'])([A-Za-z]+)-$/;
/**
 * The first word of the following line.
 *
 * Its CASE has to agree with the head's, which is what keeps a Title-Case
 * compound ("Third-" / "Party") from being read as a broken word: a wrapper
 * breaking a word leaves both halves in the case the word was written in.
 * Requiring a lowercase tail outright — the first version of this — meant an
 * ALL-CAPS word was never rejoined at all, and a UK contract of employment
 * whose party is "HALBROOK DIAGNOSTICS LIMITED" arrived as "HALBROOK
 * DIAGN-OSTICS", re-routed to `generic-fallback`, and lost six findings.
 */
const STARTS_LOWER_WORD = /^([a-z]+)/;
const STARTS_UPPER_WORD = /^([A-Z]+)(?![a-z])/;

/** Whether `w` is written in all capitals. */
function isUpper(w: string): boolean {
  return w === w.toUpperCase();
}

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
    const tail =
      head && isUpper(head[1]!) ? STARTS_UPPER_WORD.exec(line) : STARTS_LOWER_WORD.exec(line);
    if (head && tail && softBreak(head[1]!, tail[1]!, vocabulary)) {
      out = out.slice(0, -1) + line;
      continue;
    }
    // No evidence: keep the hyphen and the halves adjacent (a real compound is
    // restored), or join with a space when there is no hyphen at all.
    out += (/\w-$/.test(out) ? "" : " ") + line;
  }
  return out.trim();
}
