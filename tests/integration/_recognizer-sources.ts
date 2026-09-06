/**
 * Where the static ratchets look — and the half of the catalog they were all
 * missing.
 *
 * `apostrophe-tolerance`, `shall-will`, `parenthetical-numeral` and
 * `commonwealth-spelling` each sweep the source for a recognizer written one
 * way and not another. Every one of them was reading regex LITERALS only. But
 * a recognizer is as often assembled from STRINGS — FIN-005's payment-term
 * branches, the governing-law patterns in `src/extract/jurisdictions.ts`, and
 * every other `new RegExp([...].join("|"))` in the tree, fifty-two files of
 * them — and a `\\b(?:shall|will)` written inside a template literal was
 * invisible to all four.
 *
 * `commonwealth-spelling` found this the way this repo finds most things: the
 * corpus relation reported a defect (FIN-005, a loan's instalment schedule)
 * that the static half it shipped with could not see. So the scanner moved
 * here, and all four now share it.
 *
 * A string is regex source when it carries a regex escape or a group opener; a
 * rule's name, its `why` and its `fix` carry neither, and a sweep that
 * rewrites one of those corrupts a user-visible recommendation.
 */
import { readFileSync, readdirSync } from "node:fs";
import ts from "typescript";

export interface RecognizerSource {
  /** The file the pattern was written in. */
  readonly file: string;
  /** 1-indexed line, so a failure message is clickable. */
  readonly line: number;
  /** The literal's source text, delimiters and escapes intact. */
  readonly text: string;
}

/**
 * Every non-test `.ts` under `dir`, depth-first, in a stable order.
 *
 * Deliberately not `git ls-files` with quoted globs: cmd.exe does not strip
 * single quotes, so git receives them literally and returns nothing — a guard
 * built on that passed vacuously on Windows while failing its own "more than
 * 50 files" floor, which is why every caller keeps that floor. The walk is
 * also strictly more complete: `git ls-files` with a `**` pathspec does not
 * match a file sitting directly in that directory, so the original sweep never
 * looked at `rules/_helpers.ts` or `rules/index.ts` at all.
 */
export function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
    a.name.localeCompare(b.name, "en"),
  )) {
    // POSIX separators on every platform. `join` yields backslashes on
    // Windows, and every caller's DECLARED-exception keys are written with
    // forward slashes — so on Windows the key never matched, the exception was
    // never applied, and `parenthetical-numeral` failed on the cross-OS matrix
    // alone for a whole session while passing everywhere its author could see.
    const path = `${dir}/${entry.name}`.replace(/\\/g, "/");
    if (entry.isDirectory()) sourceFiles(path, out);
    else if (entry.name.endsWith(".ts") && !entry.name.includes(".test.")) out.push(path);
  }
  return out;
}

const LOOKS_LIKE_REGEX = /\\\\[bsdwSDW]|\(\?:|\(\?=|\(\?!/;

/**
 * Every regex literal in the file, plus every string and template chunk that
 * is regex source. Read through the TypeScript scanner rather than a regex
 * over the text, because a naive scan mistakes the slashes in an ordinary
 * string ("(e.g., '#ad' / 'paid partnership')") for regex delimiters.
 */
export function recognizerSources(file: string): RecognizerSource[] {
  const sf = ts.createSourceFile(file, readFileSync(file, "utf8"), ts.ScriptTarget.ESNext, true);
  const out: RecognizerSource[] = [];
  const push = (node: ts.Node, text: string): void => {
    out.push({
      file,
      line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
      text,
    });
  };
  const walk = (node: ts.Node): void => {
    // A template with interpolations is ONE recognizer, not one per chunk.
    //
    // Walking the chunks separately splits a pattern down the middle of what
    // it means: FIN-005's payment window interpolates its spelled-number
    // alternation in the head and puts the digits in the tail, so the tail read
    // alone looks blind to a spelling the whole pattern reads perfectly. Every
    // interpolated repair this repo makes creates another one of those, and
    // each cost a hand-written declared exception saying "it is fine, look at
    // the other half". Taking the expression whole — `${NAME}` included, which
    // is what a reader sees — makes the interpolated name itself the evidence.
    if (ts.isTemplateExpression(node)) {
      const text = node.getText(sf);
      if (LOOKS_LIKE_REGEX.test(text)) push(node, text);
      // Do not descend: the chunks are parts of the recognizer above, and the
      // interpolated expressions are not recognizers at all.
      return;
    }
    const isStringy = ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node);
    if (node.kind === ts.SyntaxKind.RegularExpressionLiteral || isStringy) {
      const text = node.getText(sf);
      if (node.kind === ts.SyntaxKind.RegularExpressionLiteral || LOOKS_LIKE_REGEX.test(text)) {
        push(node, text);
      }
    }
    node.forEachChild(walk);
  };
  walk(sf);
  return out;
}

/**
 * A regex escape is not a word.
 *
 * `\bshall` has the letter "b" immediately in front of "shall", so searching
 * regex SOURCE with `/\bshall\b/` finds nothing — the boundary falls between
 * the "b" of the escape and the "s", where there is none. That is the `\b§`
 * defect of session 28, and it has now shipped inside two guards written to
 * catch it. Mask the escapes out first and the lookarounds mean what they say.
 *
 * 🚨 The masking must replace the escape with a NON-word character. This
 * function used to replace `\b` with the letter `b` — dropping the backslash
 * and keeping the letter, which is precisely the thing it exists to remove.
 * It made the problem WORSE than doing nothing: before masking, the character
 * in front of "shall" was `\`, and a `(?<![a-zA-Z])` lookbehind passed;
 * afterwards it was `b`, and the lookbehind failed. So every `\b`-anchored
 * recognizer — 4,804 of the catalog's 5,677 — was invisible to all four
 * ratchets that share this helper, including `IPDATA-003`'s `\blicense\b`,
 * which sat green under a guard written to catch exactly that. A space is the
 * mask: it is not a word character in any direction.
 */
export function maskEscapes(source: string): string {
  return source.replace(/\\[a-zA-Z]/g, " ");
}

/**
 * A declared exception to a static ratchet, keyed by what it EXEMPTS rather
 * than by where that sits.
 *
 * Every ratchet in this directory used to key its exceptions by `path:line`,
 * and a line number is a property of the file, not of the recognizer. Adding
 * one import above a rule moves it, and the guard then fails on an exemption
 * that is still perfectly correct — twice in one session, on edits that had
 * nothing to do with either guard. The failure is loud, which is the good
 * case; the bad case is the one `parenthetical-numeral` already documents,
 * where a key that stopped matching silently stopped exempting.
 *
 * A distinctive substring of the recognizer's own source is stable under every
 * edit that does not change the recognizer. It is also readable: the key says
 * WHICH pattern is exempt, where a line number said only where to look.
 */
export interface DeclaredException {
  /** Repo-relative, POSIX separators — the form `sourceFiles` returns. */
  readonly file: string;
  /** A distinctive substring of the recognizer's source text. */
  readonly pattern: string;
  /** Why this one is not the defect the ratchet hunts. */
  readonly why: string;
}

export interface DeclaredExceptions {
  /** Is this recognizer exempt? Records the entry as used. */
  exempts(file: string, text: string): boolean;
  /** Entries that matched nothing — a stale exemption is a wrong one. */
  unused(): string[];
}

/** Normalize either an absolute or a repo-relative path to the latter. */
const repoRelative = (file: string): string =>
  file.replace(/\\/g, "/").replace(`${process.cwd().replace(/\\/g, "/")}/`, "");

export function declaredExceptions(entries: readonly DeclaredException[]): DeclaredExceptions {
  const used = new Set<DeclaredException>();
  return {
    exempts(file, text) {
      const hit = entries.find((e) => repoRelative(file) === e.file && text.includes(e.pattern));
      if (hit) used.add(hit);
      return hit !== undefined;
    },
    unused() {
      return entries.filter((e) => !used.has(e)).map((e) => `${e.file}  ${e.pattern}`);
    },
  };
}
