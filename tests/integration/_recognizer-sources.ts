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
import { join } from "node:path";
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
    const path = join(dir, entry.name);
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
  const walk = (node: ts.Node): void => {
    const isStringy =
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node);
    if (node.kind === ts.SyntaxKind.RegularExpressionLiteral || isStringy) {
      const text = node.getText(sf);
      if (node.kind === ts.SyntaxKind.RegularExpressionLiteral || LOOKS_LIKE_REGEX.test(text)) {
        out.push({
          file,
          line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
          text,
        });
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
 */
export function maskEscapes(source: string): string {
  return source.replace(/\\([a-zA-Z])/g, (_m, c: string) => `${c}`);
}
