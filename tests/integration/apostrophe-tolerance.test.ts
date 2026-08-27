/**
 * Every regex that reads DOCUMENT text must accept the curly apostrophe.
 *
 * Word inserts U+2019 for an apostrophe by default, and the ingest layer does
 * not fold it: `normalize()` collapses whitespace and strips zero-width
 * characters, deliberately leaving the document's own punctuation alone so a
 * finding's excerpt is the drafter's text. So `landlord'?s?\s+consent` — a
 * perfectly ordinary recognizer — cannot match "Landlord’s consent is
 * required", which is what a DOCX actually contains.
 *
 * The failure is silent in exactly the way this repo keeps rediscovering: the
 * fixtures are hand-typed with straight quotes, so no test could see it, while
 * every real document from Word carries the other character. Eighty-two
 * recognizers across forty-one files were blind to it.
 *
 * `['’]` costs nothing — an apostrophe means the same thing either way — and
 * this guard keeps the next one from shipping. It reads regex literals through
 * the TypeScript scanner rather than a regex over the source, because a naive
 * scan mistakes the slashes in an ordinary string ("(e.g., '#ad' / 'paid
 * partnership')") for regex delimiters, and rewriting one of those corrupts a
 * user-visible recommendation.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import ts from "typescript";

/**
 * Source trees whose regexes read the DOCUMENT, as against the tool's own
 * output. The distinction matters: `src/report/html.ts` and
 * `negotiation-sheet.ts` each carry a bare `/'/g` that ESCAPES an apostrophe
 * on the way OUT, and widening those would be wrong — they are not listed.
 * `critical-dates.ts` is listed by name because it does read the document, to
 * find the defined dates a deadline hangs off.
 */
const DOCUMENT_READING_ROOTS = ["src/engine/rules", "src/extract", "src/engine/consistency"];
const DOCUMENT_READING_FILES = ["src/report/critical-dates.ts"];

/**
 * Walk for `.ts` sources. Deliberately not `git ls-files` with quoted globs:
 * cmd.exe does not strip single quotes, so git receives them literally and
 * returns nothing — the guard then passed vacuously on Windows while failing
 * its own "more than 50 files" floor, which is why that floor is here.
 *
 * The walk is also strictly more complete: `git ls-files` with a `**` pathspec
 * does not match a file sitting directly in that directory, so the original
 * sweep never looked at `rules/_helpers.ts` or `rules/index.ts` at all.
 */
function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
    a.name.localeCompare(b.name, "en"),
  )) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) sourceFiles(path, out);
    else if (entry.name.endsWith(".ts") && !entry.name.includes(".test.")) out.push(path);
  }
  return out;
}

describe("apostrophe tolerance", () => {
  it("no document-reading regex admits only the straight apostrophe", () => {
    const files = [
      ...DOCUMENT_READING_ROOTS.flatMap((root) => sourceFiles(root)),
      ...DOCUMENT_READING_FILES,
    ];
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    const blind: string[] = [];
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      const sf = ts.createSourceFile(file, text, ts.ScriptTarget.ESNext, true);
      const walk = (node: ts.Node): void => {
        if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) {
          const literal = node.getText(sf);
          if (literal.includes("'") && !literal.includes("’")) {
            const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
            blind.push(`${file}:${line}  ${literal.slice(0, 80)}`);
          }
        }
        node.forEachChild(walk);
      };
      walk(sf);
    }
    expect(
      blind,
      `these recognizers cannot match a Word document's apostrophe — write ['’]:\n  ${blind.join("\n  ")}`,
    ).toEqual([]);
  });
});
