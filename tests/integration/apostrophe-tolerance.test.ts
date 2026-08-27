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

import { readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import ts from "typescript";

/** Source files whose regexes read the DOCUMENT, as against the tool's own output. */
const DOCUMENT_READING_GLOBS = "'src/engine/rules/**/*.ts' 'src/extract/*.ts'";

describe("apostrophe tolerance", () => {
  it("no document-reading regex admits only the straight apostrophe", () => {
    const files = execSync(`git ls-files ${DOCUMENT_READING_GLOBS}`)
      .toString()
      .trim()
      .split("\n")
      .filter((f) => f && !f.includes(".test."));
    expect(files.length).toBeGreaterThan(50);

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
