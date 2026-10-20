/**
 * The executed-copy check over the specimen corpus
 * (add-executed-copy-conformity task 7).
 *
 * Two relations, on every specimen:
 *   - EXECUTING a document is set aside. It gets an EXECUTION VERSION legend,
 *     each signature rule is signed, and each blank is filled, and the
 *     verdict must stay "identical". Each false difference this found was a
 *     shape of signature block the allowance did not know: a rule joined with
 *     the name under it, a notary block, a form's rule with its label below,
 *     a line ingest merged into the signed one.
 *   - CHANGING a figure is not. The first dollar amount in a body paragraph
 *     is altered, and the check must report one more difference than before.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { checkConformity } from "../../src/report/conformity.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/** What signing does to a document: a legend, the rules signed, the blanks filled. */
function execute(text: string): string {
  return (
    "EXECUTION VERSION\n\n" +
    text
      .replace(/^(\s*(?:By|Name|Title|Date|Its)\s*:)\s*_{3,}\s*$/gim, "$1 /s/ Signer")
      .replace(/^_{6,}\s*$/gm, "/s/ Signer")
      .replace(/_{3,}/g, "June 3")
  );
}

describe("the executed-copy check over the corpus", () => {
  it("sets aside what execution does, and catches a changed figure", async () => {
    const names = readdirSync(DIR).filter((f) => f.endsWith(".txt"));
    expect(names.length).toBeGreaterThanOrEqual(363);
    const falseDifferences: string[] = [];
    const missed: string[] = [];
    let mutated = 0;
    for (const name of names) {
      const text = readFileSync(join(DIR, name), "utf8");
      const final = (await ingestPaste(text)).tree;
      const executed = await checkConformity(final, (await ingestPaste(execute(text))).tree);
      if (executed.verdict !== "identical") falseDifferences.push(name);
      const figure = /\$\d[\d,]*/.exec(text);
      if (!figure) continue;
      mutated += 1;
      const changed = text.slice(0, figure.index) + "$9" + text.slice(figure.index + 1);
      const c = await checkConformity(final, (await ingestPaste(execute(changed))).tree);
      if (c.difference_count <= executed.difference_count) missed.push(name);
    }
    expect(falseDifferences).toEqual([]);
    expect(mutated).toBeGreaterThanOrEqual(200);
    expect(missed).toEqual([]);
  }, 300_000);
});
