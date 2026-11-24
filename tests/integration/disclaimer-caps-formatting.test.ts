/**
 * TEXT-003 and a disclaimer Word DISPLAYS in capitals.
 *
 * 🚨 The defect, measured before the fix: the same DOCX fired `TEXT-003`
 * identically with and without `w:caps` on the disclaimer paragraph, so a
 * disclaimer shown entirely in capitals was reported as "in plain body type".
 * U.C.C. § 1-201(b)(10) counts capitals as one way to be conspicuous, and the
 * rule was reading the TEXT's own case — which a Word user applying All Caps
 * formatting never changes.
 *
 * `docx-caps.test.ts` covers the reader. This covers the thing that matters to
 * a user: the rule's verdict, through the real DOCX ingest.
 */
import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { strToU8, unzipSync, zipSync } from "fflate";
import { renderDocx } from "./_redline-docx.js";
import { ingestDocxBuffer } from "../../src/ingest/docx.js";
import { rule as TEXT_003 } from "../../src/engine/rules/text/TEXT-003.js";
import { buildContext } from "../../src/engine/_test-fixtures.js";

const DISCLAIMER =
  "The Supplier disclaims the implied warranty of merchantability and fitness for a particular purpose.";

const asArrayBuffer = (b: Buffer | Uint8Array): ArrayBuffer =>
  b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

/**
 * The same document twice: once with the disclaimer caps-formatted, once not.
 * Bold is applied to an UNRELATED run in both, because `TEXT-003` reads only a
 * file that carries run formatting at all — without it the rule is silent for
 * a different reason and the comparison would prove nothing.
 */
async function pair(): Promise<{ caps: ArrayBuffer; plain: ArrayBuffer }> {
  const dir = mkdtempSync(join(tmpdir(), "vaulytica-caps-"));
  const base = join(dir, "base.docx");
  await renderDocx(`SUPPLY AGREEMENT\n\nThe parties agree as follows.\n\n${DISCLAIMER}\n`, base);
  const files = unzipSync(new Uint8Array(readFileSync(base)));
  const xml = new TextDecoder()
    .decode(files["word/document.xml"]!)
    .replace(/(<w:r>)(<w:t[^>]*>The parties agree)/, "$1<w:rPr><w:b/></w:rPr>$2");
  const capsXml = xml.replace(
    /(<w:r>)(<w:t[^>]*>The Supplier disclaims)/,
    "$1<w:rPr><w:caps/></w:rPr>$2",
  );
  // Guard the fixture: if the injection stopped matching, both sides would be
  // identical and every assertion below would pass vacuously.
  expect(capsXml, "could not inject w:caps — the run markup changed").not.toBe(xml);
  const pack = (x: string): ArrayBuffer =>
    asArrayBuffer(zipSync({ ...files, "word/document.xml": strToU8(x) }));
  return { caps: pack(capsXml), plain: pack(xml) };
}

async function fires(bytes: ArrayBuffer): Promise<boolean> {
  const ingest = await ingestDocxBuffer(bytes);
  const ctx = { ...buildContext(["SUPPLY AGREEMENT", "x"]), tree: ingest.tree } as never;
  return TEXT_003.check(ctx) !== null;
}

describe("a warranty disclaimer the file displays in capitals", () => {
  it("draws no finding, while the same disclaimer in plain type does", async () => {
    const { caps, plain } = await pair();
    // Both halves matter. Without the second, a rule broken into permanent
    // silence would pass the first.
    expect(await fires(caps), "a caps-formatted disclaimer must not be called plain type").toBe(
      false,
    );
    expect(await fires(plain), "the same disclaimer with no caps must still be reported").toBe(
      true,
    );
  }, 60_000);

  it("stores the text unchanged, which is why the text's case cannot answer this", async () => {
    // The root of the defect: `w:caps` is a rendering instruction, so the
    // stored text is exactly what the drafter typed.
    const { caps } = await pair();
    const ingest = await ingestDocxBuffer(caps);
    const flat = JSON.stringify(ingest.tree);
    expect(flat).toContain("The Supplier disclaims");
    expect(flat).not.toContain("THE SUPPLIER DISCLAIMS");
  }, 60_000);

  it("marks the paragraph, and only that paragraph", async () => {
    const { caps } = await pair();
    const ingest = await ingestDocxBuffer(caps);
    const marked: string[] = [];
    const walk = (sections: typeof ingest.tree.sections): void => {
      for (const s of sections) {
        for (const p of s.paragraphs) {
          if (p.displayed_caps) marked.push(p.runs.map((r) => r.text).join(""));
        }
        walk(s.children);
      }
    };
    walk(ingest.tree.sections);
    expect(marked).toEqual([DISCLAIMER]);
  }, 60_000);
});
