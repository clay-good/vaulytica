/**
 * `w:caps` — the formatting that makes a disclaimer conspicuous without
 * changing a letter of its text (add-mandated-text-conformance task 5).
 *
 * The task recorded this as "`w:caps` is not read, and no row needs capitals".
 * The second half was wrong. No MANDATED TEXT row needs capitals — but
 * `TEXT-003` does, and it is not a mandated-text row: U.C.C. § 1-201(b)(10)
 * counts capitals as one way for a warranty disclaimer to be conspicuous, and
 * the rule was reading the TEXT's own case. A Word user who applies All Caps
 * formatting, which is the ordinary way to do it, leaves the stored text mixed
 * case, and mammoth drops `w:caps` so the ingest never saw it either.
 *
 * Measured before this module existed: the same document fired `TEXT-003`
 * identically with and without `w:caps` on the disclaimer — so a disclaimer
 * Word displays in capitals was reported as "in plain body type".
 */
import { describe, expect, it } from "vitest";
import { strToU8, unzipSync, zipSync } from "fflate";
import { capsParagraphs } from "./docx-caps.js";

const para = (inner: string): string => `<w:p>${inner}</w:p>`;
const run = (text: string, rPr = ""): string =>
  `<w:r>${rPr ? `<w:rPr>${rPr}</w:rPr>` : ""}<w:t xml:space="preserve">${text}</w:t></w:r>`;

/** A minimal .docx carrying just the given body XML. */
function docx(bodyXml: string): ArrayBuffer {
  const files: Record<string, Uint8Array> = {
    "[Content_Types].xml": strToU8(
      '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>',
    ),
    "word/document.xml": strToU8(
      '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>' +
        bodyXml +
        "</w:body></w:document>",
    ),
  };
  const zipped = zipSync(files);
  // Round-trip to prove the part is readable the way the ingest reads it.
  expect(Object.keys(unzipSync(zipped))).toContain("word/document.xml");
  return zipped.buffer.slice(
    zipped.byteOffset,
    zipped.byteOffset + zipped.byteLength,
  ) as ArrayBuffer;
}

const DISCLAIMER = "The Supplier disclaims the implied warranty of merchantability.";

describe("capsParagraphs", () => {
  it("finds a paragraph set in all caps", () => {
    const set = capsParagraphs(docx(para(run(DISCLAIMER, "<w:caps/>"))));
    expect([...set]).toEqual([DISCLAIMER]);
  });

  it("finds small caps too", () => {
    const set = capsParagraphs(docx(para(run(DISCLAIMER, "<w:smallCaps/>"))));
    expect([...set]).toEqual([DISCLAIMER]);
  });

  it("🚨 matches the LOWERCASE `w:caps`, which is the common spelling", () => {
    // The bug this pins: a `(?:small)?Caps` pattern matches `w:smallCaps` and
    // NOT `w:caps`, so the commoner of the two was silently missed and this
    // module returned an empty set for every ordinary document.
    expect([...capsParagraphs(docx(para(run(DISCLAIMER, "<w:caps/>"))))]).toHaveLength(1);
    expect([...capsParagraphs(docx(para(run(DISCLAIMER, "<w:smallCaps/>"))))]).toHaveLength(1);
  });

  it("honours an explicit off switch", () => {
    // Word writes `w:val="0"` when a style set caps on and the run overrides.
    for (const off of ['<w:caps w:val="0"/>', '<w:caps w:val="false"/>']) {
      expect([...capsParagraphs(docx(para(run(DISCLAIMER, off))))], off).toEqual([]);
    }
  });

  it("takes caps from the paragraph's own run properties", () => {
    const body = `<w:p><w:pPr><w:rPr><w:caps/></w:rPr></w:pPr>${run(DISCLAIMER)}</w:p>`;
    expect([...capsParagraphs(docx(body))]).toEqual([DISCLAIMER]);
  });

  it("does not call a PARTLY capitalized paragraph capitals", () => {
    // A single caps-formatted word in a mixed-case clause is not what
    // § 1-201(b)(10) describes, and treating it as capitals would silence
    // TEXT-003 on a disclaimer that is not conspicuous at all.
    const body = para(run("The Supplier ", "<w:caps/>") + run("disclaims merchantability."));
    expect([...capsParagraphs(docx(body))]).toEqual([]);
  });

  it("says nothing about an unformatted paragraph", () => {
    expect([...capsParagraphs(docx(para(run(DISCLAIMER))))]).toEqual([]);
  });

  it("returns an empty set rather than throwing on bytes that are not a docx", () => {
    expect([...capsParagraphs(new Uint8Array([1, 2, 3]).buffer as ArrayBuffer)]).toEqual([]);
  });
});
