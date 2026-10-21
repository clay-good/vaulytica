/** Flesch reading ease under the statutory counting rules (add-readability-measure, task 2). */
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../ingest/paste.js";
import { measureReadability } from "./readability.js";

const measure = async (text: string) => measureReadability((await ingestPaste(text)).tree);

describe("measureReadability", () => {
  it("computes the formula from words, sentences and syllables", async () => {
    const r = await measure("The cat sat. The dog ran.\n");
    expect([r.words, r.sentences, r.syllables]).toEqual([6, 2, 6]);
    // 206.835 − 1.015 × 3 − 84.6 × 1
    expect(r.score).toBe(119.2);
  });

  it("ends a sentence at a semicolon or colon, not at an abbreviation or a clause number", async () => {
    const r = await measure(
      "1.2 Acme Components, Inc. shall pay the fee; Buyer shall pay the tax: both are due in June.\n",
    );
    expect(r.sentences).toBe(3);
  });

  it("counts a hyphenated word and a contraction as one word", async () => {
    const r = await measure("Buyer's month-to-month lease can't renew.\n");
    expect(r.words).toBe(5);
  });

  it("leaves out captions and signature lines, and names what it did not apply", async () => {
    const r = await measure(
      "ARTICLE 1 DEFINITIONS\n\nThe Policy covers the home.\n\nBy: ____________\nName: Jordan Lee\n",
    );
    expect(r.words).toBe(5);
    expect(r.excluded).toContain("headings and captions");
    expect(r.not_applied.join(" ")).toMatch(/defined words, medical terminology/);
    expect(r.method).toMatch(/§ 627\.4145\(5\)/);
  });

  it("names the longest sentence and where it is", async () => {
    const r = await measure("Short one. This sentence is the longest one in the text by far.\n");
    expect(r.longest_sentence?.words).toBe(11);
    expect(r.longest_sentence?.paragraph_id).toMatch(/\S/);
  });

  it("is zero, not NaN, for a document with no sentences", async () => {
    expect((await measure("TITLE\n")).score).toBe(0);
  });
});
