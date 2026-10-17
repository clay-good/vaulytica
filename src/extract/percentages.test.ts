import { describe, expect, it } from "vitest";
import { ingestPaste } from "../ingest/paste.js";
import { extractPercentages } from "./percentages.js";

async function pcts(body: string) {
  const t = await ingestPaste(`Agreement\n\n${body}`);
  return extractPercentages(t.tree);
}

describe("the percentages a document states", () => {
  it("reads the three spellings a drafted instrument uses", async () => {
    expect((await pcts("A fee of 20% of revenue.")).map((p) => p.percent)).toEqual(["20"]);
    expect((await pcts("A fee of 20 percent of revenue.")).map((p) => p.percent)).toEqual(["20"]);
    expect((await pcts("A fee of 20 per cent of revenue.")).map((p) => p.percent)).toEqual(["20"]);
  });

  it("marks the spelled form, and only the spelled form", async () => {
    const [spelled] = await pcts("A fee of twenty percent of revenue.");
    expect(spelled).toMatchObject({ percent: "20", word_form: true });
    const [numeral] = await pcts("A fee of 20% of revenue.");
    expect(numeral).toMatchObject({ percent: "20", word_form: false });
  });

  it("reads 'twenty percent (20%)' as ONE percentage, not two", async () => {
    // The numeral restates the words; a document that writes both states one
    // figure. Counting it twice would double every well-drafted instrument.
    const got = await pcts("Interest accrues at twenty percent (20%) per annum.");
    expect(got).toHaveLength(1);
    expect(got[0]).toMatchObject({ percent: "20", raw_text: "twenty percent (20%)" });
  });

  it("keeps a fractional rate exact", async () => {
    expect((await pcts("A late charge of 1.5% per month.")).map((p) => p.percent)).toEqual(["1.5"]);
  });

  // ⚠️ See the module docstring: a fraction is measurably unsafe to read as a
  // share. These are the three shapes that made it so.
  it("does not read a fraction as a share", async () => {
    expect(await pcts("SEVEN HUNDRED FIFTY THOUSAND AND 00/100 DOLLARS ($750,000).")).toEqual([]);
    expect(await pcts("The hearing is set for 5/2 at the courthouse.")).toEqual([]);
    expect(await pcts("A two-thirds (2/3) vote of the Members is required.")).toEqual([]);
  });

  it("does not mistake a word that merely starts with 'percent'", async () => {
    // "percentile" is not a percentage, and the word boundary is what says so.
    expect(await pcts("Compensation at the 75 percentile of the market.")).toEqual([]);
  });

  // 🚨 A ReDoS this module shipped with in 9.917.0 and 9.918.0–9.920.0. The
  // pattern was `(?:zero|one|…|and|[-\s])+` — ONE unbounded repetition over an
  // alternation that included WHITESPACE — in front of a required "percent". On
  // a 50,000-character run of the word "one" the `+` swallowed the lot, failed
  // to find "percent", and retried from every position: **14,491 ms for one
  // paragraph**, against 17 ms now.
  //
  // ⚠️ `tests/integration/fuzz-boundary.test.ts` builds its runs from a single
  // CHARACTER (commas, spaces, hyphens, NBSP), so none of them ever spelled a
  // number and none of them could catch this. The adversarial input for a
  // word-list pattern is a run of its own words, and the near-miss — a run that
  // almost completes the match — is the worst case of all.
  it("does not backtrack on a long run of number words", async () => {
    for (const text of [
      "one ".repeat(12_500),
      "hundred and ".repeat(8_000),
      // The near miss: everything the pattern wants except the final word.
      `${"one ".repeat(12_500)}percen`,
    ]) {
      const t = performance.now();
      await pcts(text);
      expect(performance.now() - t).toBeLessThan(2_000);
    }
  }, 30_000);

  it("does not read a section number or a decimal as a percentage", async () => {
    expect(await pcts("As provided in Section 5.2 and Section 12.")).toEqual([]);
  });

  it("does not report the 1% inside 'one-half of one percent'", async () => {
    // 0.5%, which this extractor read as 1% — twice the rate. Silence, not a
    // wrong figure, when only the fraction says what the rate is.
    const late = "Interest on overdue sums accrues at one-half of one percent per month.";
    expect(await pcts(late)).toEqual([]);
    expect(await pcts("A late charge of one-quarter of 1% per day.")).toEqual([]);
  });

  it("still reads the numeral that restates the whole fractional rate", async () => {
    const p = await pcts("Interest accrues at one-half of one percent (0.5%) per month.");
    expect(p.map((x) => x.percent)).toEqual(["0.5"]);
  });
});
