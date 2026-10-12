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

  it("does not read a section number or a decimal as a percentage", async () => {
    expect(await pcts("As provided in Section 5.2 and Section 12.")).toEqual([]);
  });
});
