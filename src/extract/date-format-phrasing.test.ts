import { describe, expect, it } from "vitest";
import { extractDates } from "./dates.js";
import { buildTree } from "./_fixtures.js";

// Guard: realistic absolute-date orderings must yield a parseable ISO date. A
// miss makes STRUCT-002 assert "no Effective Date" and leaves every relative
// deadline ("within 30 days after ...") without an anchor to compute against.
const REGISTERS: Array<[text: string, iso: string]> = [
  ["This Agreement is effective January 1st, 2029.", "2029-01-01"],
  ["This Agreement is made on March 1st 2029.", "2029-03-01"],
  ["Dated: 1 March 2029.", "2029-03-01"],
  ["Entered into as of the 1st of March, 2029.", "2029-03-01"],
  ["Effective as of the 30th day of June, 2029.", "2029-06-30"],
  ["This Agreement is effective as of January 1, 2029.", "2029-01-01"],
];

// Decoys: "N <word> <year>" phrases that are not dates must not parse one.
const NO_DATE: string[] = [
  "The company shipped 12 months of updates during 2029.",
  "Each party has 30 days to cure any breach.",
];

describe("absolute-date format guard", () => {
  for (const [text, iso] of REGISTERS) {
    it(`parses ${iso} for: ${text.slice(0, 42)}`, () => {
      const dates = extractDates(buildTree(["Preamble", text]));
      const abs = dates.find((d) => d.type === "absolute" && d.iso);
      expect(abs, `NO ABSOLUTE DATE for: ${text}`).toBeTruthy();
      expect(abs!.iso).toBe(iso);
    });
  }
  for (const text of NO_DATE) {
    it(`parses no absolute date for the decoy: ${text.slice(0, 40)}`, () => {
      const dates = extractDates(buildTree(["Body", text]));
      expect(dates.find((d) => d.type === "absolute" && d.iso)).toBeUndefined();
    });
  }
});
