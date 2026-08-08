import { describe, expect, it } from "vitest";
import { extractJurisdictions } from "./jurisdictions.js";
import { buildTree } from "./_fixtures.js";

// Guard: realistic governing-law phrasings must register at the CORRECT
// jurisdiction. A miss makes CHOICE-001 assert "no governing-law clause" on a
// document that has one — the worst false absence this tool can make.
const REGISTERS: Array<[clause: string, want: RegExp]> = [
  ["Any dispute shall be resolved in accordance with the substantive laws of Georgia.", /Georgia/],
  ["This Agreement shall be governed by the internal laws of the State of Delaware.", /Delaware/],
  ["This Agreement shall be governed by the substantive laws of New York.", /New York/],
  ["This Agreement is governed by the internal substantive laws of Texas.", /Texas/],
  ["The internal laws of the State of Delaware shall govern this Agreement.", /Delaware/],
  ["The substantive laws of Nevada shall apply to this Agreement.", /Nevada/],
  // A manner adverb between "governed" and "by" must not drop the clause.
  ["This Agreement shall be governed exclusively by the laws of California.", /California/],
  ["This Agreement shall be governed solely by the laws of the State of Delaware.", /Delaware/],
  ["This Agreement is governed only by the laws of New York.", /New York/],
  ["This Agreement shall be governed entirely by Texas law.", /Texas/],
  // The elliptical "that of" statement form, where "that" == "the law".
  ["The governing law shall be that of the State of Texas.", /Texas/],
  ["The governing law is that of New York.", /New York/],
];

// Decoys: an adjective before "laws" must not turn a non-choice-of-law phrase
// into a jurisdiction, and a non-jurisdiction "laws of X" must stay unmatched.
const NO_GOV_LAW: string[] = [
  "The parties shall comply with the applicable laws of any jurisdiction in which they operate.",
  "Nothing herein alters the immutable laws of physics governing the equipment.",
];

describe("governing-law phrasing guard", () => {
  for (const [clause, want] of REGISTERS) {
    it(`registers ${want} for: ${clause.slice(0, 45)}`, () => {
      const refs = extractJurisdictions(buildTree(["Governing Law", clause]));
      const gov = refs.find((r) => r.clause_kind === "governing-law");
      expect(gov, `NO GOV-LAW for: ${clause}`).toBeTruthy();
      expect(gov!.raw_text, `WRONG (${gov!.raw_text}) for: ${clause}`).toMatch(want);
    });
  }
  for (const clause of NO_GOV_LAW) {
    it(`registers no governing law for the decoy: ${clause.slice(0, 40)}`, () => {
      const refs = extractJurisdictions(buildTree(["Body", clause]));
      expect(refs.find((r) => r.clause_kind === "governing-law")).toBeUndefined();
    });
  }
});
