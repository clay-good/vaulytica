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
  // `under` as the preposition, `controlled by` as the verb, and an intervening
  // "and <verb> <prep>," doublet between the first verb and "the laws of".
  ["This Agreement shall be governed under the laws of the State of Oregon.", /Oregon/],
  ["This Agreement shall be controlled by the laws of the State of Arizona.", /Arizona/],
  [
    "This Agreement shall be governed by, and enforced under, the laws of the State of Nevada.",
    /Nevada/,
  ],
  [
    "This Agreement shall be governed by and interpreted under the laws of Washington.",
    /Washington/,
  ],
];

// Decoys: an adjective before "laws" must not turn a non-choice-of-law phrase
// into a jurisdiction, and a non-jurisdiction "laws of X" must stay unmatched.
const NO_GOV_LAW: string[] = [
  "The parties shall comply with the applicable laws of any jurisdiction in which they operate.",
  "Nothing herein alters the immutable laws of physics governing the equipment.",
  // "controlled by X" is corporate control, not a governing-law verb, unless
  // "the laws of" follows immediately.
  "Acme is controlled by Beta Holdings under the laws of Delaware for tax purposes.",
  // A disclaimed governing law must stay unmatched.
  "This Agreement shall not be governed by the laws of the State of New York.",
  // …including when a comma parenthetical or an adverb sits between the
  // negation and the verb. The lookback was too short to reach the negation
  // past either, so the REJECTED law was reported as the chosen one.
  "This Agreement shall not, under any circumstances, be governed by the laws of the State of New York.",
  "This Agreement shall under no circumstances whatsoever be governed by the laws of the State of New York.",
];

// A negation that belongs to an earlier, unrelated clause of the same sentence
// must NOT suppress the governing law the sentence goes on to choose.
const NEGATION_ELSEWHERE: Array<[clause: string, want: RegExp]> = [
  [
    "Although the Company is not incorporated in Delaware, this Agreement is governed by the laws of Delaware.",
    /Delaware/,
  ],
  [
    "The parties have not agreed to arbitrate any dispute; this Agreement is governed by the laws of New York.",
    /New York/,
  ],
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
  for (const [clause, want] of NEGATION_ELSEWHERE) {
    it(`still registers ${want} despite an unrelated negation: ${clause.slice(0, 40)}`, () => {
      const refs = extractJurisdictions(buildTree(["Body", clause]));
      const gov = refs.find((r) => r.clause_kind === "governing-law");
      expect(gov, `OVER-SUPPRESSED for: ${clause}`).toBeTruthy();
      expect(gov!.raw_text).toMatch(want);
    });
  }

  // A disclaimed law whose clause names the law it selects instead records the
  // SELECTED one — exactly once. The selected law is read out of the rejected
  // clause's tail, so a restated verb ("…but shall instead be governed by the
  // laws of Delaware") was then matched a second time on its own and recorded
  // Delaware twice.
  it("records the selected law once when a disclaimer restates the verb", () => {
    const refs = extractJurisdictions(
      buildTree([
        "Governing Law",
        "This Agreement shall not be governed by the laws of California, but shall instead be governed by the laws of Delaware.",
      ]),
    );
    expect(refs.filter((r) => r.clause_kind === "governing-law").map((r) => r.raw_text)).toEqual([
      "Delaware",
    ]);
  });

  it("still records a separate later clause naming that same law", () => {
    // Skipping the restated clause must key on WHERE the selected law was read
    // from, not on its name: an ancillary document's own governing-law
    // sentence in the same paragraph is a real, separate clause, and keying on
    // the name silently swallowed it.
    const refs = extractJurisdictions(
      buildTree([
        "Governing Law",
        "This Agreement shall not be governed by the laws of California, but shall instead be governed by the laws of Delaware. The Ancillary IP Assignment attached as Exhibit B shall also be governed by the laws of Delaware.",
      ]),
    );
    expect(refs.filter((r) => r.clause_kind === "governing-law").map((r) => r.raw_text)).toEqual([
      "Delaware",
      "Delaware",
    ]);
  });

  it("records the selected law when the disclaimer carries a comma parenthetical", () => {
    const refs = extractJurisdictions(
      buildTree([
        "Governing Law",
        "This Agreement shall not, under any circumstances, be governed by the laws of California, but shall instead be governed by the laws of Delaware.",
      ]),
    );
    expect(refs.filter((r) => r.clause_kind === "governing-law").map((r) => r.raw_text)).toEqual([
      "Delaware",
    ]);
  });
});
