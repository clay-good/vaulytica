import { describe, expect, it } from "vitest";
import { extractJurisdictions } from "./jurisdictions.js";
import { buildTree } from "./_fixtures.js";

// Guard: realistic arbitration-seat phrasings must register a CLEAN seat name
// (not "shall be London"). CHOICE-006 renders the seat verbatim, so a polluted
// or missing capture surfaces as "Seat: shall be London" or "seat not
// specified" on a clause that plainly names one.
const REGISTERS: Array<[clause: string, want: RegExp]> = [
  ["The seat of arbitration shall be London.", /^London$/],
  ["The arbitration shall take place in Singapore.", /^Singapore$/],
  ["The arbitration shall be seated in Geneva, Switzerland.", /^Geneva$/],
  ["The seat of the arbitration shall be New York, New York.", /^New York$/],
  ["The place of arbitration shall be Paris, France.", /^Paris$/],
  ["Arbitration shall be conducted in Stockholm.", /^Stockholm$/],
  ["The legal seat of arbitration shall be Zurich.", /^Zurich$/],
  ["Any arbitration shall be held in Hong Kong.", /^Hong Kong$/],
  ["The seat, or legal place, of arbitration shall be London, England.", /^London$/],
  ["The tribunal shall sit in Dubai.", /^Dubai$/],
];

describe("arbitration-seat phrasing guard", () => {
  for (const [clause, want] of REGISTERS) {
    it(`registers ${want} for: ${clause.slice(0, 45)}`, () => {
      const refs = extractJurisdictions(buildTree(["Arbitration", clause]));
      const seat = refs.find((r) => r.clause_kind === "arbitration-seat");
      expect(seat, `NO SEAT for: ${clause}`).toBeTruthy();
      expect(seat!.raw_text.trim(), `polluted (${seat!.raw_text}) for: ${clause}`).toMatch(want);
    });
  }

  it("registers no seat when arbitration is merely mentioned", () => {
    const refs = extractJurisdictions(
      buildTree(["Body", "Either party may demand arbitration of any unresolved dispute."]),
    );
    expect(refs.find((r) => r.clause_kind === "arbitration-seat")).toBeUndefined();
  });
});
