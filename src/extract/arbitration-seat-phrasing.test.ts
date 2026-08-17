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
  // Institution-anchored form ("administered by <provider> in X").
  [
    "Disputes shall be resolved by arbitration administered by JAMS in San Francisco, California.",
    /^San Francisco$/,
  ],
  [
    "Any dispute shall be settled by arbitration administered by the AAA in New York, New York.",
    /^New York$/,
  ],
  ["The dispute shall be resolved before the LCIA in London, England.", /^London$/],
  [
    "Any dispute shall be finally resolved by arbitration under the ICC in Paris, France.",
    /^Paris$/,
  ],
  ["Disputes shall be settled under the ICC Rules in Geneva, Switzerland.", /^Geneva$/],
  // Seats that idiomatically carry the article. The capital-letter guard that
  // rejects a lowercase prose capture must look PAST "the", or these real seat
  // clauses read as no seat at all.
  ["The seat of arbitration shall be the Netherlands.", /^the Netherlands$/],
  ["The arbitration shall be seated in the Hague.", /^the Hague$/],
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

  it("does not read the rules recital after the institution as the seat", () => {
    // The pattern needs `i` for its case-varying keywords, which also weakens
    // the capture's leading `[A-Z]` to "any letter" — so "administered by the
    // ICC in accordance with the ICC Rules…" recorded "accordance with the ICC
    // Rules of Arbitration then in force" as a seat, alongside the real one.
    const refs = extractJurisdictions(
      buildTree([
        "Arbitration",
        "Any dispute shall be resolved by arbitration administered by the ICC in accordance with the ICC Rules of Arbitration then in force, and the parties agree the seat of arbitration shall be Geneva.",
      ]),
    );
    const seats = refs.filter((r) => r.clause_kind === "arbitration-seat");
    expect(seats.map((s) => s.raw_text)).toEqual(["Geneva"]);
  });

  it("registers no seat when arbitration is merely mentioned", () => {
    const refs = extractJurisdictions(
      buildTree(["Body", "Either party may demand arbitration of any unresolved dispute."]),
    );
    expect(refs.find((r) => r.clause_kind === "arbitration-seat")).toBeUndefined();
  });

  it("does not read an ordinary 'conducted/held in <place>' with no arbitral body as a seat", () => {
    // The institution anchor is required — a business or meeting "conducted in
    // New York" / "held in Chicago" names no seat.
    for (const prose of [
      "Business is conducted in New York and Delaware.",
      "The annual meeting shall be held in Chicago, Illinois.",
      "Obligations under the Agreement shall be performed in New York.",
      "The rights of the parties under applicable law are exercised in Delaware.",
    ]) {
      const refs = extractJurisdictions(buildTree(["Body", prose]));
      expect(refs.find((r) => r.clause_kind === "arbitration-seat")).toBeUndefined();
    }
  });
});
