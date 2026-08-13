import { describe, expect, it } from "vitest";
import { extractJurisdictions } from "./jurisdictions.js";
import { buildTree } from "./_fixtures.js";

// Guard: realistic forum-selection phrasings must register a venue at the
// CORRECT state — a missed venue makes CHOICE-003 assert "no forum clause" on a
// document that has one (the worst false absence this tool can make), and a
// wrong state makes the law/venue-mismatch rules fire spuriously.
const REGISTERS: Array<[clause: string, want: RegExp]> = [
  [
    "Any action shall be filed and maintained exclusively in the Superior Court of California, County of Los Angeles.",
    /California/,
  ],
  [
    "Each party hereby waives any objection to venue in the courts of Cook County, Illinois.",
    /Illinois/,
  ],
  [
    "Any claim shall be subject to the exclusive jurisdiction of the courts sitting in Denver, Colorado.",
    /Colorado/,
  ],
  [
    "Venue is proper only in the state and federal courts located in King County, Washington.",
    /Washington/,
  ],
  [
    "The parties agree that any litigation shall take place in the courts located in Miami-Dade County, Florida.",
    /Florida/,
  ],
  [
    "Suit may be brought only in a court of competent jurisdiction located in Nashville, Tennessee.",
    /Tennessee/,
  ],
  [
    "The state courts of Travis County, Texas shall be the exclusive forum for any dispute.",
    /Texas/,
  ],
  // Courts-first with a bare jurisdiction and NO "City, State" comma: the
  // capture must end before the forum verb, not run past it.
  [
    "The state and federal courts located in Delaware shall have exclusive jurisdiction.",
    /Delaware/,
  ],
  // Courts-first with the "of the State/Commonwealth of" preposition.
  [
    "The courts of the State of California shall have exclusive jurisdiction over any dispute.",
    /California/,
  ],
  ["The courts of the Commonwealth of Massachusetts shall have exclusive venue.", /Massachusetts/],
];

// Decoys: sentences that mention courts/jurisdiction but select no forum must
// NOT register a venue (over-match would seed a phantom law/venue mismatch).
const NO_VENUE: string[] = [
  "The company operates in several states, including Texas and Florida.",
  "The board has jurisdiction over internal committee matters and reports to Delaware.",
  "Each party shall comply with all applicable laws of every state in which it operates.",
  // "of <X>" without a State/Commonwealth-of scaffold is not a jurisdiction —
  // the courts-first "of" arm must not sweep these in.
  "Any dispute may be heard by the courts of competent jurisdiction shall have jurisdiction.",
  "Nothing herein grants the courts of Appeals jurisdiction over these matters.",
];

describe("venue phrasing guard", () => {
  for (const [clause, want] of REGISTERS) {
    it(`registers ${want} venue for: ${clause.slice(0, 45)}`, () => {
      const refs = extractJurisdictions(buildTree(["Governing Law", clause]));
      const venue = refs.find((r) => r.clause_kind === "venue");
      expect(venue, `NO VENUE for: ${clause}`).toBeTruthy();
      expect(venue!.raw_text, `WRONG STATE (${venue!.raw_text}) for: ${clause}`).toMatch(want);
    });
  }
  for (const clause of NO_VENUE) {
    it(`registers no venue for the decoy: ${clause.slice(0, 45)}`, () => {
      const refs = extractJurisdictions(buildTree(["Body", clause]));
      expect(refs.find((r) => r.clause_kind === "venue")).toBeUndefined();
    });
  }
});
