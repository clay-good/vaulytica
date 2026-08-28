import { describe, expect, it } from "vitest";
import { extractJurisdictions } from "./jurisdictions.js";
import { buildTree } from "./_fixtures.js";

// Guard: realistic forum-selection phrasings must register a venue at the
// CORRECT state — a missed venue makes CHOICE-003 assert "no forum clause" on a
// document that has one (the worst false absence this tool can make), and a
// wrong state makes the law/venue-mismatch rules fire spuriously.
const REGISTERS: Array<[clause: string, want: RegExp]> = [
  // A state trial court is named for its JUDICIAL DISTRICT before it names
  // its state. The capture that follows the court requires an uppercase
  // start, and this form puts a lowercase "the" there, so the whole clause
  // went unextracted and CHOICE-003 reported "no forum clause" on a surety
  // bond that names two courts.
  [
    "Any proceeding on this bond shall be brought in the District Court of the Fourth Judicial District of the State of Idaho, in and for Ada County.",
    /Idaho/,
  ],
  [
    "Venue lies in the Circuit Court of the Ninth Judicial Circuit in and for Orange County, Florida.",
    /Florida/,
  ],
  // A state court is named by its TYPE and the county it sits FOR — "the
  // Circuit Court for Dane County", "the Superior Court for the County of Los
  // Angeles". The forum patterns admitted only a bare "court(s)" plus an
  // "of/in/located in/sitting in" connector, so the commonest way an American
  // state court is written registered no venue at all, and CHOICE-003
  // reported "no forum clause" on a premarital agreement that names one.
  [
    "The Parties consent to the jurisdiction of the Circuit Court for Dane County, Wisconsin, in any proceeding concerning this Agreement.",
    /Wisconsin/,
  ],
  [
    "The parties submit to the jurisdiction of the Superior Court for the County of Los Angeles, California.",
    /California/,
  ],
  [
    "Each party waives any objection to venue in the Circuit Court for Cook County, Illinois.",
    /Illinois/,
  ],
  ["Venue shall lie exclusively in the District Court for Harris County, Texas.", /Texas/],
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

describe("a venue capture stops at the place name", () => {
  /**
   * The capture can only stop at punctuation, so a forum clause that runs to
   * the end of its sentence without one takes the sentence's tail with it.
   * "submit to the exclusive jurisdiction of the Court of Chancery of the
   * State of Delaware for any dispute arising under this Agreement"
   * registered a venue of "Delaware for any dispute arising under this
   * Agreement", and CHOICE-004, CHOICE-009, and CHOICE-012 each then reported
   * that Delaware governing law and that venue "name different
   * jurisdictions".
   *
   * Trimming to the last capitalized token is not enough — "this Agreement"
   * ends on one — so the place name ends at the first lowercase word that is
   * not an internal connective ("of", "the", "and").
   */
  const venueOf = (clause: string) =>
    extractJurisdictions(buildTree(["Body", clause]))
      .filter((r) => r.clause_kind === "venue")
      .map((r) => r.raw_text);

  it("drops the sentence tail after the place", () => {
    expect(
      venueOf(
        "The parties submit to the exclusive jurisdiction of the Court of Chancery of the State of Delaware for any dispute arising under this Agreement.",
      ),
    ).toEqual(["Delaware"]);
    expect(
      venueOf(
        "The parties consent to the exclusive jurisdiction of the courts of Delaware for any dispute arising under this Agreement.",
      ),
    ).toEqual(["Delaware"]);
  });

  it("keeps a multi-word place and its internal connectives", () => {
    expect(
      venueOf(
        "The parties consent to the jurisdiction of the courts of New York for all disputes.",
      ),
    ).toEqual(["New York"]);
    expect(
      venueOf(
        "The parties consent to the jurisdiction of the courts of Miami-Dade County, Florida, for all disputes.",
      ),
    ).toEqual(["Florida"]);
  });
});
