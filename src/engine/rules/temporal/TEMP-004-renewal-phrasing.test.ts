import { describe, expect, it } from "vitest";
import { rule as TEMP_004 } from "./TEMP-004.js";
import { buildContext } from "../../_test-fixtures.js";

// TEMP-004 should detect an auto-renewal / evergreen clause however it is phrased.
const RENEWAL: string[] = [
  "This Agreement will automatically renew for successive one-year terms.",
  "The subscription will auto-renew at the end of each billing period.",
  "This Agreement renews for additional one-year periods unless terminated.",
  "Unless either party gives notice, this Agreement renews automatically.",
  "This Agreement is evergreen and continues until terminated by either party.",
  "The term will roll over into successive one-year periods.",
  "Each term will renew for a further period of one year unless notice is given.",
  "The Agreement will be extended automatically for additional terms.",
  "The initial term shall be renewed automatically for successive periods.",
  "This Agreement continues on an evergreen basis unless canceled.",
];

// Decoys: text that mentions renewal-adjacent words but is NOT auto-renewal.
const NOT_RENEWAL: string[] = [
  "Either party may renew this Agreement by mutual written agreement.",
  "The license does not renew and terminates at the end of the term.",
];

describe("TEMP-004 auto-renewal phrasing guard", () => {
  for (const clause of RENEWAL) {
    it(`detects: ${clause.slice(0, 48)}`, () => {
      const ctx = buildContext(["Term", clause]);
      expect(TEMP_004.check(ctx), `MISSED: ${clause}`).not.toBeNull();
    });
  }
  for (const clause of NOT_RENEWAL) {
    it(`does not fire on decoy: ${clause.slice(0, 40)}`, () => {
      const ctx = buildContext(["Term", clause]);
      expect(TEMP_004.check(ctx), `FALSE FIRE: ${clause}`).toBeNull();
    });
  }
});
