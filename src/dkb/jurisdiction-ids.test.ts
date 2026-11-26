/**
 * `wire-jurisdiction-id-resolution` task 2 — the shared resolver.
 *
 * The drift guard is the point of this file. `US_STATE_PATTERN` in
 * `extract/jurisdictions.ts` is a second hand-maintained list of US states,
 * written for a different purpose (deciding whether a venue is domestic) and
 * warning in its own docstring that a partial list "silently reclassifies the
 * states it omits as foreign". Comparing the two is a vocabulary check written
 * INDEPENDENTLY of the map it guards — the circularity trap from s44, where a
 * reach guard that reuses the pattern it guards can only ever agree with it.
 */
import { describe, expect, it } from "vitest";
import { resolveJurisdictionId, resolvableJurisdictionNames } from "./jurisdiction-ids.js";
import { US_STATE_PATTERN } from "../extract/jurisdictions.js";

describe("resolveJurisdictionId", () => {
  it("resolves a bare state name", () => {
    expect(resolveJurisdictionId("Delaware")).toBe("us-de");
    expect(resolveJurisdictionId("New York")).toBe("us-ny");
  });

  it("strips the drafting affixes a clause actually carries", () => {
    expect(resolveJurisdictionId("State of California")).toBe("us-ca");
    expect(resolveJurisdictionId("the State of California")).toBe("us-ca");
    expect(resolveJurisdictionId("Commonwealth of Massachusetts")).toBe("us-ma");
    expect(resolveJurisdictionId("Delaware law")).toBe("us-de");
    expect(resolveJurisdictionId("Texas laws")).toBe("us-tx");
  });

  it("covers DC, which is not a state but is a governing law", () => {
    expect(resolveJurisdictionId("District of Columbia")).toBe("us-dc");
  });

  it("returns undefined rather than guessing", () => {
    // Real extracted values from the specimen corpus. Each resolves to no
    // state id, and that is the honest answer, not a miss to be patched.
    expect(resolveJurisdictionId("England and Wales")).toBeUndefined();
    expect(resolveJurisdictionId("Ireland")).toBeUndefined();
    expect(resolveJurisdictionId("United States")).toBeUndefined();
    expect(resolveJurisdictionId("jurisdiction where the Equipment is located")).toBeUndefined();
  });

  it("does not invent a state from a courthouse city", () => {
    // 🚨 A venue capture names a COURTHOUSE: "Wilmington, Delaware". Narrowing
    // to the trailing word would resolve this to us-de — which happens to be
    // right here and wrong for "Kansas City, Missouri" (us-ks, not us-mo) and
    // for "New York, New York" sitting in a Delaware-law contract. The whole
    // cleaned string must match, so a city-qualified venue resolves to nothing
    // and the consumer falls back to raw text.
    expect(resolveJurisdictionId("Wilmington, Delaware")).toBeUndefined();
    expect(resolveJurisdictionId("Kansas City, Missouri")).toBeUndefined();
  });

  it("knows exactly the states the extractor's own list knows", () => {
    const fromExtractor = US_STATE_PATTERN.split("|")
      .map((s) => s.replace(/\\s\+/g, " ").toLowerCase())
      .sort();
    expect([...resolvableJurisdictionNames()].sort()).toEqual(fromExtractor);
  });

  it("maps every name it knows to a well-formed, unique id", () => {
    const ids = resolvableJurisdictionNames().map((n) => resolveJurisdictionId(n)!);
    for (const id of ids) expect(id).toMatch(/^us-[a-z]{2}$/);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
