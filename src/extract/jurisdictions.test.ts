import { describe, expect, it } from "vitest";
import { extractJurisdictions } from "./jurisdictions.js";
import { buildTree } from "./_fixtures.js";

describe("extractJurisdictions", () => {
  it("captures governing law and venue with raw text", () => {
    const tree = buildTree([
      "Governing Law",
      "This Agreement shall be governed by and construed in accordance with the laws of the State of Delaware. Exclusive jurisdiction shall be in the federal courts located in New York, New York.",
    ]);
    const refs = extractJurisdictions(tree);
    const gov = refs.find((r) => r.clause_kind === "governing-law");
    const venue = refs.find((r) => r.clause_kind === "venue");
    expect(gov?.raw_text).toMatch(/Delaware/);
    expect(venue?.raw_text).toMatch(/New York/);
  });

  it("normalizes via the DKB lookup when provided", () => {
    const tree = buildTree(["Body", "Governed by the laws of the State of California."]);
    const refs = extractJurisdictions(tree, (raw) =>
      /California/.test(raw) ? "us-ca" : undefined,
    );
    expect(refs[0]!.jurisdiction_id).toBe("us-ca");
  });

  it("captures an exception/fallback jurisdiction on the primary record", () => {
    const tree = buildTree([
      "Governing Law",
      "This Agreement shall be governed by the laws of the State of Delaware, except that any dispute concerning real property shall be governed by the laws of Texas.",
    ]);
    const refs = extractJurisdictions(tree);
    const gov = refs.find((r) => r.clause_kind === "governing-law");
    expect(gov?.raw_text).toMatch(/Delaware/);
    // The primary record carries the fallback precedence link.
    expect(gov?.fallback_jurisdiction).toBe("Texas");
  });

  it("does not report a disclaimed governing law, and captures the one actually chosen", () => {
    const tree = buildTree([
      "Governing Law",
      "This Agreement shall not be governed by the laws of California, but rather by the laws of Delaware.",
    ]);
    const gov = extractJurisdictions(tree).filter((r) => r.clause_kind === "governing-law");
    // California is explicitly rejected — it must not be reported as the law.
    expect(gov.some((r) => /California/.test(r.raw_text))).toBe(false);
    // Delaware is the law the clause actually selects.
    expect(gov.map((r) => r.raw_text)).toEqual(["Delaware"]);
  });
});
