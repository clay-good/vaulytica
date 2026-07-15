import { describe, expect, it } from "vitest";
import { buildTree } from "../extract/_fixtures.js";
import { detectFilingBlocks, detectedBlockSet } from "./detect.js";

describe("detectFilingBlocks", () => {
  it("locates the canonical filing blocks by heading/text", () => {
    const tree = buildTree(
      ["IN THE UNITED STATES COURT OF APPEALS", "No. 24-1. Acme v. Globex."],
      ["TABLE OF CONTENTS", "I. Argument ... 1"],
      ["TABLE OF AUTHORITIES", "Cases ... 2"],
      ["ARGUMENT", "The court erred."],
      ["CERTIFICATE OF COMPLIANCE", "This brief complies."],
      ["CERTIFICATE OF SERVICE", "I served all counsel."],
      ["", "Respectfully submitted, Counsel for Appellant."],
    );
    const set = detectedBlockSet(tree);
    expect(set.has("caption")).toBe(true);
    expect(set.has("table-of-contents")).toBe(true);
    expect(set.has("table-of-authorities")).toBe(true);
    expect(set.has("certificate-of-compliance")).toBe(true);
    expect(set.has("certificate-of-service")).toBe(true);
    expect(set.has("signature-block")).toBe(true);
  });

  it("returns nothing on a document with none of the blocks", () => {
    const tree = buildTree(["Recipe", "Combine flour and water. Bake at 350."]);
    const found = detectFilingBlocks(tree);
    expect(found.length).toBe(0);
  });

  it("records at most one entry per block kind", () => {
    const tree = buildTree(
      ["TABLE OF AUTHORITIES", "Cases"],
      ["More", "table of authorities again"],
    );
    const toa = detectFilingBlocks(tree).filter((b) => b.block === "table-of-authorities");
    expect(toa.length).toBe(1);
  });
});
