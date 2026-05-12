import { describe, expect, it } from "vitest";
import { extractDefinitions } from "./definitions.js";
import { buildTree } from "./_fixtures.js";

describe("extractDefinitions", () => {
  it("captures inline quoted definitions", () => {
    const tree = buildTree([
      "Body",
      '"Confidential Information" means any non-public information shared between the parties.',
      "Each party shall protect the Confidential Information.",
    ]);
    const map = extractDefinitions(tree);
    const entry = map.entries.find((e) => e.term === "Confidential Information");
    expect(entry).toBeDefined();
    expect(entry?.used_at.length).toBeGreaterThan(0);
  });

  it("records defined-but-never-used terms", () => {
    const tree = buildTree([
      "Definitions",
      '"Unused Term" means something that is never referenced again.',
    ]);
    const map = extractDefinitions(tree);
    expect(map.unused_terms).toContain("Unused Term");
  });
});
