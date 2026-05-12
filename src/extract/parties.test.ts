import { describe, expect, it } from "vitest";
import { extractParties } from "./parties.js";
import { buildTree } from "./_fixtures.js";

describe("extractParties", () => {
  it("pulls parties from the preamble entity-declaration pattern", () => {
    const tree = buildTree([
      "Agreement",
      'This Agreement is made between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
    ]);
    const parties = extractParties(tree);
    const provider = parties.find((p) => p.role === "Provider");
    const customer = parties.find((p) => p.role === "Customer");
    expect(provider?.name).toMatch(/Acme/);
    expect(provider?.jurisdiction_of_formation).toBe("Delaware");
    expect(customer?.name).toMatch(/Globex/);
    expect(customer?.jurisdiction_of_formation).toBe("New York");
  });

  it("returns an empty list when no preamble pattern matches", () => {
    const tree = buildTree(["Untitled", "Some words. Some more words."]);
    expect(extractParties(tree)).toEqual([]);
  });
});
