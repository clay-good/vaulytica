import { describe, expect, it } from "vitest";
import { extractObligations } from "./obligations.js";
import { extractParties } from "./parties.js";
import { buildTree } from "./_fixtures.js";

describe("extractObligations", () => {
  it("captures modal sentences with party-named obligor", () => {
    const tree = buildTree([
      "Agreement",
      'This Agreement is between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
      "Provider shall deliver the Services within thirty (30) days after the Effective Date.",
      "Customer must pay the fees subject to the terms of Section 4.",
    ]);
    const parties = extractParties(tree);
    const oblis = extractObligations(tree, parties);
    expect(oblis.length).toBeGreaterThanOrEqual(2);
    const provider = oblis.find((o) => /Provider/i.test(o.obligor));
    const customer = oblis.find((o) => /Customer/i.test(o.obligor));
    expect(provider?.modal).toBe("shall");
    expect(customer?.modal).toBe("must");
    expect(provider?.trigger ?? "").toMatch(/within\s+thirty/);
    expect(customer?.qualifier ?? "").toMatch(/subject\s+to/);
  });
});
