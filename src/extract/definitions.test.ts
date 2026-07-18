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

  it("resolves a definition by reference to an exhibit", () => {
    const tree = buildTree([
      "Definitions",
      '"Master Agreement" means the Master Service Agreement attached as Exhibit A.',
      "The Master Agreement governs the relationship.",
    ]);
    const entry = extractDefinitions(tree).entries.find((e) => e.term === "Master Agreement");
    expect(entry?.reference).toBe("Exhibit A");
  });

  it("captures a scope-gated definition", () => {
    const tree = buildTree([
      "Pricing",
      'For the purposes of this Section 4, "Customer" means the end user only.',
      "The Customer pays the fees under this Section 4.",
    ]);
    const entry = extractDefinitions(tree).entries.find((e) => e.term === "Customer");
    expect(entry?.scope).toMatch(/Section 4/);
  });

  it("detects circular definitions", () => {
    const tree = buildTree([
      "Definitions",
      '"Term" means the period ending on the Termination Date.',
      '"Termination Date" means two years from the start of the Term.',
      "The Term and the Termination Date are referenced throughout.",
    ]);
    const map = extractDefinitions(tree);
    expect(map.circular_terms).toBeDefined();
    const flat = (map.circular_terms ?? []).flat();
    expect(flat).toContain("Term");
    expect(flat).toContain("Termination Date");
  });

  it("captures a definition whose 'Means' is capitalized", () => {
    // Sentence-initial / ALL-CAPS / OCR'd drafting capitalizes "Means"; the
    // quoted term makes it unambiguously a definition regardless of case.
    const tree = buildTree(["Definitions", '"Deliverable" Means any work product provided.']);
    expect(extractDefinitions(tree).entries.map((e) => e.term)).toContain("Deliverable");
    // A bare "means" in prose (no quoted term) is still not a definition.
    const prose = buildTree(["Body", "The parties agree this means nothing formal."]);
    expect(extractDefinitions(prose).entries).toHaveLength(0);
  });

  it("does not attach an unrelated later sentence's exhibit as a definition reference", () => {
    const tree = buildTree([
      "Definitions",
      '"Payment" means the amount due each month. Shipping is set forth in Exhibit B for reference only.',
    ]);
    const payment = extractDefinitions(tree).entries.find((e) => e.term === "Payment");
    expect(payment?.reference).toBeUndefined();
    // A genuine by-reference definition in the term's own clause still resolves.
    const specs = extractDefinitions(
      buildTree(["Definitions", '"Specs" means the specifications set forth in Exhibit A.']),
    ).entries.find((e) => e.term === "Specs");
    expect(specs?.reference).toBe("Exhibit A");
  });
});
