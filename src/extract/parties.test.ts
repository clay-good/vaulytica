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

  it("resolves alias/role chains for a multi-word legal name", () => {
    const tree = buildTree([
      "Agreement",
      'This Agreement is made between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
    ]);
    const provider = extractParties(tree).find((p) => p.role === "Provider");
    expect(provider?.aliases).toContain("Provider");
    expect(provider?.aliases).toContain("Acme");
  });

  it("captures a d/b/a operating name", () => {
    const tree = buildTree([
      "Agreement",
      'This Agreement is made between Acme Corp., a Delaware corporation doing business as Acme Cloud ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
    ]);
    const acme = extractParties(tree).find((p) => /Acme/.test(p.name));
    expect(acme?.dba).toBe("Acme Cloud");
  });

  it("captures both parties from a two-column signature block", () => {
    const tree = buildTree([
      "Agreement",
      'This Agreement is made between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
      "Signatures",
      "By: Jane Roe          By: John Doe",
    ]);
    const names = extractParties(tree).map((p) => p.name);
    expect(names).toContain("Jane Roe");
    expect(names).toContain("John Doe");
  });

  it("captures the parties of a one-sided instrument named '<Name> (the \"<Role>\")'", () => {
    // A guaranty names an individual guarantor and a lender with no entity-type
    // suffix, so PARTY_DECL misses them; the one-sided role-label path catches
    // them and STRUCT-001 no longer reports "no parties".
    const tree = buildTree([
      "Continuing Guaranty",
      'This Continuing Guaranty is made by Harold Vance (the "Guarantor") in favor of Summit Commercial Bank (the "Lender").',
    ]);
    const roles = extractParties(tree).map((p) => `${p.name}:${p.role ?? ""}`);
    expect(roles).toContain("Harold Vance:Guarantor");
    expect(roles).toContain("Summit Commercial Bank:Lender");
  });

  it("does NOT surface a reciprocal role as an extra party in a mutual agreement", () => {
    // "Receiving Party" / "Recipient" is a position BOTH parties occupy; adding
    // it as a party would make OBLI-002 read role-based mutuality as a one-
    // sided obligation. Only the two entity parties are returned.
    const tree = buildTree([
      "Mutual NDA",
      'This Agreement is between Alpha Systems, Inc. ("Alpha") and Beta Logic, LLC ("Beta"). The Receiving Party shall protect the Confidential Information of the Disclosing Party.',
    ]);
    const names = extractParties(tree).map((p) => p.name.toLowerCase());
    expect(names.some((n) => n.includes("receiving party") || n.includes("disclosing party"))).toBe(
      false,
    );
  });
});
