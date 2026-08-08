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

  it("captures a power of attorney's Principal and Agent/Attorney-in-Fact", () => {
    // A POA names two individuals with no entity suffix; PARTY_DECL misses them
    // and STRUCT-001 reported "no parties" on a plainly captioned instrument.
    const roles = (t: string) =>
      extractParties(buildTree(["Power of Attorney", t]))
        .map((p) => `${p.name}:${p.role ?? ""}`)
        .sort();
    expect(
      roles(
        'This Power of Attorney is granted by Margaret Okafor (the "Principal") to David Lin (the "Agent").',
      ),
    ).toEqual(["David Lin:Agent", "Margaret Okafor:Principal"]);
    expect(
      roles(
        'Executed by Ruth Cole (the "Principal") appointing James Ford (the "Attorney-in-Fact").',
      ),
    ).toEqual(["James Ford:Attorney-in-Fact", "Ruth Cole:Principal"]);
  });

  it('does not read a credit agreement\'s "Administrative Agent" as a POA Agent', () => {
    // "Agent" is quote-anchored on both sides, so a space-prefixed
    // "Administrative Agent" is not captured as a one-sided party role.
    const roles = extractParties(
      buildTree([
        "Credit Agreement",
        'Acme Bank, N.A. (the "Administrative Agent"), and the Lenders party hereto.',
      ]),
    ).map((p) => p.role);
    expect(roles).not.toContain("Agent");
  });

  it("captures an insurance policy's 'Named Insured:' / 'Insurer:' labeled parties", () => {
    const tree = buildTree([
      "Policy Summary",
      "Named Insured: Harborview Manufacturing, Inc.",
      "Insurer: Sentinel Casualty Insurance Company",
    ]);
    const roles = extractParties(tree).map((p) => p.role);
    // The labeled-party name truncates at the comma (existing behavior), so
    // assert on the roles, which are the point: two parties are now identified.
    expect(roles).toContain("Named Insured");
    expect(roles).toContain("Insurer");
  });

  it('captures a trust settlor from a multi-role paren \'(the "Grantor" and "Trustee")\'', () => {
    const tree = buildTree([
      "Revocable Living Trust",
      'This Declaration of Trust is made by Margaret Okafor (the "Grantor" and initial "Trustee").',
    ]);
    const roles = extractParties(tree).map((p) => `${p.name}:${p.role ?? ""}`);
    expect(roles).toContain("Margaret Okafor:Grantor");
  });

  it("reads a three-party 'among' preamble (untyped individuals)", () => {
    // Only "between" was handled, so an all-individual multi-party preamble
    // reported no parties at all.
    const tree = buildTree([
      "Agreement",
      "This Agreement is made by and among Alice Walker, Bob Marley, and Carol King.",
    ]);
    const names = extractParties(tree).map((p) => p.name);
    expect(names).toEqual(expect.arrayContaining(["Alice Walker", "Bob Marley", "Carol King"]));
    expect(names).toHaveLength(3);
  });

  it("reads a typed 'among' list without manufacturing descriptor parties", () => {
    const tree = buildTree([
      "Agreement",
      "This Agreement is entered into by and among Acme Corp, a Delaware corporation, Beta LLC, a New York limited liability company, and Gamma Inc., a Texas corporation.",
    ]);
    const names = extractParties(tree).map((p) => p.name);
    expect(names).toEqual(expect.arrayContaining(["Acme Corp", "Beta LLC", "Gamma Inc"]));
    // No "a Delaware corporation" / "a New York limited liability company" junk.
    expect(names.some((n) => /^a\s/i.test(n))).toBe(false);
  });

  it("captures 'among' member roles from trailing parentheticals", () => {
    const tree = buildTree([
      "Stock Purchase Agreement",
      'This Agreement is by and among Acme Corp ("Buyer"), Jane Doe ("Seller"), and John Roe ("Founder").',
    ]);
    const roles = extractParties(tree).map((p) => p.role);
    expect(roles).toEqual(expect.arrayContaining(["Buyer", "Seller", "Founder"]));
  });

  it("does not read a prose or negated 'among' as a preamble", () => {
    for (const prose of [
      "Profits shall be allocated among Class A, Class B, and Class C members.",
      "Costs are shared among the parties in proportion to usage.",
      "Nothing in this Agreement creates a partnership among Acme Corp, Beta LLC, and Gamma Inc.",
    ]) {
      expect(extractParties(buildTree(["Doc", prose]))).toEqual([]);
    }
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
