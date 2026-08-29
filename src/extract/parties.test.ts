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

  it("captures a labeled party whose name begins with an initialed abbreviation", () => {
    // "J.P. Morgan…" starts with a period two chars in; the old name char-class
    // excluded '.', so the `{2,80}` minimum failed at the first period and the
    // whole party was dropped (STRUCT-001 "could not identify the parties").
    const tree = buildTree([
      "Parties",
      "Lender: J.P. Morgan Chase Bank, N.A.",
      "Borrower: Acme Manufacturing Company",
    ]);
    const names = extractParties(tree).map((p) => p.name);
    // Truncates at the comma before "N.A." (existing labeled-party behavior),
    // but the initialed name itself is now captured rather than dropped.
    expect(names).toContain("J.P. Morgan Chase Bank");
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

  it("reads an 'among' list of abbreviated entity names without truncating at a period", () => {
    // The list body carries in-word periods ("Alpha Inc.", "Beta Corp.",
    // "Gamma Ltd."); a non-greedy `.+?` stopped at the FIRST period and dropped
    // every party but "Alpha Inc".
    const tree = buildTree([
      "Agreement",
      "This Agreement is entered into by and among Alpha Inc., Beta Corp., and Gamma Ltd.",
    ]);
    const names = extractParties(tree).map((p) => p.name);
    expect(names).toEqual(expect.arrayContaining(["Alpha Inc", "Beta Corp", "Gamma Ltd"]));
    expect(names).toHaveLength(3);
  });

  it("reads an abbreviated-entity 'among' list whose members carry role parentheticals", () => {
    const tree = buildTree([
      "Stock Purchase Agreement",
      'This Agreement is entered into by and among Acme Inc. ("Buyer"), Beta LLC ("Seller"), and Gamma Ltd. ("Escrow Agent").',
    ]);
    const parties = extractParties(tree);
    expect(parties.map((p) => p.name)).toEqual(
      expect.arrayContaining(["Acme Inc", "Beta LLC", "Gamma Ltd"]),
    );
    expect(parties.map((p) => p.role)).toEqual(
      expect.arrayContaining(["Buyer", "Seller", "Escrow Agent"]),
    );
  });

  it("drops a bare entity-suffix fragment split from a comma-separated 'among' member", () => {
    // "Alpha Holdings, L.P." splits on its internal comma; the "L.P." fragment
    // is not a party, but the distinctive name is kept.
    const tree = buildTree([
      "Agreement",
      "This Agreement is made by and among Alpha Holdings, L.P., Beta Capital, LLC, and Gamma Ventures, Inc.",
    ]);
    const names = extractParties(tree).map((p) => p.name);
    expect(names).toEqual(
      expect.arrayContaining(["Alpha Holdings", "Beta Capital", "Gamma Ventures"]),
    );
    expect(names).toHaveLength(3);
  });

  it("does not pull a following sentence into an abbreviated-entity 'among' list", () => {
    // The abbreviation period must not defeat the sentence boundary: the second
    // sentence's prose is not read as additional parties.
    const tree = buildTree([
      "Agreement",
      "This Agreement is by and among Acme Inc., Beta LLC, and Gamma Ltd. This Agreement is governed by New York law and the Delaware General Corporation Law.",
    ]);
    const names = extractParties(tree).map((p) => p.name);
    expect(names).toEqual(["Acme Inc", "Beta LLC", "Gamma Ltd"]);
  });

  it("reads an ALL-CAPS abbreviated-entity 'among' preamble", () => {
    const tree = buildTree([
      "AGREEMENT",
      "THIS AGREEMENT IS ENTERED INTO BY AND AMONG ACME INC., BETA CORP., AND GAMMA LTD.",
    ]);
    const names = extractParties(tree).map((p) => p.name);
    expect(names).toEqual(expect.arrayContaining(["ACME INC", "BETA CORP", "GAMMA LTD"]));
    expect(names).toHaveLength(3);
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
  // The assertions above mostly use `.find(...)` or `.toContain(...)`, which
  // cannot see a PHANTOM party — an extra entry alongside the right ones. Two
  // such phantoms were shipping, both on fixtures this file already used. The
  // tests below assert the EXACT list, which is the only shape that catches
  // them.

  it("registers a comma-suffixed legal name once, not twice", () => {
    // "…and Globex Industries, Inc., a New York corporation" — the between-
    // preamble capture stopped at the comma before the suffix and registered
    // "Globex Industries" under a different key than the full name, so one
    // company became two parties and the phantom carried no role.
    const parties = extractParties(
      buildTree([
        "Preamble",
        'This Agreement is made between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
      ]),
    );
    expect(parties.map((p) => [p.name, p.role])).toEqual([
      ["Acme Corp", "Provider"],
      ["Globex Industries, Inc", "Customer"],
    ]);
  });

  it("reads a two-column signature block as exactly its two signers", () => {
    // The leading-label strip took the whole rest of the line, so the second
    // signer's own "By:" field came along as part of the first signer's name.
    const parties = extractParties(buildTree(["Signatures", "By: Jane Roe          By: John Doe"]));
    expect(parties.map((p) => p.name)).toEqual(["Jane Roe", "John Doe"]);
  });

  it("keeps a signer whose name is longer than the field cap", () => {
    // `SIGNATURE_FIELD` caps a captured name at five words, so this column was
    // skipped by that path entirely; with the leading-strip path swallowing
    // the rest of the line, the signer appeared nowhere as a clean party.
    const parties = extractParties(
      buildTree(["Signatures", "By: Maria De La Cruz Fernandez Ibanez          By: John Doe"]),
    );
    expect(parties.map((p) => p.name)).toEqual(["Maria De La Cruz Fernandez Ibanez", "John Doe"]);
  });
});

describe("an all-caps instrument's parties", () => {
  /**
   * Old-form guaranties, bonds, and powers of attorney are set in capitals
   * from the caption to the signature: `BY MARTIN R. ODEGAARD … (THE
   * "GUARANTOR"), IN FAVOR OF NORTHLAND MERCANTILE BANK, N.A. (THE "LENDER")`.
   * The role-labeled pattern is case-sensitive — its lead-in "the" and its
   * Title-Case role names — so an all-caps document registered no parties and
   * STRUCT-001 reported "could not identify the parties" about a preamble that
   * names both.
   */
  it("reads both roles out of an all-caps preamble", () => {
    const parties = extractParties(
      buildTree([
        "CONTINUING GUARANTY",
        'THIS CONTINUING GUARANTY IS MADE AS OF SEPTEMBER 30, 2026 BY MARTIN R. ODEGAARD (THE "GUARANTOR"), IN FAVOR OF NORTHLAND MERCANTILE BANK, N.A. (THE "LENDER").',
      ]),
    );
    expect(parties.map((p) => p.role).sort()).toEqual(["GUARANTOR", "LENDER"]);
  });

  it("still reads a mixed-case preamble the same way", () => {
    const parties = extractParties(
      buildTree([
        "Continuing Guaranty",
        'This Continuing Guaranty is made as of September 30, 2026 by Martin R. Odegaard (the "Guarantor"), in favor of Northland Mercantile Bank, N.A. (the "Lender").',
      ]),
    );
    expect(parties.map((p) => p.role).sort()).toEqual(["Guarantor", "Lender"]);
  });
});

describe("the preamble window is measured in characters too", () => {
  // A paragraph COUNT is a fact about the layout, not about the document. The
  // same option-grant notice arrives as twenty-one paragraphs with its blank
  // lines and as six without them — a PDF copy-paste, where each numbered
  // section runs into its heading — and a quarter of six is one paragraph past
  // the preamble. The grant reported "No parties identified" while naming the
  // company, its state, and its defined role in plain sight.
  it("reads a preamble that sits past a quarter of a six-paragraph document", () => {
    const body = "x ".repeat(400);
    const parties = extractParties(
      buildTree([
        "HALCYON INSTRUMENTS, INC.",
        "2026 EQUITY INCENTIVE PLAN",
        "NOTICE OF STOCK OPTION GRANT",
        'Halcyon Instruments, Inc., a Delaware corporation (the "Company"), hereby grants to the Optionee named below an option to purchase shares.',
        body,
        body,
      ]),
    );
    expect(parties.map((p) => p.name)).toContain("Halcyon Instruments, Inc");
  });
});

describe("a signature-block label whose value is not a name", () => {
  // `SIGNATURE_LINE` recognizes a signature-block line; only "By:" and "Name:"
  // carry a name after it. Stripping any of the four labels and registering
  // what followed turned the execution date of a signed form into a party: a
  // contributor license agreement ending in "Date: May 14, 2026" reported one
  // party, named "May 14, 2026" — which also masked the true finding that the
  // form names no parties the extractor can read.
  it("does not register the execution date as a party", () => {
    const names = extractParties(
      buildTree([
        "Individual Contributor License Agreement",
        "You grant the Foundation a perpetual, royalty-free copyright license to Your Contributions.",
        "Signature: /s/ Rosalind Achebe-Karlsson",
        "Date: May 14, 2026",
      ]),
    ).map((p) => p.name);
    expect(names).not.toContain("May 14, 2026");
  });

  it("still reads the signer from a By: line", () => {
    // The signature-block scan reads only the last 15% of paragraphs, so the
    // fixture needs a body for the block to be at the end of.
    const body = Array.from(
      { length: 10 },
      (_, i) => `${i + 1}. The parties shall perform their obligations in good faith.`,
    );
    const names = extractParties(
      buildTree([
        "Agreement",
        ...body,
        "ACME, INC.",
        "By: /s/ Dana Reyes",
        "Title: Chief Executive Officer",
        "Date: May 14, 2026",
      ]),
    ).map((p) => p.name);
    expect(names).toContain("Dana Reyes");
  });
});

describe("a role parenthetical behind a QUALIFIER", () => {
  // "Sonoran Crest Management, Inc., an Arizona corporation HOLDING ARIZONA
  // REAL ESTATE BROKER LICENSE NUMBER BR-558214 ("Manager")". The role must
  // follow the entity type immediately, and `BETWEEN_RE` cannot supply it
  // either — its capture terminates at the comma before "an Arizona
  // corporation". A party with no role is invisible to every rule that
  // compares an obligor against the party set, so OBLI-002 reported a MUTUAL
  // indemnity as one-sided.
  const roles = (t: string) =>
    extractParties(buildTree(["Agreement", t])).map((p) => `${p.name}|${p.role ?? ""}`);

  it("reads the role across the qualifier", () => {
    expect(
      roles(
        'This Agreement is made between Halverson Ridge Apartments LLC, an Arizona limited liability company ("Owner"), and Sonoran Crest Management, Inc., an Arizona corporation holding Arizona real estate broker license number BR-558214 ("Manager").',
      ),
    ).toEqual(["Halverson Ridge Apartments LLC|Owner", "Sonoran Crest Management, Inc|Manager"]);
  });

  it("does not reach past this party's clause into the next party's role", () => {
    // The gap refuses to cross "and", so the first party cannot borrow the
    // second party's parenthetical.
    const r = roles(
      'This Agreement is made between Acme LLC, a Delaware limited liability company, and Beta Corp., a Delaware corporation ("Manager").',
    );
    expect(r.some((x) => x.startsWith("Acme LLC|Manager"))).toBe(false);
  });

  it("does not run past the end of a sentence to find a parenthetical", () => {
    // The leading period is admitted only as an ABBREVIATION period — one not
    // followed by a capital across a space.
    const r = roles(
      'This Agreement is made between Acme LLC and Beta Corp. The Services are described in Exhibit A ("Services").',
    );
    expect(r.some((x) => x.endsWith("|Services"))).toBe(false);
  });
});

describe("a d/b/a name must be CAPITALIZED", () => {
  // DBA_RE needs its `i` flag for the case-varying "d/b/a" marker, which also
  // weakens the capture's leading `[A-Z]` to "any letter".
  it("does not register a lowercase phrase as an operating name", () => {
    const parties = extractParties(
      buildTree([
        "Agreement",
        'This Agreement is made between Halcyon Freight Systems, LLC, a Delaware limited liability company doing business as a regional carrier in the Midwest ("Carrier"), and Beta Corp., a New York corporation ("Shipper").',
      ]),
    );
    expect(parties.some((p) => p.dba)).toBe(false);
  });

  it("still registers a real operating name", () => {
    const parties = extractParties(
      buildTree([
        "Agreement",
        'This Agreement is made between Halcyon Freight Systems, LLC, a Delaware limited liability company doing business as Halcyon Logistics ("Carrier"), and Beta Corp., a New York corporation ("Shipper").',
      ]),
    );
    expect(parties.some((p) => p.dba === "Halcyon Logistics")).toBe(true);
  });
});

describe("extractParties — a preamble parenthetical is not part of the name (v9.220.0)", () => {
  it("does not register a name that swallowed an unmatched open parenthesis", () => {
    const tree = buildTree([
      "Asset Purchase Agreement",
      'This Agreement is entered into by and among Kestrel Coatings LLC, a Delaware limited liability company ("Buyer"), Harrowgate Finishing Systems, Inc., an Ohio corporation ("Seller"), and, solely for purposes of Article 7, Merrill Vance and Antonia Pike (each, a "Principal" and together, the "Principals").',
    ]);
    const names = extractParties(tree).map((p) => p.name);
    // The ", a …" descriptor strip used to cut inside the parenthetical and
    // leave a party named `Antonia Pike (each`.
    expect(names).toContain("Antonia Pike");
    expect(names.some((n) => n.includes("("))).toBe(false);
  });

  it("does not register the same entity twice, with and without its suffix", () => {
    const tree = buildTree([
      "Asset Purchase Agreement",
      'This Agreement is entered into by and among Kestrel Coatings LLC, a Delaware limited liability company ("Buyer"), Harrowgate Finishing Systems, Inc., an Ohio corporation ("Seller"), and Merrill Vance.',
    ]);
    const names = extractParties(tree).map((p) => p.name);
    expect(names).not.toContain("Harrowgate Finishing Systems");
    expect(names).toContain("Harrowgate Finishing Systems, Inc");
  });

  it("keeps two entities that share a stem but carry different suffixes", () => {
    const tree = buildTree([
      "Agreement",
      'This Agreement is made between Acme Holdings, Inc., a Delaware corporation ("Parent"), and Acme Holdings LLC, a Delaware limited liability company ("Opco").',
    ]);
    const names = extractParties(tree).map((p) => p.name);
    expect(names).toContain("Acme Holdings, Inc");
    expect(names).toContain("Acme Holdings LLC");
  });
});
