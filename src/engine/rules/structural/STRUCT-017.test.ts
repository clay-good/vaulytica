import { describe, expect, it } from "vitest";
import { rule as STRUCT_017 } from "./STRUCT-017.js";
import { buildContext } from "../../_test-fixtures.js";

describe("STRUCT-017 — signature-block completeness", () => {
  it("fires when a labeled multi-party block omits a declared party (3-party case)", () => {
    const ctx = buildContext(
      [
        "Agreement",
        'This Agreement is among Acme Corp., a Delaware corporation ("Provider"), Globex Industries, Inc., a New York corporation ("Customer"), and Initech LLC, a Texas limited liability company ("Guarantor").',
      ],
      ["Provider sig", "Provider"],
      ["Provider line", "By: ____ Name: Jane Roe Title: CEO"],
      ["Customer sig", "Customer"],
      ["Customer line", "By: ____ Name: John Doe Title: COO"],
    );
    const f = STRUCT_017.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.severity).toBe("warning");
    expect(f?.description).toMatch(/Initech|Guarantor/);
  });

  it("stays silent when every declared party is labeled in the block", () => {
    const ctx = buildContext(
      [
        "Agreement",
        'This Agreement is between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
      ],
      ["Provider sig", "Provider"],
      ["Provider line", "By: ____ Name: Jane Roe Title: CEO"],
      ["Customer sig", "Customer"],
      ["Customer line", "By: ____ Name: John Doe Title: COO"],
    );
    expect(STRUCT_017.check(ctx)).toBeNull();
  });

  it("stays silent on a generic, unlabeled stub block (cannot be reconciled)", () => {
    const ctx = buildContext(
      [
        "Agreement",
        'This Agreement is between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer").',
      ],
      ["Signatures", "Signed by: ____________________  Title: Authorized Representative"],
    );
    expect(STRUCT_017.check(ctx)).toBeNull();
  });

  it("stays silent when there is no signature block at all (STRUCT-003's job)", () => {
    const ctx = buildContext([
      "Agreement",
      'This Agreement is between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer"). The parties agree to the terms herein.',
    ]);
    expect(STRUCT_017.check(ctx)).toBeNull();
  });

  it("still reconciles a party that defines its own name", () => {
    // A party is routinely a defined term ("Northwind Trust" means the
    // Delaware statutory trust acting as Escrow Agent). Excluding defined
    // terms from the party set erased this finding entirely.
    const ctx = buildContext(
      [
        "Agreement",
        'This Escrow Agreement is among Acme Corp., a Delaware corporation ("Depositor"), Globex Industries, Inc., a New York corporation ("Beneficiary"), and Northwind Trust, a Delaware trust ("Escrow Agent").',
      ],
      [
        "Definitions",
        '"Northwind Trust" means the Delaware statutory trust acting as Escrow Agent hereunder, and its permitted successors.',
      ],
      ["Depositor sig", "Depositor"],
      ["Depositor line", "By: ____ Name: Jane Roe Title: CEO"],
      ["Beneficiary sig", "Beneficiary"],
      ["Beneficiary line", "By: ____ Name: John Doe Title: COO"],
    );
    const f = STRUCT_017.check(ctx);
    expect(f?.description).toMatch(/Northwind Trust/);
  });

  it("stays silent with fewer than two declared parties", () => {
    const ctx = buildContext(
      ["Agreement", 'Acme Corp., a Delaware corporation ("Provider"), offers the Services.'],
      ["Signatures", "Provider", "By: ____ Name: Jane Roe Title: CEO Date: ____"],
    );
    expect(STRUCT_017.check(ctx)).toBeNull();
  });
});

describe("STRUCT-017 v1.1.0 — reconciling a real signature block", () => {
  it("reads a label line that names the entity AND its formation clause", () => {
    // "PELLWORTH & KIRUNA DESIGN LLC, an Illinois limited liability company"
    // is 68 characters, and the label bound was 60 — so the label fell
    // outside the block, the "By:" line named only the human signing, and a
    // sublease was told the subtenant had no signature line in the block
    // bearing its signature.
    const ctx = buildContext(
      [
        "Sublease",
        'This Sublease is between Orthogonal Labs, Inc., a Delaware corporation ("Sublandlord"), and Pellworth & Kiruna Design LLC, an Illinois limited liability company ("Subtenant").',
      ],
      ["Sublandlord label", "SUBLANDLORD:"],
      ["Sublandlord name", "ORTHOGONAL LABS, INC., a Delaware corporation"],
      [
        "Sublandlord line",
        "By: /s/ Tobias Wrenfield Name: Tobias Wrenfield Title: Chief Operating Officer",
      ],
      ["Subtenant label", "SUBTENANT:"],
      ["Subtenant name", "PELLWORTH & KIRUNA DESIGN LLC, an Illinois limited liability company"],
      ["Subtenant line", "By: /s/ Anneli Kiruna Name: Anneli Kiruna Title: Managing Member"],
    );
    expect(STRUCT_017.check(ctx)).toBeNull();
  });

  it("does not fold a short definition paragraph into the block", () => {
    // The label bound alone is not enough: a label line is a NAME, and a
    // sentence has a finite verb. Widening the bound without that filter
    // swept in '"Northwind Trust" MEANS the Delaware statutory trust …' and
    // reconciled a party with no signature line at all.
    const ctx = buildContext(
      [
        "Agreement",
        'This Escrow Agreement is among Acme Corp., a Delaware corporation ("Depositor"), Globex Industries, Inc., a New York corporation ("Beneficiary"), and Northwind Trust, a Delaware trust ("Escrow Agent").',
      ],
      [
        "Definitions",
        '"Northwind Trust" means the Delaware statutory trust acting as Escrow Agent hereunder.',
      ],
      ["Depositor sig", "Depositor"],
      ["Depositor line", "By: ____ Name: Jane Roe Title: CEO"],
      ["Beneficiary sig", "Beneficiary"],
      ["Beneficiary line", "By: ____ Name: John Doe Title: COO"],
    );
    expect(STRUCT_017.check(ctx)?.description).toMatch(/Northwind Trust/);
  });

  it("does not count a one-word truncation of a party's name", () => {
    // The extractor registers "FULTON" alongside "FULTON MARKET REALTY III
    // LLC", and a signature block that states the signatory's address —
    // "1130 West Fulton Market, Chicago" — reconciled the landlord as having
    // signed. A signature block names a party by its full legal name.
    const ctx = buildContext(
      [
        "Agreement",
        'This Agreement is among Acme Corp., a Delaware corporation ("Depositor"), Globex Industries, Inc., a New York corporation ("Beneficiary"), and Fulton Market Realty III LLC, an Illinois limited liability company ("Landlord").',
      ],
      ["Depositor sig", "Depositor"],
      [
        "Depositor line",
        "By: ____ Name: Jane Roe Title: CEO Address: 1130 West Fulton Market, Chicago, Illinois",
      ],
      ["Beneficiary sig", "Beneficiary"],
      ["Beneficiary line", "By: ____ Name: John Doe Title: COO"],
    );
    expect(STRUCT_017.check(ctx)?.description).toMatch(/Fulton Market Realty III LLC/);
  });

  it("does not ask a prime landlord to sign the sublease", () => {
    // A sublease names the prime landlord in its recitals as a party to the
    // PRIME LEASE. It is fully declared, entity-typed and role-bearing, and
    // it will never sign the sublease — it consents separately.
    const ctx = buildContext(
      [
        "Sublease",
        'This Sublease is between Orthogonal Labs, Inc., a Delaware corporation ("Sublandlord"), and Pellworth Design LLC, an Illinois limited liability company ("Subtenant").',
      ],
      [
        "Recitals",
        'Sublandlord, as tenant, and Fulton Market Realty III LLC, an Illinois limited liability company ("Prime Landlord"), as landlord, are parties to that certain Office Lease dated June 15, 2022.',
      ],
      ["Sublandlord label", "SUBLANDLORD: ORTHOGONAL LABS, INC."],
      ["Sublandlord line", "By: ____ Name: Tobias Wrenfield Title: COO"],
      ["Subtenant label", "SUBTENANT: PELLWORTH DESIGN LLC"],
      ["Subtenant line", "By: ____ Name: Anneli Kiruna Title: Managing Member"],
    );
    expect(STRUCT_017.check(ctx)).toBeNull();
  });
});
