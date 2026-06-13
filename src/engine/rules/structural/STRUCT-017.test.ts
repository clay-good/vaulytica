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

  it("stays silent with fewer than two declared parties", () => {
    const ctx = buildContext(
      ["Agreement", 'Acme Corp., a Delaware corporation ("Provider"), offers the Services.'],
      ["Signatures", "Provider", "By: ____ Name: Jane Roe Title: CEO Date: ____"],
    );
    expect(STRUCT_017.check(ctx)).toBeNull();
  });
});
