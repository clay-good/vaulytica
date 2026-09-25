/**
 * OBLI-005 surfaces negative covenants. v1.1.0 adds "must not" to the negation
 * filter — "must not <verb>" is extracted as an obligation but was not being
 * classified as negative, so an "Employee must not disclose" covenant was
 * dropped from the list. Bare "cannot" is intentionally excluded (it would sweep
 * in savings clauses / conditionals that are not restrictive covenants).
 */
import { describe, expect, it } from "vitest";
import { rule as OBLI_005 } from "./OBLI-005.js";
import { buildContext } from "../../_test-fixtures.js";

describe("OBLI-005 — negative covenants list", () => {
  it("fires on the 'shall not' / 'may not' baseline", () => {
    expect(
      OBLI_005.check(
        buildContext([
          "Restrictions",
          "Licensee shall not sublicense the Software to any third party.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("reads the 'must not' negation (v1.1.0)", () => {
    expect(
      OBLI_005.check(
        buildContext([
          "Confidentiality",
          "Employee must not disclose Confidential Information to any third party.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("does not classify a 'cannot be waived' savings clause as a covenant (v1.1.0)", () => {
    // "cannot" reads too broadly; a consumer-rights savings clause is not a
    // restrictive covenant. With only affirmative + savings language, no
    // negative covenant should be surfaced.
    expect(
      OBLI_005.check(
        buildContext([
          "Consumer Rights",
          "Vendor shall provide the Services. Nothing here limits any rights that cannot be waived by contract.",
        ]),
      ),
    ).toBeNull();
  });

  it("is silent when every obligation is affirmative", () => {
    expect(
      OBLI_005.check(
        buildContext(["Use", "Vendor shall use Customer data solely to provide the Services."]),
      ),
    ).toBeNull();
  });

  // v1.2.0 — a cap limits a remedy; it is not a promise to refrain.
  it("does not list a liability cap as a negative covenant", () => {
    expect(
      OBLI_005.check(
        buildContext([
          "Limitation",
          "Seller's aggregate liability under Section 8.1(a) shall not exceed the escrow amount.",
        ]),
      ),
    ).toBeNull();
  });

  it("still lists a party's promise not to exceed a limit", () => {
    expect(
      OBLI_005.check(
        buildContext(["Use", "Customer shall not exceed the usage limits in the Order Form."]),
      ),
    ).not.toBeNull();
  });

  it("does not list a statement of possibility", () => {
    expect(
      OBLI_005.check(
        buildContext([
          "Output",
          "Material generated without sufficient human authorship may not be eligible for copyright registration.",
        ]),
      ),
    ).toBeNull();
  });

  it("cuts a long clause at a word and marks the cut", () => {
    const f = OBLI_005.check(
      buildContext([
        "Use",
        "Subcontractor shall not use or disclose PHI other than as this Agreement permits, as the Upstream BAA permits Business Associate to use it, or as required by law.",
      ]),
    );
    expect(f?.description).toMatch(/\b\w+…$/);
    expect(f?.description).not.toMatch(/Busine…$/);
  });
});

describe("OBLI-005 — a provision named by what it does is not a party", () => {
  it("does not count 'this limitation shall not apply' as a negative covenant", () => {
    expect(
      OBLI_005.check(
        buildContext([
          "Limitation of Liability",
          "The aggregate liability of each party shall not exceed $2,000,000, except that this limitation shall not apply to fraud or willful misconduct.",
        ]),
      ),
    ).toBeNull();
  });

  it("still counts a party's covenant in the same sentence shape", () => {
    expect(
      OBLI_005.check(
        buildContext(["Covenants", "Assignee shall not apply the Assets to any unlawful purpose."]),
      ),
    ).not.toBeNull();
  });
});

describe("OBLI-005 — 'may not be an adequate remedy' states a fact about a remedy", () => {
  it("does not count the injunctive-relief recital as a negative covenant", () => {
    expect(
      OBLI_005.check(
        buildContext([
          "Remedies",
          "Damages alone may not be an adequate remedy for a breach of this agreement, and the Discloser is entitled to seek injunctive relief.",
        ]),
      ),
    ).toBeNull();
  });
});

describe("OBLI-005 — a securities legend's transfer restriction (v1.5.0)", () => {
  it("lists 'THIS INSTRUMENT … MAY NOT BE OFFERED, SOLD, OR OTHERWISE TRANSFERRED'", () => {
    expect(
      OBLI_005.check(
        buildContext([
          "Legend",
          "THIS INSTRUMENT AND ANY SECURITIES ISSUABLE PURSUANT HERETO HAVE NOT BEEN REGISTERED UNDER THE SECURITIES ACT OF 1933, AND MAY NOT BE OFFERED, SOLD, OR OTHERWISE TRANSFERRED EXCEPT PURSUANT TO AN EFFECTIVE REGISTRATION STATEMENT.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("still leaves out a provision describing its own scope", () => {
    expect(
      OBLI_005.check(
        buildContext(["Limitation", "This Section shall not apply to claims of fraud."]),
      ),
    ).toBeNull();
  });
});

describe("OBLI-005 — a provision named by pronoun states its scope (v1.6.0)", () => {
  it("does not count 'it shall not apply to a Settlor's own interest'", () => {
    expect(
      OBLI_005.check(
        buildContext([
          "Spendthrift",
          "This Section does not restrict a Settlor's power to revoke or amend, and it shall not apply to a Settlor's own beneficial interest during that Settlor's lifetime.",
        ]),
      ),
    ).toBeNull();
  });

  it("still counts 'Licensee shall not apply to register the Marks'", () => {
    expect(
      OBLI_005.check(
        buildContext([
          "Marks",
          "Licensee shall not apply to register the Licensed Marks in any country.",
        ]),
      ),
    ).not.toBeNull();
  });
});
