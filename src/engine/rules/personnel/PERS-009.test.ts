import { describe, expect, it } from "vitest";
import { rule as PERS_009 } from "./PERS-009.js";
import { buildContext } from "../../_test-fixtures.js";

describe("PERS-009 — long non-solicit duration", () => {
  it("fires on a 24-month non-solicit", () => {
    const ctx = buildContext([
      "XI Non-Solicit",
      "For a period of twenty-four (24) months after termination, Customer shall not solicit any employee of Vendor.",
    ]);
    const f = PERS_009.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.title).toMatch(/24 months/);
    expect(f?.title).toMatch(/well beyond/);
  });

  it("fires on an 18-month non-solicit with 'exceeds' framing", () => {
    const ctx = buildContext([
      "Non-Solicit",
      "During the term of this Agreement and for a period of eighteen (18) months thereafter, each party agrees not to solicit any employee of the other party.",
    ]);
    const f = PERS_009.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.title).toMatch(/18 months/);
    expect(f?.title).toMatch(/exceeds/);
  });

  it("fires on a two-year non-solicit (years → months conversion)", () => {
    const ctx = buildContext([
      "Non-Solicit",
      "Receiver shall not solicit any employee of Discloser for a period of two (2) years following termination.",
    ]);
    const f = PERS_009.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.title).toMatch(/24 months/);
  });

  it("silent on a 12-month non-solicit", () => {
    const ctx = buildContext([
      "Non-Solicit",
      "For twelve (12) months after termination, each party agrees not to solicit any employee of the other party.",
    ]);
    expect(PERS_009.check(ctx)).toBeNull();
  });

  it("silent on a 6-month non-solicit", () => {
    const ctx = buildContext([
      "Non-Solicit",
      "For a period of six (6) months following termination, neither party shall solicit any employee of the other party.",
    ]);
    expect(PERS_009.check(ctx)).toBeNull();
  });

  it("silent when no non-solicit language is present", () => {
    const ctx = buildContext(["X", "The term of this Agreement is three (3) years."]);
    expect(PERS_009.check(ctx)).toBeNull();
  });

  it("does not read a material-contact lookback window as the restriction duration (v1.3.0)", () => {
    // The 12-month restriction is the duration; the "two (2) years" is the
    // historical material-contact window, not a 24-month non-solicit.
    const ctx = buildContext([
      "Non-Solicitation of Customers",
      "During employment and for twelve (12) months after termination, the Employee shall not solicit the Company's customers with whom the Employee had material contact during the last two (2) years of employment.",
    ]);
    expect(PERS_009.check(ctx)).toBeNull();
  });

  it("still flags a genuine 24-month non-solicit that also cites a lookback", () => {
    const ctx = buildContext([
      "Non-Solicitation",
      "For a period of twenty-four (24) months after termination, the Employee shall not solicit customers contacted during the last two (2) years of employment.",
    ]);
    const f = PERS_009.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.title).toMatch(/24 months/);
  });

  it("does not read a 'two years preceding' lookback (tail form) as the duration (v1.4.0)", () => {
    // The lookback window can trail the number — "customers with whom the
    // Company did business during the two (2) years preceding the Effective
    // Date" — which the lead-in / "of employment" checks did not catch.
    const ctx = buildContext([
      "Non-Solicitation",
      "During the Restricted Period, the Seller shall not solicit any customer of the Company with whom the Company did business during the two (2) years preceding the Effective Date.",
    ]);
    expect(PERS_009.check(ctx)).toBeNull();
  });
});

/**
 * The sale-of-business character is a fact about the DOCUMENT (v1.5.0).
 *
 * The paragraph-scoped guard stood down on the non-COMPETE paragraph that
 * recited the purchased goodwill and not on the non-SOLICIT one three
 * paragraphs later, because a well-drafted seller covenant states its
 * character ONCE — in the recitals, or in a section saying in terms that the
 * covenant is "given in connection with the sale of the goodwill of a
 * business, enforceable under California Business and Professions Code
 * § 16601" — and its operative covenants do not repeat it.
 *
 * So a five-year seller covenant was told its duration was "well beyond the
 * consensus 12-month bound", a bound drawn from post-employment authorities
 * that § 16601 exists to displace.
 */
describe("PERS-009 — a covenant given on the sale of a business", () => {
  const SELLER_RECITAL =
    "Under a Stock Purchase Agreement of even date, the Buyer is acquiring all of the outstanding equity of the Company from the Seller for $34,000,000, of which $6,800,000 is allocated to the goodwill of the Company's business.";
  const FIVE_YEAR_NON_SOLICIT =
    "For five (5) years after the Closing, the Seller will not solicit for employment, or hire, any person employed by the Company at the Closing.";

  it("is silent where the recital three paragraphs earlier states the sale", () => {
    expect(
      PERS_009.check(
        buildContext([
          "Non-Competition and Non-Solicitation Agreement",
          SELLER_RECITAL,
          "For five (5) years after the Closing, the Seller will not own or operate any competing business.",
          FIVE_YEAR_NON_SOLICIT,
        ]),
      ),
    ).toBeNull();
  });

  it("is silent where the document cites § 16601", () => {
    expect(
      PERS_009.check(
        buildContext([
          "Non-Competition and Non-Solicitation Agreement",
          "The parties intend this Agreement to be a covenant given in connection with the sale of the goodwill of a business, enforceable under California Business and Professions Code § 16601.",
          FIVE_YEAR_NON_SOLICIT,
        ]),
      ),
    ).toBeNull();
  });

  // Load-bearing: the same five-year non-solicit in an EMPLOYMENT agreement,
  // where the twelve-month consensus is the right benchmark, still reports.
  it("still reports a five-year non-solicit ancillary to employment", () => {
    expect(
      PERS_009.check(
        buildContext([
          "Employment Agreement",
          "The Company employs the Executive as Vice President, Laboratory Operations.",
          "For five (5) years after employment ends, the Executive will not solicit for employment any person employed by the Company.",
        ]),
      ),
    ).not.toBeNull();
  });
});
