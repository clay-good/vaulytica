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
});
