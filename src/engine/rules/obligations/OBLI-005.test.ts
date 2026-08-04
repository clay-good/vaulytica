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
        buildContext(["Restrictions", "Licensee shall not sublicense the Software to any third party."]),
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
});
