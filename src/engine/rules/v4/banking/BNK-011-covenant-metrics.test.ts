import { describe, expect, it } from "vitest";
import { V4_RULES } from "../index.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Rule } from "../../../finding.js";

const BNK011 = V4_RULES.find((r) => r.id === "BNK-011") as Rule;

// Guard: BNK-011 warns when a loan is covenant-lite. It must recognize the
// common financial-covenant metrics beyond the original four, so a loan with a
// real covenant is not reported as covenant-lite.
describe("BNK-011 financial-covenant metrics", () => {
  for (const covenant of [
    "The Borrower shall maintain a debt-service-coverage ratio of not less than 1.25 to 1.00.",
    "The Borrower shall maintain a current ratio of at least 1.5 to 1.0.",
    "The Borrower shall not permit its debt-to-equity ratio to exceed 2.0 to 1.0.",
    "The loan-to-value ratio shall not exceed 75%.",
    "The Borrower shall maintain a minimum tangible net worth of $10,000,000.",
    "The Borrower shall maintain a total leverage ratio of not more than 3.0 to 1.0.",
  ]) {
    it(`recognizes: ${covenant.slice(0, 48)}`, () => {
      expect(BNK011.check(buildContext(["Covenants", covenant]))).toBeNull();
    });
  }

  it("still warns on a covenant-lite loan (no ratio covenants)", () => {
    expect(
      BNK011.check(
        buildContext(["Covenants", "The Borrower shall deliver annual financial statements and pay all taxes when due."]),
      ),
    ).not.toBeNull();
  });
});
