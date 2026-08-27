import { describe, expect, it } from "vitest";
import { rule as STRUCT_006 } from "./STRUCT-006.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

/**
 * A document that imports its definitions is not missing them.
 *
 * "Capitalized terms used and not defined in this Amendment have the meanings
 * given in the Lease" appears in every amendment, addendum, statement of work,
 * side letter, and order form — documents whose whole point is that the parent
 * defines the vocabulary. A third amendment to an office lease was told that
 * Base Rent, Base Year, Proportionate Share, Fair Market Rental Value, and
 * Security Deposit were undefined, in a document whose Section 1 says exactly
 * where they are defined.
 */
describe("STRUCT-006 — incorporation by reference (v1.2.0)", () => {
  const AMENDMENT = [
    "Base Rent for the Existing Premises during the Extension Term is $38.50 per rentable square foot.",
    "Tenant shall continue to pay its Proportionate Share of Operating Expenses in excess of the Base Year.",
    "The Security Deposit is increased. Base Rent escalates annually and the Proportionate Share is restated.",
  ];

  it("stays silent when the document imports its definitions", () => {
    expect(
      STRUCT_006.check(
        doc(
          "Third Amendment to Office Lease",
          "Capitalized terms used and not defined in this Amendment have the meanings given in the Lease.",
          ...AMENDMENT,
        ),
      ),
    ).toBeNull();
  });

  it("still fires on the same text without the incorporation clause", () => {
    // The suppression is load-bearing, not incidental: the identical body,
    // with only the incorporation sentence removed, is exactly what the rule
    // exists to report.
    expect(STRUCT_006.check(doc("Third Amendment to Office Lease", ...AMENDMENT))).not.toBeNull();
  });

  it("is not disabled by a sentence that merely mentions defined terms", () => {
    // Both halves are required — capitalized terms not defined HERE, and their
    // meanings given THERE — so an ordinary reference does not switch the
    // check off.
    expect(
      STRUCT_006.check(
        doc(
          "Agreement",
          "The defined terms in this Agreement are listed in Schedule 1 and are used consistently throughout.",
          ...AMENDMENT,
        ),
      ),
    ).not.toBeNull();
  });
});
