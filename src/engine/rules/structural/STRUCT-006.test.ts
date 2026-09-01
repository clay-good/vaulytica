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

/**
 * A person the document names by their relationship to the declarant.
 *
 * A will, trust, power of attorney, or guardianship designation names the
 * people it benefits and appoints, and none of them is a PARTY — the only
 * party is the declarant — so the party-name subtraction could not reach them.
 * A well-drafted will was told that "Thomas Aurelio Harper" and "Nadia Harper
 * Okonkwo" are Title-Case terms it forgot to define.
 */
describe("STRUCT-006 — a named person is not an undefined term (v1.4.0)", () => {
  const WILL = (appositive: boolean) => {
    const husband = appositive ? "my husband, Thomas Aurelio Harper," : "Thomas Aurelio Harper";
    const daughter = appositive ? "my daughter, Nadia Harper Okonkwo," : "Nadia Harper Okonkwo";
    return buildContext([
      "Last Will and Testament of Eleanor Marguerite Harper",
      "I, Eleanor Marguerite Harper, of Columbus, Ohio, being of sound mind, declare this to be my Last Will and Testament.",
      `I give my residuary estate to ${husband} if he survives me by thirty days.`,
      `I appoint ${daughter} as successor Executor of this Will.`,
      "If Thomas Aurelio Harper does not survive me, my estate passes to Nadia Harper Okonkwo in equal shares.",
      "Thomas Aurelio Harper shall serve without bond, and Nadia Harper Okonkwo shall serve without bond.",
    ]);
  };

  it("is silent on the executor and the beneficiary a will appoints", () => {
    expect(STRUCT_006.check(WILL(true))).toBeNull();
  });

  // The suppression is load-bearing, not incidental: the identical will with
  // the relationship appositives removed is exactly what the rule reports.
  it("still reports the same names where nothing says they are people", () => {
    const found = STRUCT_006.check(WILL(false));
    expect(found?.description).toContain("Thomas Aurelio Harper");
    expect(found?.description).toContain("Nadia Harper Okonkwo");
  });
});
