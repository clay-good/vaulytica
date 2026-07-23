/**
 * IPDATA-001 required "hereby assigns" as two adjacent words, so the standard
 * invention-assignment sentence — "Employee hereby IRREVOCABLY assigns to the
 * Company all right, title, and interest in any and all inventions" — was
 * reported as a contract that "does not allocate ownership of intellectual
 * property".
 */
import { describe, expect, it } from "vitest";
import { rule as IPDATA_001 } from "./IPDATA-001.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (...paras: string[]) => buildContext(["Intellectual Property", ...paras]);

describe("IPDATA-001 — IP ownership clause present", () => {
  it("reads an assignment carrying an adverb", () => {
    expect(
      IPDATA_001.check(
        doc(
          "Employee hereby irrevocably assigns to the Company all right, title, and interest in any and all inventions, discoveries, improvements, and works of authorship conceived during the term of employment.",
        ),
      ),
    ).toBeNull();
  });

  it("still requires the assignment to be of intellectual property", () => {
    // A bare assignment of something else — receivables, a lease — is not an
    // IP-ownership clause, adverb or no adverb.
    expect(
      IPDATA_001.check(
        doc(
          "Borrower hereby absolutely assigns to Lender all rents and receivables of the Premises.",
        ),
      ),
    ).not.toBeNull();
  });
});
