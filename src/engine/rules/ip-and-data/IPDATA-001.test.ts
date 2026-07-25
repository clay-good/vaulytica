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

  it("reads a trademark license's active reservation and goodwill inurement (v1.3.0)", () => {
    // A license allocates IP ownership by reserving it — in the active voice
    // and, for a trademark, through goodwill inurement.
    expect(
      IPDATA_001.check(
        doc(
          "The Licensor reserves all rights not expressly granted. The Licensee acquires no ownership interest in the Licensed Marks, and all goodwill arising from the Licensee's use of the Licensed Marks inures solely to the benefit of the Licensor.",
        ),
      ),
    ).toBeNull();
  });

  it("reads a bare 'Licensee acquires no ownership interest' reservation (v1.3.0)", () => {
    expect(
      IPDATA_001.check(doc("The Licensee acquires no ownership interest in the Licensed Marks.")),
    ).toBeNull();
  });

  it("reads an ownership STATEMENT — 'Licensor owns the Licensed Patents' (v1.3.1)", () => {
    expect(
      IPDATA_001.check(doc("The Licensor represents that it owns the Licensed Patents.")),
    ).toBeNull();
    expect(IPDATA_001.check(doc("Each party owns the improvements it makes."))).toBeNull();
  });

  it("does not read a bare non-IP 'owns' as an IP-ownership clause (v1.3.1)", () => {
    expect(
      IPDATA_001.check(doc("The Investor owns 10% of the outstanding shares of the Company.")),
    ).not.toBeNull();
  });

  it("reads retention / title-vesting / owner / property-of ownership forms (v1.4.0)", () => {
    expect(
      IPDATA_001.check(doc("Licensor retains all right, title, and interest in and to the Licensed Materials.")),
    ).toBeNull();
    expect(IPDATA_001.check(doc("Title to all Inventions shall vest in the Employer."))).toBeNull();
    expect(
      IPDATA_001.check(doc("The Company shall be the sole and exclusive owner of all Work Product.")),
    ).toBeNull();
    expect(
      IPDATA_001.check(doc("All work product is the exclusive property of the Client.")),
    ).toBeNull();
    expect(IPDATA_001.check(doc("Customer shall own all Customer Data."))).toBeNull();
  });

  it("does not read a possessive 'its own … data' as an ownership clause", () => {
    expect(
      IPDATA_001.check(
        doc("Processor shall maintain its own internal documentation of personal data flows."),
      ),
    ).not.toBeNull();
  });
});
