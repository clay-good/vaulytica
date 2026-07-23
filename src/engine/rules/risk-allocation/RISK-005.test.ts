/**
 * RISK-005 matched the HEADING ("limitation of liability", "aggregate
 * liability") rather than the cap. A textbook cap that uses neither label —
 * "EACH PARTY'S TOTAL CUMULATIVE LIABILITY … SHALL NOT EXCEED THE FEES PAID …"
 * — was reported as "Vaulytica did not find a limitation-of-liability clause".
 */
import { describe, expect, it } from "vitest";
import { rule as RISK_005 } from "./RISK-005.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (...paras: string[]) => buildContext(["Liability", ...paras]);

describe("RISK-005 — limitation of liability present", () => {
  it("reads a cap written without either label", () => {
    expect(
      RISK_005.check(
        doc(
          "EACH PARTY'S TOTAL CUMULATIVE LIABILITY ARISING OUT OF OR RELATED TO THIS AGREEMENT, WHETHER IN CONTRACT, TORT, OR OTHERWISE, SHALL NOT EXCEED THE FEES PAID BY CUSTOMER TO PROVIDER IN THE TWELVE (12) MONTHS PRECEDING THE EVENT GIVING RISE TO THE CLAIM.",
        ),
      ),
    ).toBeNull();
  });

  it("reads the 'limited to' form", () => {
    expect(
      RISK_005.check(
        doc("Vendor's total liability is limited to the fees paid in the prior year."),
      ),
    ).toBeNull();
  });

  it("reads the 'in no event … exceed' form", () => {
    expect(
      RISK_005.check(
        doc("In no event shall either party's liability under this Agreement exceed $100,000."),
      ),
    ).toBeNull();
  });

  it("still fires when nothing caps liability", () => {
    expect(
      RISK_005.check(
        doc(
          "Recipient shall protect Confidential Information with the same degree of care it uses for its own, but in no event less than a reasonable degree of care.",
        ),
      ),
    ).not.toBeNull();
  });

  it("does not borrow a cap from a different sentence", () => {
    expect(
      RISK_005.check(
        doc(
          "Provider accepts liability for its own negligence. Fees for professional services shall not exceed the amount stated in the Order Form.",
        ),
      ),
    ).not.toBeNull();
  });
});
