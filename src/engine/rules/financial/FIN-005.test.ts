/**
 * Every branch of the payment-term detector was invoice-shaped ("Net 30",
 * "due within 15 days of invoice"), so a recurring charge — which states its
 * term as a due DATE — was reported as having none: "Base Rent: $20,000 per
 * month, payable in advance on the first of each month" was told the document
 * "references fees but no 'Net X' or 'due within' clause was found."
 */
import { describe, expect, it } from "vitest";
import { rule as FIN_005 } from "./FIN-005.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (...paras: string[]) => buildContext(["Fees", ...paras]);

describe("FIN-005 — payment terms present", () => {
  it("reads a recurring due date", () => {
    expect(
      FIN_005.check(
        doc("Base Rent: $20,000 per month, payable in advance on the first of each month."),
      ),
    ).toBeNull();
    expect(
      FIN_005.check(doc("Base Rent: $2,500 per month, due on the first of each month.")),
    ).toBeNull();
  });

  it("reads a payroll-style cadence", () => {
    expect(
      FIN_005.check(
        doc(
          "Company shall pay Contractor $100.00 for all hours worked, payable bi-weekly on the same schedule as Company's regular payroll.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires when fees are stated with no due date at all", () => {
    expect(
      FIN_005.check(
        doc("Customer shall pay each invoice in the amount set out in the Order Form."),
      ),
    ).not.toBeNull();
  });

  it("stays silent on a document that never mentions money", () => {
    expect(
      FIN_005.check(doc("Recipient shall hold Confidential Information in confidence.")),
    ).toBeNull();
  });
});

describe("FIN-005 — settlement-style payment routing (v1.2.0)", () => {
  it("reads 'shall pay … (the \"Settlement Payment\") … within thirty (30) days'", () => {
    expect(
      FIN_005.check(
        doc(
          'Harbor Point shall pay Meridian the total sum of $425,000 (the "Settlement Payment") by wire transfer to the trust account of Meridian\'s counsel within thirty (30) days after the Effective Date.',
        ),
      ),
    ).toBeNull();
  });
});

describe("FIN-005 — a note's maturity date is its payment term (v1.3.0)", () => {
  it("reads 'due and payable on May 15, 2028'", () => {
    expect(
      FIN_005.check(
        doc(
          "Unless earlier converted, the outstanding principal and accrued interest shall be due and payable on May 15, 2028, upon written demand of the Investor.",
        ),
      ),
    ).toBeNull();
  });

  it("reads 'due and payable on the Maturity Date'", () => {
    expect(
      FIN_005.check(doc("All outstanding amounts are due and payable on the Maturity Date.")),
    ).toBeNull();
  });
});
