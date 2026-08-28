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

describe("FIN-005 — anniversary and Effective Date fee terms (v1.4.0)", () => {
  it("reads 'due and payable on the Effective Date and on each anniversary'", () => {
    expect(
      FIN_005.check(
        doc(
          "Buyer and Seller shall each pay one-half of the Escrow Agent's fees, due and payable on the Effective Date and on each anniversary of the Effective Date.",
        ),
      ),
    ).toBeNull();
  });
});

describe("FIN-005 — 'no later than N days' is a payment window (v1.4.1)", () => {
  it("reads 'shall pay each invoice no later than thirty (30) days after receipt'", () => {
    expect(
      FIN_005.check(
        doc("Customer shall pay each invoice no later than thirty (30) days after receipt."),
      ),
    ).toBeNull();
  });

  it("reads 'payable no later than fifteen (15) days after the invoice date'", () => {
    expect(
      FIN_005.check(
        doc("Each invoice is payable no later than fifteen (15) days after the invoice date."),
      ),
    ).toBeNull();
  });

  it("reads 'the fees are due no later than thirty (30) days'", () => {
    expect(
      FIN_005.check(doc("The fees are due no later than thirty (30) days after the invoice date.")),
    ).toBeNull();
  });

  it("still fires when payment is stated with no window at all", () => {
    expect(
      FIN_005.check(
        doc("Customer shall pay each invoice as set out in the applicable Order Form."),
      ),
    ).not.toBeNull();
  });
});

describe("FIN-005 — more payment-term phrasings (v1.6.0)", () => {
  it("reads 'payable on a monthly basis'", () => {
    expect(FIN_005.check(doc("The fee is payable on a monthly basis."))).toBeNull();
  });
  it("reads a spelled 'net sixty (60) days' window", () => {
    expect(FIN_005.check(doc("Invoices are payable net sixty (60) days."))).toBeNull();
  });
  it("reads 'remit payment within fifteen (15) business days'", () => {
    expect(
      FIN_005.check(doc("Customer will remit payment within fifteen (15) business days.")),
    ).toBeNull();
  });
  it("reads 'due and payable upon presentation of an invoice'", () => {
    expect(
      FIN_005.check(doc("All amounts are due and payable upon presentation of an invoice.")),
    ).toBeNull();
  });
  it("reads 'within thirty days following the end of each month'", () => {
    expect(
      FIN_005.check(
        doc("Payment shall be made within thirty (30) days following the end of each month."),
      ),
    ).toBeNull();
  });
  it("does not read a stray 'net income of sixty' as a payment term", () => {
    expect(
      FIN_005.check(
        doc("Customer shall make payment for the services. Net income was sixty million dollars."),
      ),
    ).not.toBeNull();
  });
});

describe("FIN-005 — an installment schedule with no stated count (v1.5.0)", () => {
  it("reads a lease rent 'payable in equal monthly installments' (no number)", () => {
    expect(
      FIN_005.check(
        doc(
          "The Tenant shall pay annual base rent of $360,000, payable in equal monthly installments.",
        ),
      ),
    ).toBeNull();
  });

  it("still reads the counted form 'payable in twelve (12) equal monthly installments'", () => {
    expect(
      FIN_005.check(
        doc("The purchase price is payable in twelve (12) equal monthly installments."),
      ),
    ).toBeNull();
  });
});

describe("FIN-005 — the employment payroll-cadence payment term (v1.6.2)", () => {
  it("reads 'payable in accordance with the Company's regular payroll practices'", () => {
    expect(
      FIN_005.check(
        doc(
          "The Company shall pay the Executive an annual base salary of $420,000, payable in accordance with the Company's regular payroll practices.",
        ),
      ),
    ).toBeNull();
  });

  it("does not treat 'payroll taxes' as the payment term when a payment obligation is present", () => {
    // "payable" trips the payment gate; "payroll taxes" is not a cadence noun,
    // so with no real term stated the rule must still fire.
    expect(
      FIN_005.check(
        doc(
          "Compensation is payable to the Executive. The Company shall withhold all applicable payroll taxes.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("FIN-005 — a royalty payment window (v1.4.4)", () => {
  it("reads 'Royalties are payable within thirty (30) days after the end of each quarter'", () => {
    expect(
      FIN_005.check(
        doc(
          "The Licensee shall pay the Licensor a royalty of fifteen percent (15%) of net receipts. Royalties are payable within thirty (30) days after the end of each calendar quarter.",
        ),
      ),
    ).toBeNull();
  });
});

describe("FIN-005 — payment at the Closing event (v1.4.3)", () => {
  it("reads 'the Purchase Price … payable in cash at the Closing'", () => {
    expect(
      FIN_005.check(doc("The Purchase Price is $12,000,000, payable in cash at the Closing.")),
    ).toBeNull();
  });

  it("reads 'the balance is due and payable at closing'", () => {
    expect(
      FIN_005.check(doc("The balance is due and payable at the closing of the transaction.")),
    ).toBeNull();
  });

  it("does not treat a stray 'closing' with no payment verb as a term", () => {
    expect(
      FIN_005.check(
        doc("Payment is described in the Order Form. See the closing paragraph for definitions."),
      ),
    ).not.toBeNull();
  });
});

describe("FIN-005 — hyphenated compound-number windows (v1.4.2)", () => {
  it("reads 'due and payable within forty-five (45) days of the invoice date'", () => {
    expect(
      FIN_005.check(
        doc("Each invoice is due and payable within forty-five (45) days of the invoice date."),
      ),
    ).toBeNull();
  });

  it("reads 'payable within twenty-one (21) days of invoice'", () => {
    expect(
      FIN_005.check(doc("Fees are payable within twenty-one (21) days of invoice.")),
    ).toBeNull();
  });
});

describe("FIN-005 — retainer/deposit due at signing (v1.6.4)", () => {
  it("reads a fee due at signing or upon execution of the agreement", () => {
    for (const text of [
      "The retainer fee of $5,000 is due at signing.",
      "The deposit is payable upon signing of this Agreement.",
      "The fee is payable upon execution of this Agreement.",
    ]) {
      expect(FIN_005.check(doc(text)), text).toBeNull();
    }
  });

  it("still warns when 'execution' names a milestone, not the agreement", () => {
    // "due upon execution of Phase 1" is a delivery milestone, not a payment
    // term — the agreement-scoping keeps it out, so the rule still fires.
    expect(
      FIN_005.check(doc("The deliverable fee is due upon execution of Phase 1.")),
    ).not.toBeNull();
  });
});

describe("FIN-005 — the deadline fronted ahead of the verb (v1.8.0)", () => {
  // "Within ten (10) business days after the Effective Date, Kanaan shall pay
  // Pelagic $265,000" is as conventional as the trailing form, and every
  // branch read left to right from the verb, so a plainly stated payment term
  // was reported as none.
  it("is silent on a fronted payment deadline", () => {
    for (const clause of [
      "Within ten (10) business days after the Effective Date, Kanaan shall pay Pelagic $265,000 by wire transfer to the account Pelagic designates in writing.",
      "Within thirty (30) days of receipt of a proper invoice, Customer shall pay the fees set forth on the Order Form.",
      "No later than 15 days after the end of each month, Licensee shall remit the royalties due for that month.",
    ]) {
      expect(FIN_005.check(doc(clause)), clause).toBeNull();
    }
  });

  it("still fires when a fee is stated with no term at all", () => {
    expect(
      FIN_005.check(
        doc("Customer shall pay each invoice in the amount set out in the Order Form."),
      ),
    ).not.toBeNull();
  });
});
