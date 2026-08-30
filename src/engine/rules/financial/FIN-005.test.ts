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

describe("FIN-005 — a subscription is billed, not 'due'", () => {
  // Every branch leads on due / payable / paid. A consumer subscription states
  // its term as "Subscription fees are billed in advance, monthly or
  // annually" — a plainly stated payment term the rule reported as none.
  it("reads 'billed in advance, monthly or annually'", () => {
    const ctx = buildContext([
      "3. Billing and Automatic Renewal",
      "Subscription fees are billed in advance, monthly or annually depending on the plan you select, and are non-refundable except as required by law.",
    ]);
    expect(FIN_005.check(ctx)).toBeNull();
  });

  it("reads 'charged monthly'", () => {
    const ctx = buildContext(["3. Billing", "Your payment method is charged monthly."]);
    expect(FIN_005.check(ctx)).toBeNull();
  });

  it("still fires when fees are mentioned with no term at all", () => {
    const ctx = buildContext(["3. Fees", "The plan fee is $12 per seat."]);
    expect(FIN_005.check(ctx)).not.toBeNull();
  });
});

describe("FIN-005 — an installment schedule with named due dates", () => {
  // "payable in two equal installments due on January 15 and July 15 of each
  // year" is how every homeowners-association assessment is stated. The
  // cadence branch needs "monthly"/"quarterly"; the due-date branches need an
  // ordinal day of a recurring period. Between them this read as no term.
  it("reads 'payable in two equal installments due on January 15 and July 15'", () => {
    const ctx = buildContext([
      "4.3 Annual Assessment",
      "The annual assessment for the calendar year 2027 is $1,150 per Lot, payable in two equal installments due on January 15 and July 15 of each year.",
    ]);
    expect(FIN_005.check(ctx)).toBeNull();
  });

  it("still fires on a fee with no schedule at all", () => {
    const ctx = buildContext([
      "4.3 Fees",
      "The Owner shall pay a transfer fee of $1,150 per Lot to the Association.",
    ]);
    expect(FIN_005.check(ctx)).not.toBeNull();
  });
});

describe("FIN-005 — a fee payable in advance on a stated date", () => {
  // "an annual fee of $9,500, payable in advance on each anniversary of the
  // Effective Date" is a payment term. The "in advance" / "in arrears"
  // interstitial was admitted only by the ordinal-day-of-each-month branch,
  // so the branch that knows "each anniversary" could not reach past it.
  it("recognizes 'payable in advance on each anniversary'", () => {
    expect(
      FIN_005.check(
        buildContext([
          "Fees",
          "Beneficiary shall pay Escrow Agent an annual fee of $9,500, payable in advance on each anniversary of the Effective Date.",
        ]),
      ),
    ).toBeNull();
  });

  it("recognizes 'due in arrears on the Maturity Date'", () => {
    expect(
      FIN_005.check(
        buildContext([
          "Fees",
          "Interest on the outstanding principal is due in arrears on the Maturity Date.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires when fees are named with no term at all", () => {
    expect(
      FIN_005.check(buildContext(["Fees", "Beneficiary shall pay an annual fee of $9,500."])),
    ).not.toBeNull();
  });
});

describe("FIN-005 — the payment verb is not always 'pay'", () => {
  // A funder "shall FUND each conforming draw within fifteen (15) business
  // days", a lender "shall ADVANCE", an escrow agent "shall DISBURSE", an
  // employer "shall REIMBURSE". Each is a payment term, and the pay-only
  // branch reported that none was stated.
  it.each([
    "The Funder shall fund each conforming draw within fifteen (15) business days of receipt.",
    "The Lender shall advance the requested amount within three (3) business days of the notice.",
    "The Escrow Agent shall disburse the balance within ten (10) days after Closing.",
    "The Company shall reimburse approved expenses within thirty (30) days of submission.",
  ])("reads %s", (clause) => {
    expect(FIN_005.check(buildContext(["Fees", clause]))).toBeNull();
  });
});

describe("FIN-005 — a recurring due date behind the payment source", () => {
  // "payable from the Operating Account on the TENTH (10TH) DAY of the
  // following month" — the payment SOURCE sits between the verb and the date,
  // and the ordinal is spelled with the numeral in a parenthetical. The
  // ordinal-day branch read neither, so a management fee with a stated
  // monthly due date warned that no payment term was stated.
  it.each([
    "Owner shall pay Manager a management fee of four percent (4%) of Gross Collections each month, payable from the Operating Account on the tenth (10th) day of the following month.",
    "The fee is payable on the fifteenth day of each month.",
    "Rent is due on the 1st of each month.",
  ])("reads %s", (clause) => {
    expect(FIN_005.check(buildContext(["Fees", clause]))).toBeNull();
  });
});

describe("FIN-005 — a recurring annual instalment date", () => {
  // "payable $425,000 on JANUARY 31 and $425,000 on JUNE 30 of each year" —
  // the AMOUNT sits between the verb and the date, and the date carries no
  // year because it recurs. The branch required both to be absent.
  it.each([
    "Sponsor shall pay Property $850,000 per Event year, payable $425,000 on January 31 and $425,000 on June 30 of each year of the Term.",
    "The premium is payable on March 1 of each policy year.",
    "The note is due and payable on May 15, 2028.",
  ])("reads %s", (clause) => {
    expect(FIN_005.check(buildContext(["Fees", clause]))).toBeNull();
  });
});

describe("FIN-005 — 'will pay', not only 'shall pay'", () => {
  // Half of American drafting states the obligation with "will", and both
  // active-voice branches led on `shall`. A motor carrier agreement saying
  // "Shipper will pay undisputed amounts within thirty days after receiving a
  // complete invoice" was reported as stating no payment term at all.
  it.each([
    "Shipper will pay undisputed amounts within thirty days after receiving a complete invoice.",
    "Customer must pay each invoice within forty-five (45) days of the invoice date.",
    "The Company agrees to pay the fees within fifteen (15) business days after receipt.",
    "Within ten (10) business days after the Effective Date, Buyer will pay Seller $265,000.",
  ])("reads %s", (clause) => {
    expect(FIN_005.check(buildContext(["Payment", clause]))).toBeNull();
  });

  it("still warns where no term is stated at all", () => {
    expect(
      FIN_005.check(buildContext(["Payment", "Carrier will invoice Shipper for the agreed rate."])),
    ).not.toBeNull();
  });
});
