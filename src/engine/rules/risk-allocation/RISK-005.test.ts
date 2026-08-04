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

  it("reads the subject-first 'liability shall in no event exceed' cap (v1.1.0)", () => {
    expect(
      RISK_005.check(doc("Provider's liability shall in no event exceed $100,000.")),
    ).toBeNull();
  });

  it("reads an 'under no circumstances … liability … exceed' cap (v1.2.0)", () => {
    expect(
      RISK_005.check(
        doc("Under no circumstances shall the Supplier's liability exceed the purchase price."),
      ),
    ).toBeNull();
  });

  it("reads a 'shall not be liable for more than $X' cap (v1.2.0)", () => {
    expect(RISK_005.check(doc("Provider shall not be liable for more than $50,000."))).toBeNull();
  });

  it("still fires on a bare damages exclusion with no cap", () => {
    expect(
      RISK_005.check(doc("The Provider shall not be liable for the acts of third parties.")),
    ).not.toBeNull();
  });

  it("reads more cap phrasings the label/exceed patterns missed (v1.3.0)", () => {
    for (const clause of [
      "Our total liability under this Agreement will be no more than the amount you paid us.",
      "Neither party shall be liable to the other for any amount exceeding the fees paid.",
      "In no event shall the aggregate damages payable by either party exceed the fees paid.",
      "The Provider shall not be liable in excess of the total Contract Value.",
    ]) {
      expect(RISK_005.check(doc(clause)), `MISSED cap: ${clause}`).toBeNull();
    }
  });

  it("fires on an explicit DISCLAIMER of any cap — the worst case (v1.4.0)", () => {
    // A contract that states there is NO cap ("no / without [any] limitation of
    // liability", "no aggregate liability cap") is UNBOUNDED exposure; the bare
    // label used to match the phrase and wrongly stay silent.
    for (const clause of [
      "There shall be no limitation of liability under this Agreement.",
      "This Agreement is entered into without any limitation of liability.",
      "No aggregate liability cap shall apply to either party.",
    ]) {
      expect(RISK_005.check(doc(clause)), `MISSED uncapped: ${clause}`).not.toBeNull();
    }
  });

  it("still reads a genuine cap heading / carve-out that merely references the label (v1.4.0)", () => {
    for (const clause of [
      "Section 8. Limitation of Liability applies to all claims arising hereunder.",
      "This limitation of liability does not apply to breaches of confidentiality.",
      "Subject to the limitation of liability set forth herein, the parties agree as follows.",
    ]) {
      expect(RISK_005.check(doc(clause)), `FALSE no-cap: ${clause}`).toBeNull();
    }
  });

  it("does not read a liability FLOOR / basket as a cap (still fires)", () => {
    // "shall be liable for amounts exceeding $X" is a basket/threshold, the
    // OPPOSITE of a cap — the required negation keeps it out.
    for (const clause of [
      "The Provider shall be liable for all amounts exceeding the ten thousand dollar basket.",
      "Liquidated damages of $500 per day shall apply to late delivery.",
      "The Vendor shall be liable for and indemnify the Customer against all third-party claims.",
    ]) {
      expect(RISK_005.check(doc(clause)), `FALSE cap: ${clause}`).not.toBeNull();
    }
  });
});
