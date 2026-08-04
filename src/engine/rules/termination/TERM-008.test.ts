import { describe, expect, it } from "vitest";
import { rule as TERM_008 } from "./TERM-008.js";
import { buildContext } from "../../_test-fixtures.js";

describe("TERM-008 — immediate termination on payment default (v1.1.0)", () => {
  const fires = (text: string) => TERM_008.check(buildContext(["Termination", text])) !== null;

  it("fires on the adverb-first form", () => {
    expect(fires("The Company may immediately terminate this Agreement for non-payment.")).toBe(
      true,
    );
  });

  it("fires on the dominant verb-first 'terminate … immediately upon non-payment'", () => {
    expect(fires("The Company may terminate this Agreement immediately upon non-payment.")).toBe(
      true,
    );
  });

  it("fires on 'terminate immediately if … fails to pay'", () => {
    expect(
      fires(
        "Either party may terminate immediately if the Customer fails to pay any amount when due.",
      ),
    ).toBe(true);
  });

  it("fires on the trigger-first form", () => {
    expect(fires("Upon non-payment, the Company may immediately terminate this Agreement.")).toBe(
      true,
    );
  });

  it("stays silent on a for-cause termination with a cure period", () => {
    expect(
      fires(
        "Either party may terminate for cause on a material breach uncured within thirty (30) days.",
      ),
    ).toBe(false);
  });

  it("stays silent on an unrelated 'due immediately' with no termination", () => {
    expect(fires("All amounts are due immediately upon receipt of the invoice.")).toBe(false);
  });

  it("stays silent on a notice-period termination with no immediacy or payment trigger", () => {
    expect(
      fires("The Company may terminate this Agreement on sixty (60) days' prior notice."),
    ).toBe(false);
  });
});
