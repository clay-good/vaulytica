import { describe, expect, it } from "vitest";
import { rule as RISK_004 } from "./RISK-004.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (body: string) =>
  RISK_004.check(buildContext(["Limitation of Liability", body])) !== null;

describe("RISK-004 — indemnity carved out of the liability cap", () => {
  it("fires on the 'except for indemnification' carve-out", () => {
    expect(
      fires("The limitation of liability applies except for indemnification obligations."),
    ).toBe(true);
  });

  // v1.1.0 — the carve-out is as often "the cap shall/does not apply to
  // indemnification", and the cap is called a "liability cap".
  it("fires on the 'shall/does not apply to indemnification' carve-out and the 'liability cap' synonym", () => {
    expect(
      fires("The limitation of liability shall not apply to indemnification obligations."),
    ).toBe(true);
    expect(
      fires("The aggregate liability cap does not apply to a party's indemnification duties."),
    ).toBe(true);
    expect(
      fires(
        "The liability cap shall not apply to the indemnification obligations under Section 9.",
      ),
    ).toBe(true);
  });

  it("does not fire when indemnity is INSIDE the cap or unrelated", () => {
    expect(
      fires("The limitation of liability includes all indemnification obligations within the cap."),
    ).toBe(false);
    expect(
      fires(
        "The limitation of liability applies; separately, indemnification is addressed in Section 9.",
      ),
    ).toBe(false);
  });

  // The cap phrase is as often in the section HEADING as in the clause, and a
  // paragraph-only reading found it in a heading that carries no carve-out,
  // then never saw the carve-out beneath it. A set of purchase order terms and
  // a set of SaaS terms each carve indemnity out of their cap in exactly this
  // shape, and neither was reported.
  it("reads a carve-out under a numbered heading that names the cap (v1.2.0)", () => {
    const ctx = buildContext([
      "",
      "13. Limitation of Liability.",
      "Neither party is liable to the other for any indirect, incidental, consequential, special, or punitive damages arising out of an Order. This limitation does not apply to Seller's indemnification obligations under Section 11.",
    ]);
    expect(RISK_004.check(ctx)).not.toBeNull();
  });

  it("does not borrow a heading from a PARAGRAPH that merely precedes the clause", () => {
    const ctx = buildContext([
      "",
      "12. Insurance. Seller shall maintain commercial general liability insurance of at least $2,000,000 per occurrence and shall name Buyer as an additional insured under the aggregate liability limits of that policy.",
      "Nothing in this Order except for the warranty in Section 8 affects Seller's indemnification obligations.",
    ]);
    expect(RISK_004.check(ctx)).toBeNull();
  });
});
