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
});
