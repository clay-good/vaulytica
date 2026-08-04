import { describe, expect, it } from "vitest";
import { rule as RISK_016 } from "./RISK-016.js";
import { buildContext } from "../../_test-fixtures.js";

describe("RISK-016 — insurance requirement without coverage minimum", () => {
  it("fires when insurance is required without any coverage amount", () => {
    const ctx = buildContext([
      "Insurance",
      "Contractor shall maintain commercial general liability insurance during the term of this Agreement.",
    ]);
    const f = RISK_016.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/without coverage minimum/i);
  });

  it("fires on `must carry insurance` without amount", () => {
    const ctx = buildContext([
      "Insurance",
      "Vendor must carry professional liability insurance during the engagement.",
    ]);
    expect(RISK_016.check(ctx)).not.toBeNull();
  });

  it("is silent when a per-occurrence minimum is specified", () => {
    const ctx = buildContext([
      "Insurance",
      "Contractor shall maintain commercial general liability insurance with limits of $1,000,000 per occurrence and $2,000,000 aggregate.",
    ]);
    expect(RISK_016.check(ctx)).toBeNull();
  });

  it("is silent when `not less than $X` framing is used", () => {
    const ctx = buildContext([
      "Insurance",
      "Vendor shall maintain professional liability insurance of not less than $1,000,000 per claim.",
    ]);
    expect(RISK_016.check(ctx)).toBeNull();
  });

  it("is silent when `at least $X million` framing is used", () => {
    const ctx = buildContext([
      "Insurance",
      "Contractor shall procure insurance at least $5,000,000 in aggregate coverage.",
    ]);
    expect(RISK_016.check(ctx)).toBeNull();
  });

  it("is silent when no insurance clause exists", () => {
    const ctx = buildContext([
      "Term",
      "This Agreement is effective for two years from the Effective Date.",
    ]);
    expect(RISK_016.check(ctx)).toBeNull();
  });

  // v1.1.0 — the mandate is also written with an "is required to" modal, a
  // "purchase / secure" verb, or in the passive voice, all previously missed.
  it("fires on the required-to / purchase / passive forms without a minimum", () => {
    for (const body of [
      "Vendor is required to carry professional liability insurance during the engagement.",
      "Tenant shall purchase fire and casualty insurance for the premises.",
      "Insurance shall be maintained by the Contractor throughout the term.",
    ]) {
      const f = RISK_016.check(buildContext(["Insurance", body]));
      expect(f, body).not.toBeNull();
      expect(f?.severity).toBe("warning");
    }
  });

  it("does not misread an insurance-CERTIFICATE or insurance-PROCEEDS clause as the mandate", () => {
    expect(
      RISK_016.check(
        buildContext([
          "Insurance",
          "Contractor shall provide insurance certificates to Owner annually.",
        ]),
      ),
    ).toBeNull();
    expect(
      RISK_016.check(
        buildContext([
          "Casualty",
          "The Owner shall have insurance proceeds applied to restoration.",
        ]),
      ),
    ).toBeNull();
  });
});
