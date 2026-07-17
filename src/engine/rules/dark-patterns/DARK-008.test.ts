import { describe, expect, it } from "vitest";
import { rule as DARK_008 } from "./DARK-008.js";
import { buildContext } from "../../_test-fixtures.js";

describe("DARK-008 — unilateral suspension without notice or cure", () => {
  it("fires on `Vendor may suspend the Service immediately and without notice`", () => {
    const ctx = buildContext([
      "Suspension",
      "Vendor may suspend the Service immediately and without notice for any breach of this Agreement, including non-payment.",
    ]);
    const f = DARK_008.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/suspension/i);
  });

  it("fires on `sole discretion` framing", () => {
    const ctx = buildContext([
      "Service Availability",
      "Provider may suspend Customer's access to the Platform in its sole discretion at any time.",
    ]);
    expect(DARK_008.check(ctx)).not.toBeNull();
  });

  it("is silent when no suspension language exists", () => {
    const ctx = buildContext([
      "Termination",
      "Either party may terminate this Agreement upon thirty (30) days written notice.",
    ]);
    expect(DARK_008.check(ctx)).toBeNull();
  });

  // Regression: a notice-and-cure suspension with an explicit "never without
  // notice" promise is the compliant opposite of the dark pattern.
  it("is silent on a notice-and-cure suspension clause", () => {
    const ctx = buildContext([
      "Suspension",
      "Vendor may suspend the Service only after providing Customer thirty (30) days written notice of the breach and a reasonable opportunity to cure; Vendor will never suspend the Service without notice.",
    ]);
    expect(DARK_008.check(ctx)).toBeNull();
  });
});
