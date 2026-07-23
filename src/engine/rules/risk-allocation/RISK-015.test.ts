import { describe, expect, it } from "vitest";
import { rule as RISK_015 } from "./RISK-015.js";
import { buildContext } from "../../_test-fixtures.js";

describe("RISK-015 — indemnification without aggregate cap", () => {
  it("fires when indemnity present and no cap anywhere", () => {
    const ctx = buildContext([
      "Indemnification",
      "Vendor shall indemnify Customer against any third-party claim arising from the Service.",
    ]);
    const f = RISK_015.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/without aggregate cap/i);
  });

  it("fires when cap exists but explicitly carves out indemnification", () => {
    const ctx = buildContext([
      "Indemnification",
      "Vendor shall indemnify Customer against any third-party claim arising from the Service.",
      "Liability shall be limited to twelve months of fees paid, except for indemnification obligations.",
    ]);
    const f = RISK_015.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.title).toMatch(/carved out of liability cap/i);
  });

  it("is silent when indemnity is subject to a general cap (no carve-out)", () => {
    const ctx = buildContext([
      "Indemnification",
      "Vendor shall indemnify Customer against any third-party claim arising from the Service.",
      "Aggregate liability shall not exceed twelve months of fees paid under this Agreement.",
    ]);
    expect(RISK_015.check(ctx)).toBeNull();
  });

  it("is silent when no indemnification language is present", () => {
    const ctx = buildContext([
      "Limitation of Liability",
      "Aggregate liability shall not exceed the fees paid in the preceding twelve months.",
    ]);
    expect(RISK_015.check(ctx)).toBeNull();
  });

  it("is silent when indemnification is expressly disclaimed", () => {
    // The bare `indemnification obligation` trigger must not fire on a document
    // that states the obligation is ABSENT — a confident false accusation.
    const ctx = buildContext([
      "Indemnification",
      "There is no indemnification obligation under this Agreement.",
    ]);
    expect(RISK_015.check(ctx)).toBeNull();
  });

  it("fires on `hold harmless` framing without a cap", () => {
    const ctx = buildContext([
      "Indemnity",
      "Customer agrees to defend and indemnify and hold Vendor harmless from any claim arising from Customer's use of the Service.",
    ]);
    expect(RISK_015.check(ctx)).not.toBeNull();
  });
});

describe("statutory D&O indemnification is uncapped by design (v1.2.0)", () => {
  const DANDO =
    "The Corporation shall indemnify and hold harmless, to the fullest extent permitted by the General Corporation Law of the State of Delaware, any person who was or is made a party to any proceeding by reason of the fact that such person is or was a director or officer of the Corporation.";

  it("stays silent on bylaws-style DGCL § 145 indemnification", () => {
    expect(RISK_015.check(buildContext(["Indemnification", DANDO]))).toBeNull();
  });

  it("still fires on a commercial indemnity with no cap", () => {
    const ctx = buildContext([
      "Indemnity",
      "Vendor shall indemnify and hold Customer harmless from all third-party claims arising out of Vendor's breach of this Agreement.",
    ]);
    expect(RISK_015.check(ctx)).not.toBeNull();
  });

  it("'fullest extent permitted by law' alone is not the statutory form", () => {
    const ctx = buildContext([
      "Indemnity",
      "Supplier shall indemnify Buyer to the fullest extent permitted by law from all claims arising from the Services.",
    ]);
    expect(RISK_015.check(ctx)).not.toBeNull();
  });
});
