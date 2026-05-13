import { describe, expect, it } from "vitest";
import { rule as IPDATA_010 } from "./IPDATA-010.js";
import { buildContext } from "../../_test-fixtures.js";

describe("IPDATA-010 — perpetual / irrevocable license overreach", () => {
  it("fires on a sublicensable, perpetual, irrevocable, royalty-free feedback license", () => {
    const ctx = buildContext([
      "6.4 Feedback",
      "Customer hereby grants Vendor a perpetual, irrevocable, worldwide, royalty-free, sublicensable, transferable license to use any Feedback for any purpose.",
    ]);
    expect(IPDATA_010.check(ctx)).not.toBeNull();
  });

  it("fires on user-generated-content license overreach", () => {
    const ctx = buildContext([
      "Submissions",
      "By submitting any User Content, you grant us a worldwide, perpetual, irrevocable, royalty-free, sublicensable, transferable license to use, reproduce, and distribute such content.",
    ]);
    expect(IPDATA_010.check(ctx)).not.toBeNull();
  });

  it("silent on a narrow non-transferable Feedback license", () => {
    const ctx = buildContext([
      "Feedback",
      "Customer grants Vendor a non-exclusive, non-transferable license to use Feedback for the limited purpose of improving the Service, terminating on termination of this Agreement.",
    ]);
    expect(IPDATA_010.check(ctx)).toBeNull();
  });

  it("silent on the ordinary Vendor → Customer Service license (no counterparty subject)", () => {
    const ctx = buildContext([
      "License",
      "Subject to this Agreement, Vendor grants Customer a perpetual, irrevocable, worldwide, royalty-free, non-exclusive license to use the Service for internal business purposes.",
    ]);
    // No Feedback / Customer Data / User Content subject mentioned, so
    // the rule does not fire — this is the normal SaaS subscription
    // license to use the vendor's product.
    expect(IPDATA_010.check(ctx)).toBeNull();
  });
});
