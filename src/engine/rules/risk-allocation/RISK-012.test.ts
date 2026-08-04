import { describe, expect, it } from "vitest";
import { rule as RISK_012 } from "./RISK-012.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (body: string) => RISK_012.check(buildContext(["Indemnification", body])) !== null;

describe("RISK-012 — IP indemnity present", () => {
  it("fires on the noun-first and infringement-first orders", () => {
    expect(fires("The IP indemnification obligations are set forth in this Section.")).toBe(true);
    expect(fires("For any infringement claim, Vendor shall indemnify Customer.")).toBe(true);
  });

  // v1.1.0 — the natural verb-first order "shall indemnify ... against patent
  // infringement" / "... from any infringing use" was missed.
  it("fires on the verb-first 'indemnify ... infringement/infringing' order", () => {
    expect(fires("Vendor shall indemnify Customer against any claim of patent infringement.")).toBe(
      true,
    );
    expect(
      fires(
        "Supplier will indemnify and hold harmless Buyer from any infringing use of the Software.",
      ),
    ).toBe(true);
  });

  it("does not fire on a non-IP indemnity", () => {
    expect(fires("Vendor shall indemnify Customer against third-party bodily injury claims.")).toBe(
      false,
    );
  });
});
