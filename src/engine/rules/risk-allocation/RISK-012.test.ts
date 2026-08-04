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

  // v1.2.0 — an IP-indemnity DISCLAIMER matches the same shape but grants no
  // indemnity; surfacing it as "IP indemnity present" is a false positive.
  it("does not fire on an IP-indemnity disclaimer (negated-detector guard)", () => {
    expect(fires("Vendor does not indemnify Customer for any IP infringement claims.")).toBe(false);
    expect(fires("Vendor provides no indemnification for infringement of third-party IP.")).toBe(
      false,
    );
  });

  it("still fires when an unrelated 'not' sits far from the indemnify verb", () => {
    expect(
      fires(
        "Customer shall not be liable for infringement; Vendor shall indemnify Customer for IP claims.",
      ),
    ).toBe(true);
  });
});
