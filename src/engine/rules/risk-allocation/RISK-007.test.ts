/**
 * RISK-007 surfaces a waiver of consequential / special / incidental / punitive
 * damages. v1.1.0 fixes an inverse-FP: the "liable for" branch required no
 * negation, so an AFFIRMATIVE liability clause ("each party remains liable for
 * consequential damages") — the opposite of a waiver — was flagged.
 */
import { describe, expect, it } from "vitest";
import { rule as RISK_007 } from "./RISK-007.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (body: string) =>
  RISK_007.check(buildContext(["Limitation of Liability", body])) !== null;

describe("RISK-007 — consequential damages waiver present", () => {
  it("fires on genuine waiver phrasings", () => {
    expect(fires("Vendor shall not be liable for consequential damages.")).toBe(true);
    expect(fires("Vendor is not liable for any consequential damages.")).toBe(true);
    expect(fires("In no event shall either party be liable for no consequential damages.")).toBe(
      true,
    );
    expect(
      fires("Neither party is liable for special, incidental, consequential, or punitive damages."),
    ).toBe(true);
    expect(fires("Each party waives any consequential damages.")).toBe(true);
  });

  it("does not fire on an AFFIRMATIVE liability clause (inverse-FP guard, v1.1.0)", () => {
    expect(fires("Each party remains liable for consequential damages.")).toBe(false);
    expect(fires("The breaching party is liable for consequential damages.")).toBe(false);
  });

  it("reads the 'indirect' and 'exemplary' damage synonyms (v1.2.0)", () => {
    expect(fires("In no event shall either party be liable for any indirect damages.")).toBe(true);
    expect(fires("Neither party shall be liable for any indirect or exemplary damages.")).toBe(
      true,
    );
    expect(fires("Company shall not be liable for exemplary damages of any kind.")).toBe(true);
    expect(fires("No indirect damages shall be recoverable under this Agreement.")).toBe(true);
  });

  it("reads a single-type 'in no event … liable for' waiver (v1.2.0)", () => {
    expect(fires("In no event shall Vendor be liable for any consequential damages.")).toBe(true);
    expect(fires("Under no circumstances shall Provider be liable for special damages.")).toBe(
      true,
    );
  });

  it("does not treat an 'in no event … liable for more than' cap as a damages waiver (v1.2.0)", () => {
    expect(
      fires(
        "In no event shall Vendor be liable for more than the fees paid in the prior twelve months.",
      ),
    ).toBe(false);
  });

  it("does not fire on an affirmative indemnity that ASSUMES the damage types (v1.2.0)", () => {
    expect(
      fires(
        "Tenant shall further indemnify Landlord for all direct, indirect and consequential damages arising from any holdover.",
      ),
    ).toBe(false);
    expect(
      fires(
        "Contractor shall indemnify Owner for all special, incidental, and consequential damages resulting from Contractor's breach.",
      ),
    ).toBe(false);
  });

  it("still fires on a waiver that merely references an indemnity carve-out (v1.2.0)", () => {
    expect(
      fires(
        "Except for its indemnification obligations, in no event shall Vendor be liable for indirect, incidental, or consequential damages.",
      ),
    ).toBe(true);
  });
});
