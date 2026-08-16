/**
 * PERS-002 detects a non-solicit clause. v1.1.0 widens the protected object
 * beyond employees/customers to clients / personnel / staff, and reads the
 * "agrees NOT TO solicit" form — while keeping a procurement "not solicit bids
 * from vendors" clause out (vendors/suppliers are deliberately excluded).
 */
import { describe, expect, it } from "vitest";
import { rule as PERS_002 } from "./PERS-002.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (s: string) => PERS_002.check(buildContext(["Non-Solicitation", s])) !== null;

describe("PERS-002 — non-solicit present", () => {
  it("fires on the 'Non-Solicitation' label and the employees object", () => {
    expect(fires("Section 8. Non-Solicitation. This section survives termination.")).toBe(true);
    expect(fires("Executive shall not solicit any employees of the Company.")).toBe(true);
  });

  it("reads the clients / personnel / staff objects and the 'agrees not to solicit' form (v1.1.0)", () => {
    expect(fires("Executive shall not solicit any client of the Company.")).toBe(true);
    expect(fires("Contractor agrees not to solicit any customers or clients of the Company.")).toBe(
      true,
    );
    expect(fires("Employee shall not induce any personnel to leave the Company.")).toBe(true);
    expect(fires("Executive shall not solicit members of the Company's staff.")).toBe(true);
  });

  it("does not fire on a procurement 'not solicit bids from vendors/suppliers' clause (v1.1.0)", () => {
    expect(
      fires("The Company shall not solicit bids from unqualified vendors for the cafeteria."),
    ).toBe(false);
    expect(
      fires("Buyer agrees not to solicit proposals from suppliers outside the approved list."),
    ).toBe(false);
  });
});
