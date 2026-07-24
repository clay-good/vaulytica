/**
 * DARK-010 flags a residential-lease term that waives the non-waivable implied
 * warranty of habitability (or relieves the landlord of the duty to keep the
 * premises habitable). Both directions are pinned: the void waiver fires at
 * critical, and the compliant landlord-repair / carve-out forms stay silent.
 */
import { describe, expect, it } from "vitest";
import { rule as DARK_010 } from "./DARK-010.js";
import { buildContext } from "../../_test-fixtures.js";

describe("DARK-010 — residential waiver of the warranty of habitability", () => {
  it("fires (critical) on an express habitability waiver", () => {
    const f = DARK_010.check(
      buildContext(["Lease", "Tenant hereby waives the implied warranty of habitability."]),
    );
    expect(f).not.toBeNull();
    expect(f?.severity).toBe("critical");
  });

  it("fires when the landlord is relieved of the duty to repair to a habitable condition", () => {
    expect(
      DARK_010.check(
        buildContext([
          "Lease",
          "Tenant accepts the premises as-is, and Landlord has no obligation to repair or maintain the unit.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("stays silent on a compliant landlord-repair obligation", () => {
    expect(
      DARK_010.check(
        buildContext([
          "Lease",
          "Landlord shall maintain the premises in habitable condition and make all necessary repairs.",
        ]),
      ),
    ).toBeNull();
  });

  it("stays silent on an 'as-is' acceptance carved out 'except as required by law'", () => {
    expect(
      DARK_010.check(
        buildContext(["Lease", "Tenant accepts the premises as-is, except as required by law."]),
      ),
    ).toBeNull();
  });

  it("stays silent on a clause that preserves the tenant's habitability right", () => {
    expect(
      DARK_010.check(
        buildContext(["Lease", "Tenant shall not waive any right to a habitable premises."]),
      ),
    ).toBeNull();
  });
});
