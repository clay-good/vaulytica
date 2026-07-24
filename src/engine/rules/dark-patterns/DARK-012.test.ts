/**
 * DARK-012 flags a residential security-deposit forfeiture / non-return term —
 * void in most states. Pinned both ways: forfeiture / non-refundable-deposit
 * fires, while a lawful itemized return and a separately-labeled non-refundable
 * pet/cleaning fee stay silent.
 */
import { describe, expect, it } from "vitest";
import { rule as DARK_012 } from "./DARK-012.js";
import { buildContext } from "../../_test-fixtures.js";

describe("DARK-012 — residential security-deposit forfeiture / non-return", () => {
  it("fires on a non-refundable / forfeited security deposit", () => {
    expect(
      DARK_012.check(buildContext(["Lease", "The security deposit is non-refundable."])),
    ).not.toBeNull();
    expect(
      DARK_012.check(
        buildContext([
          "Lease",
          "Upon any breach, the security deposit shall be forfeited in full.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("fires on a non-refundable pet DEPOSIT (a deposit cannot be non-refundable)", () => {
    expect(
      DARK_012.check(
        buildContext(["Lease", "Tenant shall pay a non-refundable pet deposit of $750."]),
      ),
    ).not.toBeNull();
  });

  it("fires when the tenant waives the itemized-return right", () => {
    expect(
      DARK_012.check(
        buildContext([
          "Lease",
          "Tenant waives any right to an itemized statement of deductions from the deposit.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("stays silent on a lawful itemized return within the statutory period", () => {
    expect(
      DARK_012.check(
        buildContext([
          "Lease",
          "The security deposit will be returned within 21 days less any itemized deductions.",
        ]),
      ),
    ).toBeNull();
  });

  it("stays silent on a separately-labeled non-refundable pet fee", () => {
    expect(
      DARK_012.check(
        buildContext([
          "Lease",
          "A non-refundable pet fee of $200 applies, separate from the security deposit.",
        ]),
      ),
    ).toBeNull();
  });
});
