/**
 * DARK-013 flags a residential-lease waiver of non-waivable statutory tenant
 * rights. Pinned both ways: the catch-all / quiet-enjoyment / notice waiver
 * fires at critical, and an ordinary obligation, the negated 'shall not waive'
 * form, and a lawful specific waiver stay silent.
 */
import { describe, expect, it } from "vitest";
import { rule as DARK_013 } from "./DARK-013.js";
import { buildContext } from "../../_test-fixtures.js";

describe("DARK-013 — residential waiver of statutory tenant rights", () => {
  it("fires (critical) on a catch-all waiver of rights under the landlord-tenant act", () => {
    const f = DARK_013.check(
      buildContext([
        "Lease",
        "Tenant hereby waives all rights and remedies under the landlord-tenant act.",
      ]),
    );
    expect(f).not.toBeNull();
    expect(f?.severity).toBe("critical");
  });

  it("fires on a waiver of the covenant of quiet enjoyment or the right to notice", () => {
    expect(
      DARK_013.check(buildContext(["Lease", "Tenant waives the covenant of quiet enjoyment."])),
    ).not.toBeNull();
    expect(
      DARK_013.check(
        buildContext(["Lease", "Tenant waives any right to notice before termination."]),
      ),
    ).not.toBeNull();
  });

  it("stays silent on an ordinary obligation and the negated 'shall not waive' form", () => {
    expect(
      DARK_013.check(
        buildContext([
          "Lease",
          "Tenant shall keep the premises clean and notify Landlord of needed repairs.",
        ]),
      ),
    ).toBeNull();
    expect(
      DARK_013.check(
        buildContext(["Lease", "Tenant shall not waive any statutory rights under this Lease."]),
      ),
    ).toBeNull();
  });
});
