/**
 * DARK-011 flags a residential self-help eviction / lockout clause — void in
 * nearly every state. Both directions pinned: the self-help remedy fires at
 * critical, the lawful-judicial-process remedy stays silent.
 */
import { describe, expect, it } from "vitest";
import { rule as DARK_011 } from "./DARK-011.js";
import { buildContext } from "../../_test-fixtures.js";

describe("DARK-011 — residential self-help eviction / lockout", () => {
  it("fires (critical) on a lockout / belongings-removal clause", () => {
    const f = DARK_011.check(
      buildContext([
        "Lease",
        "Landlord may change the locks and remove the tenant without notice.",
      ]),
    );
    expect(f).not.toBeNull();
    expect(f?.severity).toBe("critical");
  });

  it("fires on a utility-shutoff self-help remedy", () => {
    expect(
      DARK_011.check(
        buildContext(["Lease", "Landlord may shut off the utilities if rent is late."]),
      ),
    ).not.toBeNull();
  });

  it("stays silent when possession is retaken through the judicial process", () => {
    expect(
      DARK_011.check(
        buildContext([
          "Lease",
          "Landlord may take possession only in accordance with applicable law through judicial eviction proceedings.",
        ]),
      ),
    ).toBeNull();
  });

  it("stays silent on an ordinary landlord obligation", () => {
    expect(
      DARK_011.check(
        buildContext(["Lease", "Landlord shall maintain the premises in good repair."]),
      ),
    ).toBeNull();
  });
});

describe("DARK-011 — additional self-help actions (v1.1.0)", () => {
  const fires = (t: string) => DARK_011.check(buildContext(["Lease", t])) !== null;

  it.each([
    "Landlord may disconnect the utilities if rent is unpaid.",
    "Landlord may cut off the utilities to the unit.",
    "Landlord reserves the right to padlock the premises.",
    "Landlord may seize the tenant's belongings for unpaid rent.",
    "Landlord may distrain upon the tenant's goods for rent due.",
  ])("fires on an additional self-help remedy: %s", (t) => {
    expect(fires(t)).toBe(true);
  });

  it.each([
    "Landlord may recover possession only through the applicable judicial eviction process.",
    "Landlord may take possession in accordance with applicable law.",
    "Landlord shall not change the locks or shut off utilities.",
    "Tenant may change the locks and provide Landlord a key.",
  ])("stays silent on a lawful / negated / tenant-side clause: %s", (t) => {
    expect(fires(t)).toBe(false);
  });
});
