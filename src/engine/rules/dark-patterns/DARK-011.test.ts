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
