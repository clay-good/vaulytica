import { describe, expect, it } from "vitest";
import { rule as OBLI_007 } from "./OBLI-007.js";
import { buildContext } from "../../_test-fixtures.js";

describe("OBLI-007 — Material Adverse Change clause", () => {
  it("fires on `material adverse change`", () => {
    const ctx = buildContext([
      "Conditions",
      "Closing is conditioned on the absence of any material adverse change in the business between signing and closing.",
    ]);
    expect(OBLI_007.check(ctx)?.severity).toBe("warning");
  });

  it("fires on `material adverse effect`", () => {
    const ctx = buildContext([
      "Reps",
      "Each representation must remain true except where the breach would not result in a material adverse effect.",
    ]);
    expect(OBLI_007.check(ctx)).not.toBeNull();
  });

  it("fires on `MAC event`", () => {
    const ctx = buildContext(["H", "A MAC event entitles either party to terminate immediately."]);
    expect(OBLI_007.check(ctx)).not.toBeNull();
  });

  it("is silent when no MAC language is present", () => {
    const ctx = buildContext(["Indemnity", "Each party shall indemnify the other for third-party claims."]);
    expect(OBLI_007.check(ctx)).toBeNull();
  });

  it("is silent on the unrelated word `material` alone", () => {
    const ctx = buildContext(["H", "Material breach by either party shall give rise to termination."]);
    expect(OBLI_007.check(ctx)).toBeNull();
  });
});
