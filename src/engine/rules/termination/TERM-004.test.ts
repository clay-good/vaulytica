import { describe, expect, it } from "vitest";
import { rule as TERM_004 } from "./TERM-004.js";
import { buildContext } from "../../_test-fixtures.js";

describe("TERM-004 — termination-notice form", () => {
  const fires = (b: string) => !!TERM_004.check(buildContext(["Termination", b]) as never);

  it.each([
    "Notice of termination shall be in writing.",
    "Any termination notice shall be given in writing.",
    "Written notice of termination must be delivered by certified mail.",
    "Notice of termination may be provided by email to the other party.",
  ])("surfaces the notice-of-termination / termination-notice form: %s", (b) => {
    expect(fires(b)).toBe(true);
  });

  it("stays silent when the notice need not be in writing", () => {
    expect(fires("Notice of termination need not be in writing and may be oral.")).toBe(false);
  });

  it("emits an info-severity finding", () => {
    expect(
      TERM_004.check(
        buildContext(["Termination", "Any termination notice shall be in writing."]) as never,
      )?.severity,
    ).toBe("info");
  });
});
