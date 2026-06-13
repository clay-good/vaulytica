import { describe, expect, it } from "vitest";
import { rule as STRUCT_018 } from "./STRUCT-018.js";
import { buildContext } from "../../_test-fixtures.js";

describe("STRUCT-018 — attachment completeness", () => {
  it("fires when a referenced exhibit is not present", () => {
    const ctx = buildContext([
      "Body",
      "The Services are described in Exhibit A. Pricing is set forth in Exhibit C.",
    ]);
    const f = STRUCT_018.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.severity).toBe("warning");
    expect(f?.description).toMatch(/Exhibit A/);
    expect(f?.description).toMatch(/Exhibit C/);
  });

  it("stays silent when every referenced attachment is present as a heading", () => {
    const ctx = buildContext(
      ["Body", "The Services are described in Exhibit A."],
      ["Exhibit A — Services", "The Provider will deliver the following services in detail."],
    );
    expect(STRUCT_018.check(ctx)).toBeNull();
  });

  it("treats an in-paragraph title line as presence", () => {
    const ctx = buildContext(
      ["Body", "Pricing is set forth in Schedule 2."],
      ["Appendix", "Schedule 2 — Pricing\nThe fees are $1,000 per month for the duration of the term."],
    );
    expect(STRUCT_018.check(ctx)).toBeNull();
  });

  it("stays silent when no attachment is referenced", () => {
    const ctx = buildContext(["Body", "This Agreement contains all terms between the parties."]);
    expect(STRUCT_018.check(ctx)).toBeNull();
  });

  it("reports only the absent one when one of two is present", () => {
    const ctx = buildContext(
      ["Body", "See Exhibit A for services and Exhibit B for pricing."],
      ["Exhibit A — Services", "The detailed scope of services to be provided under this Agreement."],
    );
    const f = STRUCT_018.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.description).toMatch(/Exhibit B/);
    expect(f?.title).toMatch(/not present: 1/);
  });
});
