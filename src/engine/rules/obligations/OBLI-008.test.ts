import { describe, expect, it } from "vitest";
import { rule as OBLI_008 } from "./OBLI-008.js";
import { buildContext } from "../../_test-fixtures.js";

describe("OBLI-008 — efforts standard undefined", () => {
  it("fires on `best efforts` with no in-document definition", () => {
    const ctx = buildContext([
      "Performance",
      "Vendor shall use best efforts to provide the Service.",
    ]);
    const f = OBLI_008.check(ctx);
    expect(f?.severity).toBe("info");
    expect(f?.title).toMatch(/best efforts.*undefined/i);
  });

  it("fires on `commercially reasonable efforts`", () => {
    const ctx = buildContext([
      "Performance",
      "Provider shall use commercially reasonable efforts to maintain uptime.",
    ]);
    expect(OBLI_008.check(ctx)).not.toBeNull();
  });

  it("fires on `reasonable efforts`", () => {
    const ctx = buildContext([
      "Cooperation",
      "Each party agrees to use reasonable efforts to fulfill its obligations.",
    ]);
    expect(OBLI_008.check(ctx)).not.toBeNull();
  });

  it("is silent when `best efforts` is defined in the document", () => {
    const ctx = buildContext(
      ["Definitions", `"Best efforts" means obtaining all consents, devoting professional staff, and absorbing reasonable costs but not requiring litigation.`],
      ["Performance", "Vendor shall use best efforts to provide the Service."],
    );
    expect(OBLI_008.check(ctx)).toBeNull();
  });

  it("is silent when no efforts language is present", () => {
    const ctx = buildContext([
      "Performance",
      "Vendor shall provide the Service in accordance with this Agreement.",
    ]);
    expect(OBLI_008.check(ctx)).toBeNull();
  });
});
