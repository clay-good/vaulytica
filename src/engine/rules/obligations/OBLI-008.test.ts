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
      [
        "Definitions",
        `"Best efforts" means obtaining all consents, devoting professional staff, and absorbing reasonable costs but not requiring litigation.`,
      ],
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

  // v1.1.0 — a definition is introduced in several standard ways; the check
  // recognized only "means" / "shall mean" / "is defined as", so an efforts
  // standard defined via "has the meaning …" / "refers to …" was falsely
  // flagged as undefined.
  it("is silent when the efforts standard is defined via 'has the meaning'", () => {
    const ctx = buildContext(
      ["Definitions", `"Best Efforts" has the meaning set forth in Section 8.3 of this Agreement.`],
      ["Performance", "Vendor shall use best efforts to provide the Service."],
    );
    expect(OBLI_008.check(ctx)).toBeNull();
  });

  it("is silent when the efforts standard is defined via 'shall have the meaning' / 'refers to'", () => {
    const withShallHave = buildContext(
      [
        "Definitions",
        `"Commercially Reasonable Efforts" shall have the meaning given in Schedule A.`,
      ],
      ["Performance", "Provider shall use commercially reasonable efforts to maintain uptime."],
    );
    expect(OBLI_008.check(withShallHave)).toBeNull();

    const withRefersTo = buildContext(
      ["Definitions", `"Reasonable Efforts" refers to the standard described in Exhibit 2.`],
      ["Cooperation", "Each party agrees to use reasonable efforts to fulfill its obligations."],
    );
    expect(OBLI_008.check(withRefersTo)).toBeNull();
  });
});
