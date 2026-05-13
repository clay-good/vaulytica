import { describe, expect, it } from "vitest";
import { rule as CHOICE_012 } from "./CHOICE-012.js";
import { buildContext } from "../../_test-fixtures.js";

describe("CHOICE-012 — governing-law / venue mismatch", () => {
  it("fires when governing law and venue name different jurisdictions", () => {
    const ctx = buildContext(
      ["14.1 Governing Law", "This Agreement shall be governed by the laws of the State of Delaware."],
      ["14.2 Jurisdiction", "The exclusive jurisdiction for any dispute shall be the state and federal courts located in New York."],
    );
    const finding = CHOICE_012.check(ctx);
    expect(finding).not.toBeNull();
    expect(finding?.severity).toBe("warning");
    expect(finding?.title).toMatch(/Delaware/);
    expect(finding?.title).toMatch(/New York/);
  });

  it("silent when governing law and venue name the same jurisdiction", () => {
    const ctx = buildContext(
      ["14.1 Governing Law", "This Agreement shall be governed by the laws of the State of Delaware."],
      ["14.2 Jurisdiction", "Exclusive jurisdiction shall be the state and federal courts of Delaware."],
    );
    expect(CHOICE_012.check(ctx)).toBeNull();
  });

  it("silent when no governing-law clause is present", () => {
    const ctx = buildContext(["X", "Exclusive jurisdiction shall be in New York."]);
    expect(CHOICE_012.check(ctx)).toBeNull();
  });

  it("silent when no venue clause is present", () => {
    const ctx = buildContext(["X", "This Agreement shall be governed by the laws of the State of Delaware."]);
    expect(CHOICE_012.check(ctx)).toBeNull();
  });

  it("tolerates 'Commonwealth of' / 'State of' phrasing on either side", () => {
    const ctx = buildContext(
      ["X", "This Agreement shall be governed by the laws of the Commonwealth of Massachusetts."],
      ["Y", "Exclusive jurisdiction shall be the courts of Massachusetts."],
    );
    expect(CHOICE_012.check(ctx)).toBeNull();
  });
});
