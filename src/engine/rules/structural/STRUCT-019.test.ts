import { describe, expect, it } from "vitest";
import { rule as STRUCT_019 } from "./STRUCT-019.js";
import { buildContext } from "../../_test-fixtures.js";

describe("STRUCT-019 — recited formality without a fillable block", () => {
  it("fires when notarization is recited but no notary block is present", () => {
    const ctx = buildContext([
      "Execution",
      "This instrument shall be notarized by each party. By: ____ Name: ____ Title: ____",
    ]);
    const f = STRUCT_019.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/notar/i);
  });

  it("stays silent when a notary acknowledgment block is present", () => {
    const ctx = buildContext(
      ["Execution", "This instrument shall be notarized by each party."],
      [
        "Acknowledgment",
        "Subscribed and sworn to before me this ___ day of ______, 2026. Notary Public, State of Delaware. My Commission Expires: ______.",
      ],
    );
    expect(STRUCT_019.check(ctx)).toBeNull();
  });

  it("fires when witnessing is recited but no witness block is present", () => {
    const ctx = buildContext([
      "Execution",
      "This Agreement shall be executed in the presence of the undersigned witnesses. By: ____ Name: ____",
    ]);
    const f = STRUCT_019.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.title).toMatch(/witness/i);
  });

  it("stays silent when a witness block is present", () => {
    const ctx = buildContext(
      [
        "Execution",
        "This Agreement shall be executed in the presence of the undersigned witnesses.",
      ],
      ["Witnesses", "Witness 1: ______  Name of Witness: ______\nWitness 2: ______"],
    );
    expect(STRUCT_019.check(ctx)).toBeNull();
  });

  it("stays silent when no formality is recited", () => {
    const ctx = buildContext(["Body", "The parties agree to the terms set forth above."]);
    expect(STRUCT_019.check(ctx)).toBeNull();
  });
});
