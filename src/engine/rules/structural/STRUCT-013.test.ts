import { describe, expect, it } from "vitest";
import { rule as STRUCT_013 } from "./STRUCT-013.js";
import { buildContext } from "../../_test-fixtures.js";

describe("STRUCT-013 — unfilled template placeholders", () => {
  it("fires on [insert party name]", () => {
    const ctx = buildContext([
      "Agreement",
      `This Agreement is entered into between [insert party name], a Delaware corporation, and Beta LLC.`,
    ]);
    const f = STRUCT_013.check(ctx);
    expect(f?.severity).toBe("critical");
    expect(f?.title).toMatch(/Unfilled template placeholders: \d+/);
  });

  it("fires on [Customer Name] Title-Case placeholder", () => {
    const ctx = buildContext(["H", "Customer: [Customer Name]"]);
    expect(STRUCT_013.check(ctx)).not.toBeNull();
  });

  it("fires on [TBD], [REDACTED], [PLACEHOLDER]", () => {
    expect(STRUCT_013.check(buildContext(["H", "Renewal term: [TBD]"]))).not.toBeNull();
    expect(STRUCT_013.check(buildContext(["H", "Salary: [REDACTED]"]))).not.toBeNull();
    expect(STRUCT_013.check(buildContext(["H", "Term: [PLACEHOLDER]"]))).not.toBeNull();
  });

  it("fires on {{mustache}} placeholders", () => {
    const ctx = buildContext(["H", "Effective as of {{effective_date}}."]);
    expect(STRUCT_013.check(ctx)).not.toBeNull();
  });

  it("fires on <<angle>> placeholders", () => {
    const ctx = buildContext(["H", "Party A: <<COUNTERPARTY>>"]);
    expect(STRUCT_013.check(ctx)).not.toBeNull();
  });

  it("fires on long underscore lines and XXX placeholders", () => {
    expect(STRUCT_013.check(buildContext(["H", "Signed: __________________"]))).not.toBeNull();
    expect(
      STRUCT_013.check(buildContext(["H", "Order number XXXX from supplier."])),
    ).not.toBeNull();
  });

  it("silent on bracketed footnotes like [1] or [a]", () => {
    const ctx = buildContext(["H", "See note [1] and item [a] for details."]);
    expect(STRUCT_013.check(ctx)).toBeNull();
  });

  it("silent on a clean Common-Paper-shaped clause", () => {
    const ctx = buildContext([
      "Confidentiality",
      `Recipient shall protect Discloser's Confidential Information using the same degree of care it uses to protect its own confidential information of like importance.`,
    ]);
    expect(STRUCT_013.check(ctx)).toBeNull();
  });

  it("counts multiple placeholders", () => {
    const ctx = buildContext([
      "H",
      `Effective Date: [insert date]. Customer: [insert name]. Term: [TBD].`,
    ]);
    const f = STRUCT_013.check(ctx);
    expect(f?.title).toMatch(/\b3\b/);
  });
});
