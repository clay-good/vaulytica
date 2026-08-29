import { describe, expect, it } from "vitest";
import { rule as RISK_006 } from "./RISK-006.js";
import { buildContext } from "../../_test-fixtures.js";

describe("RISK-006 — a carve-out list that cites the sections it excepts", () => {
  // "Except for the INDEMNITY OBLIGATIONS in Sections 8.1 and 8.2, breach of
  // Section 9, and a party's gross negligence or WILLFUL MISCONDUCT, neither
  // party's aggregate liability shall exceed…" — a bare `[^.;\n]` window
  // stopped at the "8.1", so every carve-out after the first citation was
  // invisible, and the `indemnif` stem does not match "indemnity".
  it("reads past a section citation and recognizes the noun 'indemnity'", () => {
    const f = RISK_006.check(
      buildContext([
        "Liability",
        "8.5 Limitation of Liability. Except for the indemnity obligations in Sections 8.1 and 8.2, breach of Section 9, and a party's gross negligence or willful misconduct, neither party's aggregate liability under this Agreement shall exceed the amounts paid in the twelve months preceding the claim.",
      ]),
    );
    expect(f).not.toBeNull();
    expect(f?.description).toContain("willful misconduct");
    expect(f?.description).toContain("indemnification");
  });
});
