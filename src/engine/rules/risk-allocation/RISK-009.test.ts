import { describe, expect, it } from "vitest";
import { rule as RISK_009 } from "./RISK-009.js";
import { buildContext } from "../../_test-fixtures.js";

describe("RISK-009 — uncapped liability", () => {
  it("fires on an uncapped-liability clause", () => {
    const ctx = buildContext([
      "Liability",
      "The Vendor shall have unlimited liability under this Agreement.",
    ]);
    const f = RISK_009.check(ctx);
    expect(f?.severity).toBe("critical");
  });

  // Regression: the excerpt used a document-absolute offset on paragraph-local
  // text, so a clause past the document's first ~240 chars shipped with an
  // EMPTY excerpt — no supporting text for this critical finding.
  it("carries the actual clause text as the excerpt even when it appears late", () => {
    const preamble =
      "This Agreement is entered into by the parties as of the Effective Date. ".repeat(6);
    const ctx = buildContext([
      "Liability",
      preamble +
        "The Provider shall be liable for all damages without any cap on liability arising from any breach.",
    ]);
    const f = RISK_009.check(ctx);
    expect(f).not.toBeNull();
    expect(f!.excerpt.text.length).toBeGreaterThan(0);
    expect(f!.excerpt.text.toLowerCase()).toContain("without any cap on liability");
  });
});
