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

describe("RISK-009 — uncapped liability recognizes 'no limit on' & 'shall not be limited' (v1.1.0)", () => {
  const fires = (b: string) => !!RISK_009.check(buildContext(["Liability", b]) as any);

  it.each([
    "Each party's liability under this Agreement is unlimited.",
    "The Vendor shall have unlimited liability for data breaches.",
    "There shall be no limit on the Supplier's liability.",
    "The Contractor's liability shall not be limited in any way.",
  ])("fires on an uncapped-liability phrasing: %s", (b) => {
    expect(fires(b)).toBe(true);
  });

  it.each([
    "The Provider's liability is limited to the fees paid in the prior 12 months.",
    "In no event shall either party's liability exceed $1,000,000.",
    "Nothing in this Agreement shall limit or exclude the Provider's liability for death or personal injury caused by negligence.",
  ])("stays silent on a capped liability / statutory carve-out: %s", (b) => {
    expect(fires(b)).toBe(false);
  });
});
