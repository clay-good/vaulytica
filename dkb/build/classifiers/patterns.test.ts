import { describe, expect, it } from "vitest";
import { PATTERNS } from "./patterns.js";

describe("PATTERNS", () => {
  it("covers every category named in spec §26 step 11", () => {
    const required = [
      "governing-law",
      "indemnification",
      "limitation-of-liability",
      "confidentiality-obligation",
      "term",
      "termination-for-cause",
      "termination-for-convenience",
      "force-majeure",
      "assignment",
      "entire-agreement",
      "severability",
      "waiver",
      "notices",
      "counterparts",
    ];
    const have = new Set(PATTERNS.map((p) => p.category));
    for (const r of required) expect(have.has(r), r).toBe(true);
  });

  it("every pattern compiles as a regex with its flags", () => {
    for (const p of PATTERNS) {
      expect(() => new RegExp(p.pattern, p.flags), `${p.category}: ${p.pattern}`).not.toThrow();
    }
  });

  it("confidence values are within [0,1]", () => {
    for (const p of PATTERNS) {
      expect(p.confidence, p.category).toBeGreaterThan(0);
      expect(p.confidence, p.category).toBeLessThanOrEqual(1);
    }
  });

  it("the governing-law pattern matches a canonical clause", () => {
    const gl = PATTERNS.find((p) => p.category === "governing-law")!;
    const re = new RegExp(gl.pattern, gl.flags);
    expect(re.test("This Agreement shall be governed by and construed in accordance with the laws of the State of Delaware.")).toBe(true);
  });

  it("the force-majeure pattern matches both 'force majeure' and 'reasonable control' phrasing", () => {
    const fm = PATTERNS.filter((p) => p.category === "force-majeure");
    expect(fm.some((p) => new RegExp(p.pattern, p.flags).test("This is a Force Majeure event."))).toBe(true);
    expect(
      fm.some((p) =>
        new RegExp(p.pattern, p.flags).test(
          "Neither party shall be liable for delays beyond its reasonable control.",
        ),
      ),
    ).toBe(true);
  });
});
