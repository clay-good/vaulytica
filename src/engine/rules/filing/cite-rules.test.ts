import { describe, expect, it } from "vitest";
import type { RuleContext } from "../../finding.js";
import { buildContext } from "../../_test-fixtures.js";
import { CITE_001, CITE_002, CITE_003, CITE_004, CITE_005, CITE_RULES } from "./cite-rules.js";

function briefCtx(sections: [string, ...string[]][]): RuleContext {
  const ctx = buildContext(...sections);
  ctx.playbook = { id: "appellate-brief", version: "1.0.0" };
  return ctx;
}

describe("CITE pack gating", () => {
  it("every CITE rule declares the filing-playbook gate", () => {
    for (const r of CITE_RULES) expect(r.applies_to_playbooks, r.id).toContain("appellate-brief");
  });
});

describe("CITE-001 malformed citation", () => {
  it("flags a citation-shaped reference with an unknown reporter", () => {
    const ctx = briefCtx([["ARGUMENT", "As held in 123 Fake Rep. 45, the rule applies."]]);
    const f = CITE_001.check(ctx)!;
    expect(f.severity).toBe("warning");
    expect(f.description).toMatch(/Fake Rep/);
  });

  it("is silent on a well-formed citation", () => {
    const ctx = briefCtx([["ARGUMENT", "See 410 U.S. 113 (1973)."]]);
    expect(CITE_001.check(ctx)).toBeNull();
  });
});

describe("CITE-002 orphaned id.", () => {
  it("flags an id. with no antecedent in its section", () => {
    const ctx = briefCtx([["ARGUMENT", "Id. at 5 shows the point."]]);
    const f = CITE_002.check(ctx)!;
    expect(f.title).toMatch(/orphaned/i);
  });

  it("is silent when a citation precedes the id.", () => {
    const ctx = briefCtx([["ARGUMENT", "See 410 U.S. 113. Id. at 120."]]);
    expect(CITE_002.check(ctx)).toBeNull();
  });
});

describe("CITE-003 dangling supra / short form", () => {
  it("flags a supra whose authority was never cited in full", () => {
    const ctx = briefCtx([["ARGUMENT", "As explained in Marbury, supra, the statute fails."]]);
    const f = CITE_003.check(ctx)!;
    expect(f.title).toMatch(/dangling/i);
  });

  it("is silent when the authority was introduced first", () => {
    const ctx = briefCtx([
      ["ARGUMENT", "See Roe v. Wade, 410 U.S. 113 (1973). Later, Roe, supra, controls."],
    ]);
    expect(CITE_003.check(ctx)).toBeNull();
  });
});

describe("CITE-004 TOA reconciliation", () => {
  it("returns null when there is no table of authorities", () => {
    const ctx = briefCtx([["ARGUMENT", "See 410 U.S. 113."]]);
    expect(CITE_004.check(ctx)).toBeNull();
  });

  it("flags an authority cited in the body but absent from the table", () => {
    const ctx = briefCtx([
      ["TABLE OF AUTHORITIES", "Cases: 999 F.3d 1 ... 3"],
      ["ARGUMENT", "The controlling case is 410 U.S. 113, which is dispositive."],
    ]);
    const f = CITE_004.check(ctx)!;
    expect(f.title).toMatch(/does not reconcile/i);
    expect(f.source_citations.some((c) => /28\(a\)\(3\)/.test(c.source))).toBe(true);
  });
});

describe("CITE-005 inconsistent short forms", () => {
  it("flags an authority short-cited by both party names", () => {
    const ctx = briefCtx([
      ["ARGUMENT", "See Roe v. Wade, 410 U.S. 113. Roe, supra. But Wade, supra, says otherwise."],
    ]);
    const f = CITE_005.check(ctx)!;
    expect(f.title).toMatch(/[Ii]nconsistent short form/);
  });
});

describe("a clean brief produces no CITE findings", () => {
  it("all rules silent", () => {
    const ctx = briefCtx([
      ["TABLE OF AUTHORITIES", "Roe v. Wade, 410 U.S. 113 ... 2"],
      ["ARGUMENT", "See Roe v. Wade, 410 U.S. 113 (1973). Id. at 120. Roe, supra, controls here."],
    ]);
    for (const r of CITE_RULES) expect(r.check(ctx), r.id).toBeNull();
  });
});
