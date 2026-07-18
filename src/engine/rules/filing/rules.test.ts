import { describe, expect, it } from "vitest";
import type { RuleContext } from "../../finding.js";
import { buildContext } from "../../_test-fixtures.js";
import { getCourtProfile } from "../../../filing/court-profile.js";
import { FILING_OPTIONS_KEY, type FilingRunOptions } from "../../../filing/run-options.js";
import { FILE_001, FILE_002, FILE_003, FILE_006, FILING_RULES } from "./rules.js";

const FRAP = getCourtProfile("frap-default")!;

function briefCtx(
  filing: Partial<FilingRunOptions> | null,
  sections: [string, ...string[]][] = [["BRIEF FOR APPELLANT", "The court erred."]],
): RuleContext {
  const ctx = buildContext(...sections);
  ctx.playbook = { id: "appellate-brief", version: "1.0.0" };
  if (filing) {
    const opts: FilingRunOptions = {
      profile: FRAP,
      brief_kind: "principal",
      word_count: 100,
      source: "docx",
      ...filing,
    };
    ctx.options = { [FILING_OPTIONS_KEY]: opts };
  }
  return ctx;
}

describe("FILE pack dormancy", () => {
  it("every FILE rule returns null with no filing options (no --court)", () => {
    const ctx = briefCtx(null);
    for (const rule of FILING_RULES) expect(rule.check(ctx), rule.id).toBeNull();
  });

  it("every FILE rule declares the filing-playbook gate", () => {
    for (const rule of FILING_RULES) {
      expect(rule.applies_to_playbooks, rule.id).toContain("appellate-brief");
    }
  });
});

describe("FILE-001 type-volume", () => {
  it("fires critical when the post-exclusion count exceeds the limit", () => {
    const ctx = briefCtx({ word_count: 20000 });
    const f = FILE_001.check(ctx)!;
    expect(f.severity).toBe("critical");
    expect(f.title).toMatch(/Over the 13,000-word limit/);
    expect(f.source_citations[0]!.source).toMatch(/32\(a\)\(7\)\(B\)\(i\)/);
  });

  it("reports an informational margin note when under the limit", () => {
    const ctx = briefCtx({ word_count: 5000 });
    const f = FILE_001.check(ctx)!;
    expect(f.severity).toBe("info");
    expect(f.explanation).toMatch(/word-processing software count governs/);
  });

  it("downgrades to a warning when excludable blocks exist but cannot be isolated (audit)", () => {
    // Single-section text ingest: the ToA shares the (over-cap) section with
    // the body, so nothing can be subtracted — a compliant brief with a big
    // ToA was branded critical over-limit. The honest verdict is a warning.
    const filler = Array.from({ length: 700 }, (_, i) => `word${i}`).join(" ");
    const ctx = briefCtx({ word_count: 13500 }, [
      ["BRIEF FOR APPELLANT", `TABLE OF AUTHORITIES\nSmith v. Jones ... 4\n${filler}`],
    ]);
    const f = FILE_001.check(ctx)!;
    expect(f.severity).toBe("warning");
    expect(f.title).toMatch(/could not be isolated/);
    expect(f.recommendation).toMatch(/cannot confirm a violation/);
  });
});

describe("FILE-002 page limit", () => {
  it("reports pages unmeasurable for a DOCX", () => {
    const ctx = briefCtx({ source: "docx", page_count: undefined });
    const f = FILE_002.check(ctx)!;
    expect(f.severity).toBe("info");
    expect(f.title).toMatch(/not measurable/i);
  });

  it("fires critical for a PDF over the page limit", () => {
    const ctx = briefCtx({ source: "pdf", page_count: 40 });
    const f = FILE_002.check(ctx)!;
    expect(f.severity).toBe("critical");
    expect(f.title).toMatch(/Over the 30-page limit/);
  });
});

describe("FILE presence checks", () => {
  it("FILE-003 fires a warning when the certificate of compliance is absent", () => {
    const ctx = briefCtx({}, [["BRIEF FOR APPELLANT", "No certificate here."]]);
    const f = FILE_003.check(ctx)!;
    expect(f.severity).toBe("warning");
    expect(f.title).toMatch(/not detected/);
    expect(f.source_citations[0]!.source).toMatch(/32\(g\)/);
  });

  it("FILE-006 reports the table of authorities as found when present", () => {
    const ctx = briefCtx({}, [
      ["BRIEF FOR APPELLANT", "text"],
      ["TABLE OF AUTHORITIES", "Cases"],
    ]);
    const f = FILE_006.check(ctx)!;
    expect(f.severity).toBe("info");
    expect(f.title).toMatch(/found/);
  });

  it("a rule returns null when the profile does not require its block", () => {
    // cal-rules-8.204 does not require a certificate of service.
    const cal = getCourtProfile("cal-rules-8.204")!;
    const ctx = briefCtx({ profile: cal });
    // FILE-004 checks certificate-of-service; not required by this profile.
    const file004 = FILING_RULES.find((r) => r.id === "FILE-004")!;
    expect(file004.check(ctx)).toBeNull();
  });
});
