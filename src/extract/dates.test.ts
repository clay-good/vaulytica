import { describe, expect, it } from "vitest";
import { extractDates } from "./dates.js";
import { buildTree } from "./_fixtures.js";

describe("extractDates", () => {
  it("parses ISO, US numeric, and prose absolute dates", () => {
    const tree = buildTree([
      "Dates",
      "Effective on 2025-01-15. Renewable through 12/31/2026. Closed January 1, 2025.",
    ]);
    const dates = extractDates(tree);
    const isos = dates.filter((d) => d.type === "absolute").map((d) => d.iso);
    expect(isos).toContain("2025-01-15");
    expect(isos).toContain("2026-12-31");
    expect(isos).toContain("2025-01-01");
  });

  it("parses relative dates and resolves units to days", () => {
    const tree = buildTree([
      "Notice",
      "Either party may terminate this Agreement upon thirty (30) days after the Effective Date.",
    ]);
    const dates = extractDates(tree);
    const rel = dates.find((d) => d.type === "relative");
    expect(rel?.offset_days).toBe(30);
    expect(rel?.anchor).toMatch(/Effective Date/);
  });

  it("captures named anchors like 'the Effective Date'", () => {
    const tree = buildTree(["Body", "The Effective Date is the date of execution."]);
    const dates = extractDates(tree);
    expect(dates.some((d) => d.type === "named-anchor" && d.anchor === "Effective Date")).toBe(true);
  });

  it("flags impossible dates with no ISO (leaves iso undefined)", () => {
    const tree = buildTree(["Body", "On 2025-02-30 the parties shall meet."]);
    const dates = extractDates(tree);
    const found = dates.find((d) => d.raw_text === "2025-02-30");
    expect(found?.iso).toBeUndefined();
  });

  it("captures broadened anchor aliases (Commencement, Term Start, Date Hereof)", () => {
    const tree = buildTree([
      "Term",
      "This begins on the Commencement Date and ends per the Term Start Date, as of the Date Hereof.",
    ]);
    const anchors = extractDates(tree)
      .filter((d) => d.type === "named-anchor")
      .map((d) => d.anchor);
    expect(anchors).toContain("Commencement Date");
    expect(anchors).toContain("Term Start Date");
    expect(anchors).toContain("Date Hereof");
  });

  it("decomposes disjunctive range deadlines into lower and upper bounds", () => {
    const tree = buildTree([
      "Notice",
      "The party shall respond within thirty to sixty days after the Effective Date.",
    ]);
    const range = extractDates(tree).find((d) => d.offset_days_max !== undefined);
    expect(range?.offset_days).toBe(30);
    expect(range?.offset_days_max).toBe(60);
    expect(range?.anchor).toMatch(/Effective Date/);
  });

  it("does not double-count a range as a separate single-bound relative date", () => {
    const tree = buildTree([
      "Notice",
      "The party shall respond within 30 to 60 days after the Effective Date.",
    ]);
    const rel = extractDates(tree).filter((d) => d.type === "relative");
    expect(rel).toHaveLength(1);
    expect(rel[0]?.offset_days_max).toBe(60);
  });

  it("converts units to days and signs 'before' offsets negative", () => {
    const weeks = extractDates(buildTree(["Notice", "Pay within two weeks after the Effective Date."]));
    expect(weeks.find((d) => d.type === "relative")?.offset_days).toBe(14);
    const months = extractDates(buildTree(["Notice", "Pay within three months after the Effective Date."]));
    expect(months.find((d) => d.type === "relative")?.offset_days).toBe(90);
    const years = extractDates(buildTree(["Notice", "Renew one year after the Effective Date."]));
    expect(years.find((d) => d.type === "relative")?.offset_days).toBe(365);
    const before = extractDates(buildTree(["Notice", "Notify sixty (60) days before the Termination Date."]));
    expect(before.find((d) => d.type === "relative")?.offset_days).toBe(-60);
  });

  it("keeps range bounds ordered low→high and converts the unit", () => {
    const range = extractDates(
      buildTree(["Notice", "Respond within two to three weeks after the Effective Date."]),
    ).find((d) => d.offset_days_max !== undefined);
    expect(range?.offset_days).toBe(14);
    expect(range?.offset_days_max).toBe(21);
  });

  it("captures fiscal periods with a normalized label and no iso", () => {
    const tree = buildTree([
      "Payment",
      "Payment is due in fiscal Q2 2025 and reconciled by FY2025-Q3 and FY 2026.",
    ]);
    const fiscal = extractDates(tree).filter((d) => d.type === "fiscal-period");
    const labels = fiscal.map((d) => d.fiscal_period);
    expect(labels).toContain("FY2025-Q2");
    expect(labels).toContain("FY2025-Q3");
    expect(labels).toContain("FY2026");
    expect(fiscal.every((d) => d.iso === undefined)).toBe(true);
  });

  it("does not catastrophically backtrack on a long Unicode-whitespace run (ReDoS guard)", () => {
    // The RELATIVE / RANGE_RELATIVE numeral chain previously used four adjacent
    // unbounded `\s*`; `\s` matches NBSP (U+00A0), which `normalize` does not
    // collapse (it folds only `[ \t\r\n]`), so a crafted run of NBSPs caused
    // polynomial backtracking. Bounded whitespace makes the match linear; under
    // the old pattern this input would not complete (the test would time out).
    const nbsp = String.fromCharCode(0xa0); // U+00A0 — survives `normalize`
    const evil = "due within " + nbsp.repeat(5000) + "days after X";
    const t0 = performance.now();
    const out = extractDates(buildTree(["Notice", evil]));
    expect(performance.now() - t0).toBeLessThan(1000);
    expect(Array.isArray(out)).toBe(true);
  });
});
