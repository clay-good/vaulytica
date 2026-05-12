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
});
