import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  deriveDate,
  resolveAnchors,
  buildCriticalDates,
  type CriticalDateKind,
} from "./critical-dates.js";
import type { DateReference } from "../extract/types.js";
import { buildTree } from "../extract/_fixtures.js";
import { extractAll } from "../extract/index.js";
import { buildCriticalDatesMarkdown, buildCriticalDatesIcs } from "./exports.js";

/** Minimal relative DateReference builder. */
function rel(
  anchor: string,
  unit: DateReference["offset_unit"],
  count: number,
  extra: Partial<DateReference> = {},
): DateReference {
  return {
    id: "d1",
    type: "relative",
    raw_text: `${Math.abs(count)} ${unit} ${count < 0 ? "before" : "after"} the ${anchor}`,
    anchor,
    offset_unit: unit,
    offset_count: count,
    offset_days: count, // approximate; derivation prefers unit+count
    position: { section_id: "s1", start: 0, end: 10 },
    ...extra,
  };
}

describe("deriveDate — the arithmetic (spec-v9 §25, companion §3)", () => {
  it("adds and subtracts calendar days", () => {
    expect(deriveDate(rel("Effective Date", "days", 30), "2025-01-01").computed_date).toBe(
      "2025-01-31",
    );
    expect(deriveDate(rel("Termination Date", "days", -60), "2025-12-31").computed_date).toBe(
      "2025-11-01",
    );
  });

  it("adds weeks as 7-day multiples", () => {
    expect(deriveDate(rel("Effective Date", "weeks", 2), "2025-01-01").computed_date).toBe(
      "2025-01-15",
    );
  });

  it("clamps month-end: Jan 31 + 1 month = Feb 28 (non-leap)", () => {
    expect(deriveDate(rel("Effective Date", "months", 1), "2025-01-31").computed_date).toBe(
      "2025-02-28",
    );
  });

  it("clamps month-end into a leap February: Jan 31 + 1 month = Feb 29 (2024)", () => {
    expect(deriveDate(rel("Effective Date", "months", 1), "2024-01-31").computed_date).toBe(
      "2024-02-29",
    );
  });

  it("subtracts months with clamp: Mar 31 − 1 month = Feb 28", () => {
    expect(deriveDate(rel("Effective Date", "months", -1), "2025-03-31").computed_date).toBe(
      "2025-02-28",
    );
  });

  it("adds years and clamps Feb 29 → Feb 28 off a leap year", () => {
    expect(deriveDate(rel("Effective Date", "years", 1), "2024-02-29").computed_date).toBe(
      "2025-02-28",
    );
    expect(deriveDate(rel("Effective Date", "years", 3), "2025-01-01").computed_date).toBe(
      "2028-01-01",
    );
  });

  it("marks an unresolved anchor unresolved — never guesses", () => {
    const d = deriveDate(rel("Effective Date", "days", 30), null);
    expect(d.resolved).toBe(false);
    expect(d.computed_date).toBeNull();
    expect(d.reason).toContain("Effective Date");
  });

  it("marks business-days unresolved (no holiday calendar asserted)", () => {
    const d = deriveDate(rel("Effective Date", "business-days", 10), "2025-01-01");
    expect(d.resolved).toBe(false);
    expect(d.computed_date).toBeNull();
    expect(d.reason).toContain("business");
  });

  it("derives both bounds of a disjunctive range as a window", () => {
    const ref = rel("Effective Date", "days", 30, { offset_count_max: 60 });
    const d = deriveDate(ref, "2025-01-01");
    expect(d.window).toEqual(["2025-01-31", "2025-03-02"]);
    expect(d.computed_date).toBe("2025-01-31");
  });
});

describe("deriveDate — properties (companion §3)", () => {
  const isoArb = fc
    .record({
      y: fc.integer({ min: 1970, max: 2099 }),
      m: fc.integer({ min: 1, max: 12 }),
      d: fc.integer({ min: 1, max: 28 }),
    })
    .map(({ y, m, d }) => `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`);

  it("the computed date is always a valid ISO date", () => {
    fc.assert(
      fc.property(
        isoArb,
        fc.constantFrom<"days" | "weeks" | "months" | "years">("days", "weeks", "months", "years"),
        fc.integer({ min: -240, max: 240 }),
        (anchor, unit, n) => {
          const d = deriveDate(rel("X Date", unit, n), anchor);
          expect(d.computed_date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
          const [, mo, day] = d.computed_date!.split("-").map(Number) as [number, number, number];
          expect(mo).toBeGreaterThanOrEqual(1);
          expect(mo).toBeLessThanOrEqual(12);
          expect(day).toBeGreaterThanOrEqual(1);
          expect(day).toBeLessThanOrEqual(31);
        },
      ),
      { numRuns: 400 },
    );
  });

  it("day arithmetic is monotonic in the offset", () => {
    fc.assert(
      fc.property(
        isoArb,
        fc.integer({ min: 0, max: 1000 }),
        fc.integer({ min: 0, max: 1000 }),
        (anchor, a, b) => {
          const lo = Math.min(a, b);
          const hi = Math.max(a, b);
          const dlo = deriveDate(rel("X Date", "days", lo), anchor).computed_date!;
          const dhi = deriveDate(rel("X Date", "days", hi), anchor).computed_date!;
          expect(dlo <= dhi).toBe(true);
        },
      ),
      { numRuns: 300 },
    );
  });

  it("adding then subtracting the same number of months is identity for day≤28", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1970, max: 2090 }),
        fc.integer({ min: 1, max: 12 }),
        fc.integer({ min: 1, max: 28 }),
        fc.integer({ min: 1, max: 60 }),
        (y, m, day, n) => {
          const iso = `${y}-${String(m).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
          const fwd = deriveDate(rel("X Date", "months", n), iso).computed_date!;
          const back = deriveDate(rel("X Date", "months", -n), fwd).computed_date!;
          expect(back).toBe(iso);
        },
      ),
      { numRuns: 300 },
    );
  });
});

describe("resolveAnchors (companion §2)", () => {
  it("binds an anchor from a definition that pins an absolute date", () => {
    const tree = buildTree(
      ["Definitions", '"Effective Date" means January 1, 2025.'],
      ["Term", "This Agreement begins on the Effective Date."],
    );
    const extracted = extractAll(tree);
    const anchors = resolveAnchors(extracted, tree);
    expect(anchors.get("effective date")).toBe("2025-01-01");
  });

  it("binds an anchor co-located with its parenthetical", () => {
    const tree = buildTree([
      "Preamble",
      'This Agreement is effective as of March 15, 2025 (the "Effective Date").',
    ]);
    const extracted = extractAll(tree);
    const anchors = resolveAnchors(extracted, tree);
    expect(anchors.get("effective date")).toBe("2025-03-15");
  });

  it("leaves a behaviorally-defined anchor unmapped — never guesses", () => {
    const tree = buildTree([
      "Term",
      'The "Effective Date" means the date of the last signature below.',
    ]);
    const extracted = extractAll(tree);
    const anchors = resolveAnchors(extracted, tree);
    expect(anchors.has("effective date")).toBe(false);
  });
});

describe("buildCriticalDates — the register (spec-v9 §29, companion §5)", () => {
  it("computes a resolved deadline with its anchor, trigger, and section", async () => {
    const tree = buildTree(
      ["Definitions", '"Renewal Date" means December 31, 2025.'],
      ["Renewal", "Either party may terminate 60 days before the Renewal Date."],
    );
    const extracted = extractAll(tree);
    const reg = await buildCriticalDates(extracted, tree);
    expect(reg.register.length).toBeGreaterThan(0);
    const row = reg.register.find((r) => r.anchor === "Renewal Date");
    expect(row).toBeDefined();
    expect(row!.resolved).toBe(true);
    expect(row!.computed_date).toBe("2025-11-01");
    expect(row!.trigger).toContain("60");
  });

  it("classifies an auto-renewal notice as DATE-001", async () => {
    const tree = buildTree(
      ["Definitions", '"Renewal Date" means December 31, 2025.'],
      [
        "Auto-renewal",
        "This Agreement renews automatically. Either party may opt out 30 days before the Renewal Date.",
      ],
    );
    const extracted = extractAll(tree);
    const reg = await buildCriticalDates(extracted, tree);
    const row = reg.register.find((r) => r.anchor === "Renewal Date");
    expect(row).toBeDefined();
    expect(row!.kind).toBe<CriticalDateKind>("auto-renewal-notice");
    expect(row!.rule_id).toBe("DATE-001");
  });

  it("surfaces an unresolved anchor as a verify-manually row, never a guess", async () => {
    const tree = buildTree([
      "Cure",
      "The breaching party shall cure within 30 days after the Notice Date.",
    ]);
    const extracted = extractAll(tree);
    const reg = await buildCriticalDates(extracted, tree);
    const row = reg.register.find((r) => r.anchor === "Notice Date");
    expect(row).toBeDefined();
    expect(row!.resolved).toBe(false);
    expect(row!.computed_date).toBeNull();
    expect(row!.reason).toBeTruthy();
  });

  it("is empty and deterministic for a document with no derivable dates", async () => {
    const tree = buildTree(["Body", "This Agreement has no temporal terms."]);
    const extracted = extractAll(tree);
    const reg = await buildCriticalDates(extracted, tree);
    expect(reg.register).toEqual([]);
    expect(reg.resolved_count).toBe(0);
    const again = await buildCriticalDates(extracted, tree);
    expect(again.critical_dates_hash).toBe(reg.critical_dates_hash);
  });

  it("sorts resolved dates ascending before unresolved rows", async () => {
    const tree = buildTree(
      ["Definitions", '"Effective Date" means January 1, 2025.'],
      ["A", "Deliver within 90 days after the Effective Date."],
      ["B", "Deliver within 10 days after the Effective Date."],
      ["C", "Respond within 5 days after the Unknown Date."],
    );
    const extracted = extractAll(tree);
    const reg = await buildCriticalDates(extracted, tree);
    const resolved = reg.register.filter((r) => r.resolved).map((r) => r.computed_date);
    const sorted = [...resolved].sort();
    expect(resolved).toEqual(sorted);
    // Unresolved rows come last.
    const firstUnresolved = reg.register.findIndex((r) => !r.resolved);
    if (firstUnresolved >= 0) {
      expect(reg.register.slice(firstUnresolved).every((r) => !r.resolved)).toBe(true);
    }
  });
});

describe("critical-dates exports (spec-v9 §29/§30, Step 163)", () => {
  async function fixtureRegister() {
    const tree = buildTree(
      ["Definitions", '"Renewal Date" means December 31, 2025.'],
      [
        "Auto-renewal",
        "This Agreement renews automatically. Either party may opt out 60 days before the Renewal Date.",
      ],
      ["Cure", "Provider shall cure within 30 days after the Notice Date."],
    );
    const extracted = extractAll(tree);
    return buildCriticalDates(extracted, tree);
  }

  it("renders a Markdown register with the computed date and a verify-manually list", async () => {
    const reg = await fixtureRegister();
    const md = buildCriticalDatesMarkdown(reg);
    expect(md).toContain("# Vaulytica critical dates");
    expect(md).toContain("2025-11-01"); // Dec 31 − 60 days
    expect(md).toContain("Verify manually");
    // Never a relative-to-today phrase in the hashed/exported artifact.
    expect(md).not.toMatch(/days? remaining|overdue|due in/i);
  });

  it("renders a deterministic .ics with a notice alarm and no wall-clock", async () => {
    const reg = await fixtureRegister();
    const ics = buildCriticalDatesIcs(reg);
    expect(ics).toContain("BEGIN:VCALENDAR");
    expect(ics).toContain("DTSTART;VALUE=DATE:20251101");
    expect(ics).toContain("BEGIN:VALARM"); // opt-out window → reminder
    expect(ics).toContain("DTSTAMP:20200101T000000Z"); // fixed, no generation clock
    // Byte-identical on a second render.
    expect(buildCriticalDatesIcs(reg)).toBe(ics);
  });
});
