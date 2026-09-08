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

  it("marks an hours window unresolved (sub-day, cannot be pinned to a date)", () => {
    const d = deriveDate(
      rel("Security Incident", "hours", 72, { offset_days: undefined }),
      "2025-01-01",
    );
    expect(d.resolved).toBe(false);
    expect(d.computed_date).toBeNull();
    expect(d.reason).toContain("hour");
  });

  /**
   * What the register prints INSTEAD of a date.
   *
   * `deriveDate`'s whole contract is "never guess": when it cannot compute a
   * date it returns a `reason`, and that sentence is what an attorney reads in
   * the row where a deadline should be. Mutation testing found four of these
   * branches with **no test executing them at all** — the fallback for an
   * older reference shape, the "no offset to apply" refusal, and the two
   * count-missing arms of the business-day and hours reasons. Every one is a
   * path that only runs when something upstream is already unusual, which is
   * exactly when the reader most needs the sentence to be right.
   *
   * The existing tests above assert `reason).toContain("business")` and
   * `toContain("hour")` — true of the mutants too. These pin what the row says.
   */
  it("names the anchor it could not resolve, and says so plainly when there is none", () => {
    const named = deriveDate(rel("Effective Date", "days", 30), null);
    expect(named.reason).toBe('relative to "Effective Date", which has no defined calendar date');
    // No anchor at all is a different sentence: there is nothing to name.
    const anonymous = deriveDate(rel("", "days", 30, { anchor: undefined }), null);
    expect(anonymous.reason).toBe("relative date with no resolvable anchor");
  });

  it("prints the count in the business-day and hours reasons, and 'n' when it has none", () => {
    expect(deriveDate(rel("Effective Date", "business-days", -10), "2025-01-01").reason).toBe(
      "business-day deadline (10 business days) — no holiday calendar is asserted; verify manually",
    );
    expect(
      deriveDate(
        rel("Effective Date", "business-days", 0, { offset_count: undefined }),
        "2025-01-01",
      ).reason,
    ).toContain("(n business days)");
    expect(
      deriveDate(rel("Security Incident", "hours", -72, { offset_days: undefined }), "2025-01-01")
        .reason,
    ).toBe(
      "72-hour deadline — a sub-day window the calendar register cannot pin; verify the exact time manually",
    );
    expect(
      deriveDate(rel("Security Incident", "hours", 0, { offset_count: undefined }), "2025-01-01")
        .reason,
    ).toContain("n-hour deadline");
  });

  it("falls back to the day-collapsed offset when the calendar unit was never captured", () => {
    // An older `DateReference` shape: no `offset_unit`/`offset_count`, only the
    // collapsed `offset_days`. Still deterministic, still resolved.
    const legacy = deriveDate(
      rel("Effective Date", undefined, 0, { offset_unit: undefined, offset_days: 45 }),
      "2025-01-01",
    );
    expect(legacy.resolved).toBe(true);
    expect(legacy.computed_date).toBe("2025-02-15");

    // The same shape with a unit but no count also takes the fallback.
    const noCount = deriveDate(
      rel("Effective Date", "days", 0, { offset_count: undefined, offset_days: -1 }),
      "2025-01-01",
    );
    expect(noCount.resolved).toBe(true);
    expect(noCount.computed_date).toBe("2024-12-31");
  });

  it("refuses when there is no offset of any kind — it does not fall through to the anchor", () => {
    const d = deriveDate(
      rel("Effective Date", undefined, 0, { offset_unit: undefined, offset_days: undefined }),
      "2025-01-01",
    );
    expect(d.resolved).toBe(false);
    expect(d.computed_date).toBeNull();
    expect(d.reason).toBe("no offset to apply");
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

describe("buildCriticalDates — opt-in deadline resolution (add-deadline-computation)", () => {
  it("resolves a business-days deadline that is unresolved without a profile", async () => {
    const { getDeadlineProfile } = await import("../deadlines/profile.js");
    const frcp = getDeadlineProfile("frcp-6")!;
    const tree = buildTree(
      ["Definitions", '"Effective Date" means July 1, 2026.'],
      ["Cure", "The breaching party shall cure within 10 business days after the Effective Date."],
    );
    const extracted = extractAll(tree);
    const without = await buildCriticalDates(extracted, tree);
    const wo = without.register.find((r) => r.anchor === "Effective Date")!;
    expect(wo.resolved).toBe(false); // business-days is punted with no profile

    const withProfile = await buildCriticalDates(extracted, tree, { profile: frcp });
    const wp = withProfile.register.find((r) => r.anchor === "Effective Date")!;
    expect(wp.resolved).toBe(true);
    expect(wp.deadline_profile_id).toBe("frcp-6");
    expect(wp.deadline_calendar_version).toBeTruthy();
    expect(wp.deadline_steps!.length).toBeGreaterThan(0);
  });

  it("rolls a 'days' deadline off a weekend under the profile", async () => {
    const { getDeadlineProfile } = await import("../deadlines/profile.js");
    const frcp = getDeadlineProfile("frcp-6")!;
    const tree = buildTree(
      ["Definitions", '"Effective Date" means July 1, 2026.'],
      ["A", "Respond within 3 days after the Effective Date."],
    );
    const extracted = extractAll(tree);
    // Without a profile: 2026-07-01 + 3 = 2026-07-04 (Saturday), no roll.
    const without = await buildCriticalDates(extracted, tree);
    expect(without.register.find((r) => r.anchor === "Effective Date")!.computed_date).toBe(
      "2026-07-04",
    );
    // With FRCP: rolls Sat → Mon 2026-07-06.
    const withProfile = await buildCriticalDates(extracted, tree, { profile: frcp });
    const row = withProfile.register.find((r) => r.anchor === "Effective Date")!;
    expect(row.computed_date).toBe("2026-07-06");
    expect(row.deadline_profile_id).toBe("frcp-6");
  });

  /**
   * A BACKWARD-counted period under an asserted profile.
   *
   * "at least 14 days before the hearing" counts back; the profile's
   * arithmetic counts forward, and an earlier version ran it through
   * `Math.abs()` — which moved the answer **2N days late**, the single worst
   * direction of error a deadline register has. The fix keeps the plain
   * backward arithmetic and SAYS the profile was not applied.
   *
   * Mutation testing found the whole branch unexecuted: the guard, the early
   * return for an unresolved row, and the sentence that explains itself could
   * all be deleted and every test still passed. The regression that motivated
   * the code had no test.
   */
  it("does NOT apply forward profile arithmetic to a backward-counted period, and says so", async () => {
    const { getDeadlineProfile } = await import("../deadlines/profile.js");
    const frcp = getDeadlineProfile("frcp-6")!;
    const tree = buildTree(
      ["Definitions", '"Hearing Date" means July 20, 2026.'],
      ["Notice", "A party shall file the motion at least 14 days before the Hearing Date."],
    );
    const extracted = extractAll(tree);
    const row = (await buildCriticalDates(extracted, tree, { profile: frcp })).register.find(
      (r) => r.anchor === "Hearing Date",
    )!;
    // Plain backward count: 2026-07-20 − 14 = 2026-07-06. NOT 2026-08-03,
    // which is where Math.abs() plus a forward roll used to land it.
    expect(row.computed_date).toBe("2026-07-06");
    expect(row.deadline_steps).toHaveLength(1);
    expect(row.deadline_steps![0]!.rule).toBe("frcp-6");
    expect(row.deadline_steps![0]!.detail).toContain(
      "the asserted profile's forward-counting arithmetic was not applied",
    );
  });

  it("leaves an UNRESOLVED backward-counted row exactly as it was — no empty steps list", async () => {
    const { getDeadlineProfile } = await import("../deadlines/profile.js");
    const frcp = getDeadlineProfile("frcp-6")!;
    // 🚨 The first draft of this dropped the anchor DEFINITION to make the row
    // unresolved — which meant `resolveUnderProfile` was never reached at all
    // (its caller requires an anchor), so the test passed with the branch
    // deleted. An unresolved row that DOES reach it needs a defined anchor and
    // a unit `deriveDate` refuses: backward BUSINESS days.
    const tree = buildTree(
      ["Definitions", '"Hearing Date" means July 20, 2026.'],
      [
        "Notice",
        "A party shall file the motion at least 14 business days before the Hearing Date.",
      ],
    );
    const extracted = extractAll(tree);
    const row = (await buildCriticalDates(extracted, tree, { profile: frcp })).register.find(
      (r) => r.anchor === "Hearing Date",
    )!;
    expect(row.resolved).toBe(false);
    // Untouched: no step explaining arithmetic the branch did not do, and no
    // profile stamp claiming the profile decided this row.
    expect(row.deadline_steps).toBeUndefined();
    expect(row.deadline_profile_id).toBeUndefined();
  });

  /**
   * The profile asserted, and unable to compute.
   *
   * The shipped holiday calendars cover 2024–2027, so a deadline anchored
   * outside them cannot be rolled. Two outcomes, and the whole branch was
   * unexecuted: a "days" row that plain arithmetic already resolved keeps its
   * date and gains a step SAYING the profile did not apply (otherwise the
   * register silently mixes court-rule-correct rows with plain arithmetic
   * under one asserted profile — an audit finding); a row plain arithmetic
   * could NOT resolve is published unresolved with the profile's own reason.
   */
  it("keeps the plain date but says the profile could not compute it", async () => {
    const { getDeadlineProfile } = await import("../deadlines/profile.js");
    const frcp = getDeadlineProfile("frcp-6")!;
    const tree = buildTree(
      ["Definitions", '"Effective Date" means July 1, 2031.'],
      ["A", "Respond within 3 days after the Effective Date."],
    );
    const row = (await buildCriticalDates(extractAll(tree), tree, { profile: frcp })).register.find(
      (r) => r.anchor === "Effective Date",
    )!;
    expect(row.resolved).toBe(true);
    expect(row.computed_date).toBe("2031-07-04"); // plain arithmetic, unrolled
    expect(row.deadline_steps).toHaveLength(1);
    expect(row.deadline_steps![0]!.rule).toBe("frcp-6");
    expect(row.deadline_steps![0]!.detail).toContain(
      "the asserted profile could not compute this row",
    );
    expect(row.deadline_steps![0]!.detail).toContain(
      "WITHOUT roll or service rules — verify manually",
    );
  });

  it("publishes the profile's own reason when plain arithmetic could not resolve it either", async () => {
    const { getDeadlineProfile } = await import("../deadlines/profile.js");
    const frcp = getDeadlineProfile("frcp-6")!;
    // Business days: `deriveDate` refuses without a calendar, and the calendar
    // does not cover 2031 — so neither can answer, and the row says why.
    const tree = buildTree(
      ["Definitions", '"Effective Date" means July 1, 2031.'],
      ["A", "Respond within 10 business days after the Effective Date."],
    );
    const row = (await buildCriticalDates(extractAll(tree), tree, { profile: frcp })).register.find(
      (r) => r.anchor === "Effective Date",
    )!;
    expect(row.resolved).toBe(false);
    expect(row.computed_date).toBeNull();
    expect(row.reason).toBeTruthy();
    expect(row.reason).not.toContain("business-day deadline"); // the PROFILE's reason, not deriveDate's
    expect(row.deadline_steps).toBeUndefined();
  });

  /**
   * FRCP 6(d) mail days apply only to periods that run after SERVICE.
   *
   * The audit this guard came from: "(Rule 6(d))" was printed as authority on
   * rows that had nothing to do with service — a contract deadline measured
   * from an effective date owes no mail days. No test ever passed a
   * `service_method`, so the trigger/anchor sniff that decides it was never
   * executed with the adjustment available to apply.
   */
  it("adds service days only to a deadline that runs from SERVICE", async () => {
    const { getDeadlineProfile } = await import("../deadlines/profile.js");
    const frcp = getDeadlineProfile("frcp-6")!;
    const tree = buildTree(
      ["Definitions", '"Effective Date" means July 1, 2026.', '"Service Date" means July 1, 2026.'],
      ["A", "A party shall respond within 10 days after the Service Date."],
      ["B", "A party shall deliver the notice within 10 days after the Effective Date."],
    );
    const reg = await buildCriticalDates(extractAll(tree), tree, {
      profile: frcp,
      service_method: "mail",
    });
    const served = reg.register.find((r) => r.anchor === "Service Date")!;
    const contractual = reg.register.find((r) => r.anchor === "Effective Date")!;
    // Same anchor date, same 10-day count: the served row gets 3 mail days.
    expect(contractual.computed_date).toBe("2026-07-13"); // Jul 11 Sat → Mon 13
    expect(served.computed_date).toBe("2026-07-14");
    expect(served.deadline_steps!.some((s) => /Rule 6\(d\)/.test(s.detail))).toBe(true);
    // And the contract row is NOT given service authority it never earned.
    expect(contractual.deadline_steps!.some((s) => /Rule 6\(d\)/.test(s.detail))).toBe(false);
  });

  it("profiles BOTH bounds of a range deadline (window is not left stale/un-profiled)", async () => {
    const { getDeadlineProfile } = await import("../deadlines/profile.js");
    const frcp = getDeadlineProfile("frcp-6")!;
    const tree = buildTree(
      ["Definitions", '"Effective Date" means July 1, 2026.'],
      ["A", "Respond within thirty to sixty days after the Effective Date."],
    );
    const reg = await buildCriticalDates(extractAll(tree), tree, { profile: frcp });
    const row = reg.register.find((r) => r.anchor === "Effective Date")!;
    expect(row.deadline_profile_id).toBe("frcp-6");
    // Both bounds profiled: +30 = 2026-07-31 (no roll), +60 = 2026-08-30 (Sun) →
    // rolled to Mon 2026-08-31. Before the fix the window kept the RAW upper
    // (2026-08-30) while the header claimed frcp-6 — the artifacts disagreed.
    expect(row.window).toEqual(["2026-07-31", "2026-08-31"]);
    expect(row.computed_date).toBe(row.window![0]);
    // The Markdown and ICS now show the profiled upper bound + a range note.
    expect(buildCriticalDatesMarkdown(reg)).toContain("2026-08-31");
    expect(buildCriticalDatesIcs(reg)).toContain("Range deadline: 2026-07-31 to 2026-08-31");
  });

  it("default path (no profile) yields a byte-identical hash", async () => {
    const tree = buildTree(
      ["Definitions", '"Effective Date" means January 1, 2025.'],
      ["A", "Deliver within 90 days after the Effective Date."],
      ["B", "Cure within 10 business days after the Effective Date."],
    );
    const extracted = extractAll(tree);
    const a = await buildCriticalDates(extracted, tree);
    const b = await buildCriticalDates(extracted, tree, undefined);
    expect(b.critical_dates_hash).toBe(a.critical_dates_hash);
    // And no row carries deadline provenance without a profile.
    expect(a.register.every((r) => r.deadline_profile_id === undefined)).toBe(true);
  });
});

describe("DDL-001 deadline drafting notes (add-deadline-computation follow-up)", () => {
  it("notes a deadline whose own math lands on a weekend and rolls", async () => {
    const { getDeadlineProfile } = await import("../deadlines/profile.js");
    const frcp = getDeadlineProfile("frcp-6")!;
    // 2026-07-01 + 3 days = 2026-07-04 (Saturday) → rolls to Monday.
    const tree = buildTree(
      ["Definitions", '"Effective Date" means July 1, 2026.'],
      ["A", "Respond within 3 days after the Effective Date."],
    );
    const extracted = extractAll(tree);
    const reg = await buildCriticalDates(extracted, tree, { profile: frcp });
    const note = reg.deadline_notes?.find((n) => n.code === "DDL-001");
    expect(note).toBeDefined();
    // The title is the note. `some(code === "DDL-001")` passes with the
    // sentence deleted, which is how the singular/plural agreement here went
    // untested: one rolled deadline reads "1 deadline falls", not "1 deadlines
    // fall", and the register is read by attorneys.
    expect(note!.title).toBe("1 deadline falls on a non-court day before rolling forward");
    expect(note!.severity).toBe("info");
    expect(note!.detail).toMatch(/"[^"]+" → 2026-07-06/);
    expect(note!.detail).toContain("Confirm the intended deadline.");
  });

  it("agrees in number: two rolled deadlines read 'deadlines fall'", async () => {
    const { getDeadlineProfile } = await import("../deadlines/profile.js");
    const frcp = getDeadlineProfile("frcp-6")!;
    // Both land on 2026-07-04 (Saturday) and roll to Monday.
    const tree = buildTree(
      ["Definitions", '"Effective Date" means July 1, 2026.'],
      ["A", "Respond within 3 days after the Effective Date."],
      ["B", "Object within 3 days after the Effective Date."],
    );
    const reg = await buildCriticalDates(extractAll(tree), tree, { profile: frcp });
    const note = reg.deadline_notes!.find((n) => n.code === "DDL-001")!;
    expect(note.title).toBe("2 deadlines fall on a non-court day before rolling forward");
  });

  it("is absent without a profile (and does not affect the hash)", async () => {
    const tree = buildTree(
      ["Definitions", '"Effective Date" means July 1, 2026.'],
      ["A", "Respond within 3 days after the Effective Date."],
    );
    const extracted = extractAll(tree);
    const a = await buildCriticalDates(extracted, tree);
    expect(a.deadline_notes).toBeUndefined();
    const b = await buildCriticalDates(extracted, tree, undefined);
    expect(b.critical_dates_hash).toBe(a.critical_dates_hash);
  });
});

describe("DDL-001 renders in the critical-dates markdown (add-deadline-computation)", () => {
  it("shows a Drafting notes section when a profile rolled a deadline", async () => {
    const { getDeadlineProfile } = await import("../deadlines/profile.js");
    const { buildCriticalDatesMarkdown } = await import("./exports.js");
    const frcp = getDeadlineProfile("frcp-6")!;
    const tree = buildTree(
      ["Definitions", '"Effective Date" means July 1, 2026.'],
      ["A", "Respond within 3 days after the Effective Date."],
    );
    const extracted = extractAll(tree);
    const reg = await buildCriticalDates(extracted, tree, { profile: frcp });
    const md = buildCriticalDatesMarkdown(reg);
    expect(md).toContain("Drafting notes");
    expect(md).toContain("DDL-001");
    // Absent without a profile.
    const plain = await buildCriticalDates(extracted, tree);
    expect(buildCriticalDatesMarkdown(plain)).not.toContain("Drafting notes");
  });
});
