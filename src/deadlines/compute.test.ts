import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { computeDeadline, computeCourtDays } from "./compute.js";
import { getDeadlineProfile } from "./profile.js";
import { getHolidayCalendar } from "./holiday-calendar.js";

const frcp6 = getDeadlineProfile("frcp-6")!;
const calCcp12 = getDeadlineProfile("cal-ccp-12")!;

describe("computeDeadline — worked examples", () => {
  it("FRCP 6: trigger 2026-07-01, 30 days, no service → 2026-07-31 (Friday, court day)", () => {
    const r = computeDeadline({ trigger: "2026-07-01", days: 30, profile: frcp6 });
    expect(r.resolved).toBe(true);
    if (r.resolved) {
      expect(r.date).toBe("2026-07-31");
      expect(r.profile_id).toBe("frcp-6");
      expect(r.steps.length).toBeGreaterThan(0);
    }
  });

  it("weekend roll: 2026-07-01 + 32 days lands on Sunday 2026-08-02 → rolls to Monday 2026-08-03", () => {
    const r = computeDeadline({ trigger: "2026-07-01", days: 32, profile: frcp6 });
    expect(r.resolved).toBe(true);
    if (r.resolved) {
      expect(r.date).toBe("2026-08-03");
      expect(r.steps.some((s) => s.detail.includes("rolled forward"))).toBe(true);
    }
  });

  it("holiday roll: 2026-07-01 + 2 days lands on observed Independence Day 2026-07-03 (Fri) → rolls past the Sat/Sun weekend to Monday 2026-07-06", () => {
    const r = computeDeadline({ trigger: "2026-07-01", days: 2, profile: frcp6 });
    expect(r.resolved).toBe(true);
    if (r.resolved) {
      // 07-03 holiday → 07-04 Sat → 07-05 Sun → 07-06 Mon (first court day).
      expect(r.date).toBe("2026-07-06");
      expect(r.steps.some((s) => s.detail.includes("rolled forward"))).toBe(true);
    }
  });

  it("6(d) mail: +3 days applied before roll — 2026-06-29 + 1 day = 2026-06-30 base, +3 mail = 2026-07-03 (holiday) → rolls to Monday 2026-07-06", () => {
    const r = computeDeadline({
      trigger: "2026-06-29",
      days: 1,
      profile: frcp6,
      service_method: "mail",
    });
    expect(r.resolved).toBe(true);
    if (r.resolved) {
      expect(r.date).toBe("2026-07-06");
      expect(r.steps.some((s) => s.detail.includes("service by mail"))).toBe(true);
    }
  });

  it("electronic service adds 0 days (not in service_methods_adjusted)", () => {
    const withoutService = computeDeadline({ trigger: "2026-07-01", days: 27, profile: frcp6 });
    const withElectronic = computeDeadline({
      trigger: "2026-07-01",
      days: 27,
      profile: frcp6,
      service_method: "electronic",
    });
    expect(withoutService.resolved).toBe(true);
    expect(withElectronic.resolved).toBe(true);
    if (withoutService.resolved && withElectronic.resolved) {
      expect(withElectronic.date).toBe(withoutService.date);
      expect(withElectronic.steps.some((s) => s.detail.includes("service by"))).toBe(false);
    }
  });

  it("mail service adds 3 days when no roll is needed: 2026-07-01+27=2026-07-28, +3 mail=2026-07-31", () => {
    const r = computeDeadline({
      trigger: "2026-07-01",
      days: 27,
      profile: frcp6,
      service_method: "mail",
    });
    expect(r.resolved).toBe(true);
    if (r.resolved) expect(r.date).toBe("2026-07-31");
  });

  it("CCP § 12a Saturday: california calendar, 2026-07-01 + 3 days lands on Saturday 2026-07-04 → rolls through Sunday to Monday 2026-07-06", () => {
    const r = computeDeadline({ trigger: "2026-07-01", days: 3, profile: calCcp12 });
    expect(r.resolved).toBe(true);
    if (r.resolved) {
      expect(r.date).toBe("2026-07-06");
      const rollSteps = r.steps.filter((s) => s.detail.includes("rolled forward"));
      expect(rollSteps.length).toBe(2); // Saturday → Sunday → Monday
    }
  });

  it("outside-covers: trigger 2030-01-01 is outside the calendar's covered years", () => {
    const r = computeDeadline({ trigger: "2030-01-01", days: 10, profile: frcp6 });
    expect(r.resolved).toBe(false);
    if (!r.resolved) {
      expect(r.reason).toContain("2024");
      expect(r.reason).toContain("2027");
      expect(r.reason).toContain("verify manually");
    }
  });

  it("rejects a malformed trigger date without throwing", () => {
    const r = computeDeadline({ trigger: "not-a-date", days: 10, profile: frcp6 });
    expect(r.resolved).toBe(false);
  });
});

describe("computeDeadline — property tests", () => {
  it("rolling an already-court-day date is idempotent (days=0 on a resolved date changes nothing)", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(frcp6, calCcp12),
        fc.integer({ min: 2024, max: 2026 }),
        fc.integer({ min: 1, max: 12 }),
        fc.integer({ min: 1, max: 28 }),
        fc.integer({ min: 0, max: 60 }),
        (profile, y, m, d, days) => {
          const trigger = `${y}`.padStart(4, "0") + "-" + `${m}`.padStart(2, "0") + "-" + `${d}`.padStart(2, "0");
          const first = computeDeadline({ trigger, days, profile });
          if (!first.resolved) return; // outside-covers edge, skip
          const second = computeDeadline({ trigger: first.date, days: 0, profile });
          if (!second.resolved) return; // rolling off the edge of covers, skip
          expect(second.date).toBe(first.date);
        },
      ),
    );
  });

  it("the resolved date is never before the un-rolled base date", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(frcp6, calCcp12),
        fc.integer({ min: 2024, max: 2026 }),
        fc.integer({ min: 1, max: 12 }),
        fc.integer({ min: 1, max: 28 }),
        fc.integer({ min: 0, max: 60 }),
        (profile, y, m, d, days) => {
          const trigger = `${y}`.padStart(4, "0") + "-" + `${m}`.padStart(2, "0") + "-" + `${d}`.padStart(2, "0");
          const r = computeDeadline({ trigger, days, profile });
          if (!r.resolved) return;
          expect(r.date.localeCompare(trigger)).toBeGreaterThanOrEqual(0);
        },
      ),
    );
  });

  it("computeDeadline never throws for arbitrary trigger within covers and days 0..400", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(frcp6, calCcp12),
        fc.integer({ min: 2024, max: 2027 }),
        fc.integer({ min: 1, max: 12 }),
        fc.integer({ min: 1, max: 28 }),
        fc.integer({ min: 0, max: 400 }),
        fc.constantFrom(undefined, "electronic", "mail", "clerk", "other-consented", "personal"),
        (profile, y, m, d, days, service_method) => {
          const trigger = `${y}`.padStart(4, "0") + "-" + `${m}`.padStart(2, "0") + "-" + `${d}`.padStart(2, "0");
          expect(() => computeDeadline({ trigger, days, profile, service_method })).not.toThrow();
        },
      ),
    );
  });
});

describe("sanity: calendar_version is threaded through", () => {
  it("resolved result carries the calendar's version", () => {
    const cal = getHolidayCalendar("us-federal")!;
    const r = computeDeadline({ trigger: "2026-07-01", days: 30, profile: frcp6 });
    expect(r.resolved).toBe(true);
    if (r.resolved) expect(r.calendar_version).toBe(cal.version);
  });
});

describe("computeCourtDays — business-day counting", () => {
  it("counts N court days, skipping weekends and holidays", () => {
    // 2026-07-01 Wed. Count 5 court days: 07-02 Thu(1), 07-03 Fri observed
    // holiday→skip, 07-04 Sat/07-05 Sun→skip, 07-06 Mon(2), 07-07(3), 07-08(4),
    // 07-09 Thu(5) → lands on 2026-07-09.
    const r = computeCourtDays({ trigger: "2026-07-01", days: 5, profile: frcp6 });
    expect(r.resolved).toBe(true);
    if (r.resolved) expect(r.date).toBe("2026-07-09");
  });
  it("returns unresolved outside the calendar range", () => {
    const r = computeCourtDays({ trigger: "2030-01-01", days: 3, profile: frcp6 });
    expect(r.resolved).toBe(false);
  });
});
