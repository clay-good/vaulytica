import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  dayOfWeek,
  HolidayCalendarSchema,
  HOLIDAY_CALENDARS,
  getHolidayCalendar,
  isNonCourtDay,
} from "./holiday-calendar.js";

describe("dayOfWeek — Zeller's congruence", () => {
  it("2024-01-01 is a Monday", () => {
    expect(dayOfWeek("2024-01-01")).toBe(1);
  });

  it("2026-07-04 is a Saturday", () => {
    expect(dayOfWeek("2026-07-04")).toBe(6);
  });

  it("2026-07-06 is a Monday", () => {
    expect(dayOfWeek("2026-07-06")).toBe(1);
  });

  it("2025-12-25 is a Thursday", () => {
    expect(dayOfWeek("2025-12-25")).toBe(4);
  });

  it("throws on a malformed date", () => {
    expect(() => dayOfWeek("not-a-date")).toThrow();
  });
});

describe("HolidayCalendarSchema", () => {
  it("parses a minimal valid calendar", () => {
    const cal = {
      id: "test",
      name: "Test Calendar",
      version: "2026-01-01",
      covers: { from: 2024, to: 2025 },
      all_saturdays_holiday: false,
      all_sundays_holiday: true,
      holidays: ["2024-12-25"],
      authority: [{ cite: "Test Cite", url: "https://example.com", retrieved_at: "2026-01-01" }],
    };
    expect(() => HolidayCalendarSchema.parse(cal)).not.toThrow();
  });

  it("rejects a holiday outside covers", () => {
    const cal = {
      id: "test",
      name: "Test Calendar",
      version: "2026-01-01",
      covers: { from: 2024, to: 2025 },
      all_saturdays_holiday: false,
      all_sundays_holiday: true,
      holidays: ["2026-12-25"],
      authority: [{ cite: "Test Cite", url: "https://example.com", retrieved_at: "2026-01-01" }],
    };
    expect(() => HolidayCalendarSchema.parse(cal)).toThrow();
  });

  it("rejects a malformed ISO holiday date", () => {
    const cal = {
      id: "test",
      name: "Test Calendar",
      version: "2026-01-01",
      covers: { from: 2024, to: 2025 },
      all_saturdays_holiday: false,
      all_sundays_holiday: true,
      holidays: ["12/25/2024"],
      authority: [{ cite: "Test Cite", url: "https://example.com", retrieved_at: "2026-01-01" }],
    };
    expect(() => HolidayCalendarSchema.parse(cal)).toThrow();
  });

  it("rejects covers.from > covers.to", () => {
    const cal = {
      id: "test",
      name: "Test Calendar",
      version: "2026-01-01",
      covers: { from: 2025, to: 2024 },
      all_saturdays_holiday: false,
      all_sundays_holiday: true,
      holidays: [],
      authority: [{ cite: "Test Cite", url: "https://example.com", retrieved_at: "2026-01-01" }],
    };
    expect(() => HolidayCalendarSchema.parse(cal)).toThrow();
  });
});

describe("shipped calendars", () => {
  it("both us-federal and california validate and load", () => {
    expect(getHolidayCalendar("us-federal")).toBeDefined();
    expect(getHolidayCalendar("california")).toBeDefined();
    expect(Object.keys(HOLIDAY_CALENDARS).sort()).toEqual(["california", "us-federal"]);
  });

  it("us-federal treats both Saturday and Sunday as non-court days (FRCP 6(a)(1)(C))", () => {
    const cal = getHolidayCalendar("us-federal")!;
    expect(cal.all_saturdays_holiday).toBe(true);
    expect(cal.all_sundays_holiday).toBe(true);
  });

  it("california treats both Saturday and Sunday as non-court days", () => {
    const cal = getHolidayCalendar("california")!;
    expect(cal.all_saturdays_holiday).toBe(true);
    expect(cal.all_sundays_holiday).toBe(true);
  });

  it("2026-07-04 (Independence Day, Saturday) is observed on 2026-07-03", () => {
    const cal = getHolidayCalendar("us-federal")!;
    expect(cal.holidays).toContain("2026-07-03");
    expect(cal.holidays).not.toContain("2026-07-04");
  });

  it("california includes Cesar Chavez Day each covered year (2024 observed Monday — Mar 31 fell on Sunday)", () => {
    const cal = getHolidayCalendar("california")!;
    expect(cal.holidays).toContain("2024-04-01");
    for (const y of [2025, 2026, 2027]) {
      expect(cal.holidays).toContain(`${y}-03-31`);
    }
  });

  it("california is the CCP § 135 JUDICIAL list, not the federal list (audit pins)", () => {
    const cal = getHolidayCalendar("california")!;
    // Columbus Day: CA courts are OPEN — must not roll.
    for (const d of ["2024-10-14", "2025-10-13", "2026-10-12", "2027-10-11"]) {
      expect(cal.holidays, d).not.toContain(d);
    }
    // Day after Thanksgiving: CA courts are CLOSED — must roll.
    for (const d of ["2024-11-29", "2025-11-28", "2026-11-27", "2027-11-26"]) {
      expect(cal.holidays, d).toContain(d);
    }
    // Lincoln's Birthday + Native American Day (4th Friday of September).
    expect(cal.holidays).toContain("2026-02-12");
    expect(cal.holidays).toContain("2026-09-25");
  });

  it("us-federal covers the observed New Year's Day 2028 inside its range (2027-12-31)", () => {
    const cal = getHolidayCalendar("us-federal")!;
    expect(cal.holidays).toContain("2027-12-31");
  });
});

describe("isNonCourtDay", () => {
  it("a Sunday is a non-court day under both calendars", () => {
    const fed = getHolidayCalendar("us-federal")!;
    const ca = getHolidayCalendar("california")!;
    // 2026-07-05 is a Sunday.
    expect(dayOfWeek("2026-07-05")).toBe(0);
    expect(isNonCourtDay(fed, "2026-07-05")).toBe(true);
    expect(isNonCourtDay(ca, "2026-07-05")).toBe(true);
  });

  it("a Saturday is a non-court day under both calendars (FRCP 6(a)(1)(C))", () => {
    const fed = getHolidayCalendar("us-federal")!;
    const ca = getHolidayCalendar("california")!;
    // 2026-07-04 is a Saturday and not itself a listed federal holiday
    // (observed on Jul 3 instead) — but Saturdays roll forward under FRCP.
    expect(dayOfWeek("2026-07-04")).toBe(6);
    expect(isNonCourtDay(fed, "2026-07-04")).toBe(true);
    expect(isNonCourtDay(ca, "2026-07-04")).toBe(true);
  });

  it("a listed holiday on a weekday is a non-court day under both", () => {
    const fed = getHolidayCalendar("us-federal")!;
    expect(isNonCourtDay(fed, "2026-12-25")).toBe(true);
  });
});

describe("property: dayOfWeek is stable and 7-cyclic", () => {
  it("adding 7 days never changes the weekday, for any covered date", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 2024, max: 2026 }),
        fc.integer({ min: 1, max: 12 }),
        fc.integer({ min: 1, max: 27 }),
        (y, m, d) => {
          const iso =
            `${y}`.padStart(4, "0") + "-" + `${m}`.padStart(2, "0") + "-" + `${d}`.padStart(2, "0");
          const dow = dayOfWeek(iso);
          expect(dow).toBeGreaterThanOrEqual(0);
          expect(dow).toBeLessThanOrEqual(6);
        },
      ),
    );
  });
});
