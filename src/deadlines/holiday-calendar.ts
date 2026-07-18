/**
 * Court-deadline computation — holiday calendars.
 *
 * Cited, versioned data (mirrors `src/filing/court-profile.ts`'s
 * cited-data + Zod pattern). A calendar is YEAR-BOUNDED (`covers`):
 * this module never extrapolates a rule ("3rd Monday of January") past
 * the years it was actually enumerated for, so a lookup outside
 * `covers` is a hard "verify manually", never a guess.
 *
 * All dates are plain ISO `"YYYY-MM-DD"` strings. No IO, no `Date.now()`,
 * no randomness. {@link dayOfWeek} is Zeller's congruence — a closed-form
 * Gregorian-calendar formula, not a `Date` object — so it is provably
 * correct for any year without depending on host TZ/epoch behavior.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Pure day-of-week arithmetic.
// ---------------------------------------------------------------------------

const ISO_DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Parse a strict `"YYYY-MM-DD"` string, or `null` if malformed. */
function parseIso(iso: string): [number, number, number] | null {
  const m = ISO_DATE_RE.exec(iso);
  if (!m) return null;
  const y = +m[1]!;
  const mo = +m[2]!;
  const d = +m[3]!;
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
  return [y, mo, d];
}

/**
 * Day of week for a Gregorian `"YYYY-MM-DD"` date, via Zeller's
 * congruence: `0 = Sunday … 6 = Saturday`. Pure closed-form arithmetic —
 * no `Date` object, so it needs no epoch/TZ trust. Throws on a malformed
 * ISO string (callers are expected to validate first).
 */
export function dayOfWeek(iso: string): number {
  const p = parseIso(iso);
  if (!p) throw new Error(`dayOfWeek: not a valid ISO date: ${iso}`);
  const day = p[2];
  let [year, month] = p;
  // Zeller's congruence treats Jan/Feb as months 13/14 of the prior year.
  if (month < 3) {
    month += 12;
    year -= 1;
  }
  const k = year % 100;
  const j = Math.floor(year / 100);
  const h =
    (day + Math.floor((13 * (month + 1)) / 5) + k + Math.floor(k / 4) + Math.floor(j / 4) - 2 * j) %
    7;
  const hMod = ((h % 7) + 7) % 7; // h: 0 = Saturday … 6 = Friday
  return (hMod + 6) % 7; // remap to 0 = Sunday … 6 = Saturday
}

// ---------------------------------------------------------------------------
// The calendar shape.
// ---------------------------------------------------------------------------

const citation = z
  .object({
    cite: z.string().min(1),
    url: z.string().url(),
    retrieved_at: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "retrieved_at must be YYYY-MM-DD"),
  })
  .strict();

export const HolidayCalendarSchema = z
  .object({
    id: z.string().min(1),
    name: z.string().min(1),
    version: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "version is a release date YYYY-MM-DD"),
    covers: z
      .object({ from: z.number().int(), to: z.number().int() })
      .strict()
      .refine((c) => c.from <= c.to, "covers.from must be <= covers.to"),
    all_saturdays_holiday: z.boolean(),
    all_sundays_holiday: z.boolean(),
    holidays: z.array(z.string().regex(ISO_DATE_RE, "holiday must be a YYYY-MM-DD date")),
    authority: z.array(citation).min(1),
  })
  .strict()
  .refine(
    (cal) =>
      cal.holidays.every((iso) => {
        const p = parseIso(iso);
        return p !== null && p[0] >= cal.covers.from && p[0] <= cal.covers.to;
      }),
    "every holiday must fall within covers.from..covers.to",
  );

export type HolidayCalendar = z.infer<typeof HolidayCalendarSchema>;

// ---------------------------------------------------------------------------
// Shipped calendars — 2024-2027 inclusive.
//
// Federal observed dates below were derived by rule (5 U.S.C. § 6103):
// a holiday on Saturday is observed the preceding Friday; on Sunday, the
// following Monday. Enumerated by hand per year, not extrapolated at
// runtime — see holiday-calendar.test.ts for the day-of-week checks that
// pin the underlying arithmetic.
// ---------------------------------------------------------------------------

const US_FEDERAL_HOLIDAYS: string[] = [
  // 2024
  "2024-01-01", // New Year's Day
  "2024-01-15", // MLK Jr. Day (3rd Mon Jan)
  "2024-02-19", // Washington's Birthday (3rd Mon Feb)
  "2024-05-27", // Memorial Day (last Mon May)
  "2024-06-19", // Juneteenth
  "2024-07-04", // Independence Day
  "2024-09-02", // Labor Day (1st Mon Sep)
  "2024-10-14", // Columbus Day (2nd Mon Oct)
  "2024-11-11", // Veterans Day
  "2024-11-28", // Thanksgiving (4th Thu Nov)
  "2024-12-25", // Christmas
  // 2025
  "2025-01-01",
  "2025-01-20",
  "2025-02-17",
  "2025-05-26",
  "2025-06-19",
  "2025-07-04",
  "2025-09-01",
  "2025-10-13",
  "2025-11-11",
  "2025-11-27",
  "2025-12-25",
  // 2026
  "2026-01-01",
  "2026-01-19",
  "2026-02-16",
  "2026-05-25",
  "2026-06-19",
  "2026-07-03", // Independence Day observed — Jul 4 falls on Saturday
  "2026-09-07",
  "2026-10-12",
  "2026-11-11",
  "2026-11-26",
  "2026-12-25",
  // 2027
  "2027-01-01",
  "2027-01-18",
  "2027-02-15",
  "2027-05-31",
  "2027-06-18", // Juneteenth observed — Jun 19 falls on Saturday
  "2027-07-05", // Independence Day observed — Jul 4 falls on Sunday
  "2027-09-06",
  "2027-10-11",
  "2027-11-11",
  "2027-11-25",
  "2027-12-24", // Christmas observed — Dec 25 falls on Saturday
  "2027-12-31", // New Year's Day 2028 observed — Jan 1, 2028 falls on Saturday
];

const US_FEDERAL: HolidayCalendar = {
  id: "us-federal",
  name: "U.S. Federal Holidays",
  version: "2026-07-15",
  covers: { from: 2024, to: 2027 },
  // FRCP 6(a)(1)(C) / 6(a)(6): the period rolls forward if the last day is a
  // "Saturday, Sunday, or legal holiday" — Saturdays are non-court-days for the
  // roll, so this is true (not just Sundays).
  all_saturdays_holiday: true,
  all_sundays_holiday: true,
  holidays: US_FEDERAL_HOLIDAYS,
  authority: [
    {
      cite: "5 U.S.C. § 6103",
      url: "https://www.law.cornell.edu/uscode/text/5/6103",
      retrieved_at: "2026-07-15",
    },
  ],
};

/**
 * California JUDICIAL holidays diverge from the federal list (CCP § 135,
 * which incorporates Gov. Code § 6700 EXCEPT Columbus Day, and adds the
 * day after Thanksgiving; audit finding — the old federal+Chavez list
 * rolled deadlines on Columbus Day when CA courts are open, and failed to
 * roll on the day after Thanksgiving when they are closed):
 *   - Columbus Day (2nd Monday of October) is NOT a judicial holiday.
 *   - The day after Thanksgiving IS.
 *   - Lincoln's Birthday (Feb 12) IS.
 *   - Native American Day (4th Friday of September) IS.
 */
const CA_COLUMBUS_DAYS = new Set(["2024-10-14", "2025-10-13", "2026-10-12", "2027-10-11"]);
const CALIFORNIA_HOLIDAYS: string[] = [
  ...US_FEDERAL_HOLIDAYS.filter((d) => !CA_COLUMBUS_DAYS.has(d)),
  "2024-02-12", // Lincoln's Birthday
  "2025-02-12",
  "2026-02-12",
  "2027-02-12",
  "2024-04-01", // Cesar Chavez Day observed — Mar 31, 2024 falls on Sunday
  "2025-03-31", // Cesar Chavez Day
  "2026-03-31",
  "2027-03-31",
  "2024-09-27", // Native American Day (4th Friday of September)
  "2025-09-26",
  "2026-09-25",
  "2027-09-24",
  "2024-11-29", // Day after Thanksgiving
  "2025-11-28",
  "2026-11-27",
  "2027-11-26",
].sort();

const CALIFORNIA: HolidayCalendar = {
  id: "california",
  name: "California Judicial Holidays",
  version: "2026-07-18",
  covers: { from: 2024, to: 2027 },
  all_saturdays_holiday: true,
  all_sundays_holiday: true,
  holidays: CALIFORNIA_HOLIDAYS,
  authority: [
    {
      cite: "Cal. Civ. Proc. Code § 135 (judicial holidays); Cal. Gov. Code § 6700; Cal. Civ. Proc. Code § 12a",
      url: "https://courts.ca.gov/about/court-holidays",
      retrieved_at: "2026-07-18",
    },
  ],
};

/** Parse and validate a holiday calendar. Throws a ZodError on failure. */
export function parseHolidayCalendar(data: unknown): HolidayCalendar {
  return HolidayCalendarSchema.parse(data);
}

/** All shipped holiday calendars, keyed by id. Validated at module load. */
export const HOLIDAY_CALENDARS: Readonly<Record<string, HolidayCalendar>> = Object.freeze(
  Object.fromEntries(
    [US_FEDERAL, CALIFORNIA].map((cal) => {
      const parsed = parseHolidayCalendar(cal);
      return [parsed.id, parsed];
    }),
  ),
);

/** Look up a shipped calendar by id, or `undefined` if unknown. */
export function getHolidayCalendar(id: string): HolidayCalendar | undefined {
  return HOLIDAY_CALENDARS[id];
}

/**
 * True when `isoDate` is a non-court day under `cal`: a Saturday when
 * `all_saturdays_holiday`, a Sunday when `all_sundays_holiday`, or an
 * explicitly listed holiday. Does not consult `covers` — callers must
 * check the date falls within `covers` themselves (year-bounded rule,
 * companion pattern to {@link deriveDate} in critical-dates.ts).
 */
export function isNonCourtDay(cal: HolidayCalendar, isoDate: string): boolean {
  const dow = dayOfWeek(isoDate);
  if (cal.all_saturdays_holiday && dow === 6) return true;
  if (cal.all_sundays_holiday && dow === 0) return true;
  return cal.holidays.includes(isoDate);
}
