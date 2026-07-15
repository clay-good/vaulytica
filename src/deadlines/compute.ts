/**
 * Court-deadline computation — the pure resolution engine.
 *
 * Applies a {@link DeadlineProfile} to a trigger date and a day count
 * (FRCP 6(a)(1) counting: exclude the trigger day, count every
 * subsequent calendar day, then roll a non-court-day landing forward to
 * the next court day). Every step is recorded so the result is
 * human-replayable, not just a bare date. Pure: no IO, no clock, no
 * randomness. A date outside the calendar's `covers` range is never
 * guessed at — it comes back `resolved: false` with a "verify manually"
 * reason, the same sentinel pattern as `deriveDate` in
 * `src/report/critical-dates.ts`.
 */

import { getHolidayCalendar, isNonCourtDay, type HolidayCalendar } from "./holiday-calendar.js";
import type { DeadlineProfile, ServiceMethod } from "./profile.js";

export type DeadlineStep = { rule: string; detail: string };

export type DeadlineResult =
  | {
      resolved: true;
      date: string;
      steps: DeadlineStep[];
      profile_id: string;
      calendar_version: string;
    }
  | { resolved: false; reason: string };

const ISO_DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

function parseIso(iso: string): [number, number, number] | null {
  const m = ISO_DATE_RE.exec(iso);
  if (!m) return null;
  const mo = +m[2]!;
  const d = +m[3]!;
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
  return [+m[1]!, mo, d];
}

function pad(n: number, w: number): string {
  return n.toString().padStart(w, "0");
}

function toIso(y: number, m: number, d: number): string {
  return `${pad(y, 4)}-${pad(m, 2)}-${pad(d, 2)}`;
}

/** Days in a Gregorian month (1-indexed), leap-year-correct. */
function daysInMonth(year: number, month1: number): number {
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const lengths = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return lengths[month1 - 1]!;
}

/** Add `n` calendar days (n may be negative), pure — no `Date` object. */
function addDays(iso: string, n: number): string {
  const p = parseIso(iso);
  if (!p) return iso;
  let [y, m, d] = p;
  d += n;
  // Normalize forward.
  while (d > daysInMonth(y, m)) {
    d -= daysInMonth(y, m);
    m += 1;
    if (m > 12) {
      m = 1;
      y += 1;
    }
  }
  // Normalize backward.
  while (d < 1) {
    m -= 1;
    if (m < 1) {
      m = 12;
      y -= 1;
    }
    d += daysInMonth(y, m);
  }
  return toIso(y, m, d);
}

function year(iso: string): number {
  return +ISO_DATE_RE.exec(iso)![1]!;
}

function outsideCoversReason(cal: HolidayCalendar, iso: string): string {
  return `the ${cal.name} calendar covers ${cal.covers.from}–${cal.covers.to}; ${iso} is outside it — verify manually`;
}

export function computeDeadline(args: {
  trigger: string;
  days: number;
  profile: DeadlineProfile;
  service_method?: ServiceMethod;
}): DeadlineResult {
  const { trigger, days, profile, service_method } = args;

  if (!parseIso(trigger)) {
    return { resolved: false, reason: `not a valid ISO date: ${trigger}` };
  }

  const cal = getHolidayCalendar(profile.calendar_id);
  if (!cal) {
    return { resolved: false, reason: `unknown calendar: ${profile.calendar_id}` };
  }

  if (year(trigger) < cal.covers.from || year(trigger) > cal.covers.to) {
    return { resolved: false, reason: outsideCoversReason(cal, trigger) };
  }

  const steps: DeadlineStep[] = [];

  // FRCP 6(a)(1)(A): exclude the trigger day, then count `days` forward.
  // Excluding the trigger day collapses to a plain `trigger + days`; not
  // excluding it means the trigger itself is day 1, so the last day is
  // `trigger + (days - 1)`.
  const excludeCite = profile.authority[0]!.cite;
  if (profile.exclude_trigger_day) {
    steps.push({ rule: excludeCite, detail: `excluded the trigger day ${trigger}` });
  } else {
    steps.push({ rule: excludeCite, detail: `counted the trigger day ${trigger} as day one` });
  }
  let current = profile.exclude_trigger_day ? addDays(trigger, days) : addDays(trigger, days - 1);
  steps.push({
    rule: excludeCite,
    detail: `added ${days} calendar day(s) from ${trigger} → ${current}`,
  });

  // FRCP 6(d): the service adjustment is added BEFORE the roll-forward
  // check, so a service add-on that itself lands on a non-court day still
  // rolls.
  if (
    service_method !== undefined &&
    profile.service_methods_adjusted.includes(service_method) &&
    profile.service_adjustment_days > 0
  ) {
    const before = current;
    current = addDays(current, profile.service_adjustment_days);
    steps.push({
      rule: excludeCite,
      detail: `service by ${service_method} adds ${profile.service_adjustment_days} day(s) (Rule 6(d)): ${before} → ${current}`,
    });
  }

  if (year(current) < cal.covers.from || year(current) > cal.covers.to) {
    return { resolved: false, reason: outsideCoversReason(cal, current) };
  }

  if (profile.roll_forward) {
    while (isNonCourtDay(cal, current)) {
      const before = current;
      const reason = nonCourtDayReasonFor(cal, current);
      current = addDays(current, 1);
      if (year(current) < cal.covers.from || year(current) > cal.covers.to) {
        return { resolved: false, reason: outsideCoversReason(cal, current) };
      }
      steps.push({
        rule: excludeCite,
        detail: `${before} is ${reason}; rolled forward to ${current}`,
      });
    }
  }

  return {
    resolved: true,
    date: current,
    steps,
    profile_id: profile.id,
    calendar_version: cal.version,
  };
}

function nonCourtDayReasonFor(cal: HolidayCalendar, iso: string): string {
  if (cal.holidays.includes(iso)) return "a holiday";
  return "a weekend day";
}

/**
 * Court-day (business-day) counting: count `days` court days forward from the
 * trigger, skipping every non-court-day as it counts. Used for a document term
 * stated in "business days" / "court days" (distinct from FRCP 6(a)'s
 * calendar-day count with a terminal roll). Because it lands on the Nth court
 * day by construction, no roll-forward is needed. Pure; outside-`covers` dates
 * come back unresolved, never extrapolated.
 */
export function computeCourtDays(args: {
  trigger: string;
  days: number;
  profile: DeadlineProfile;
}): DeadlineResult {
  const { trigger, days, profile } = args;
  if (!parseIso(trigger)) return { resolved: false, reason: `not a valid ISO date: ${trigger}` };
  const cal = getHolidayCalendar(profile.calendar_id);
  if (!cal) return { resolved: false, reason: `unknown calendar: ${profile.calendar_id}` };
  if (year(trigger) < cal.covers.from || year(trigger) > cal.covers.to) {
    return { resolved: false, reason: outsideCoversReason(cal, trigger) };
  }
  const cite = profile.authority[0]!.cite;
  const steps: DeadlineStep[] = [
    { rule: cite, detail: `excluded the trigger day ${trigger}; counting ${days} court day(s)` },
  ];
  let current = trigger;
  let counted = 0;
  // Bound the walk defensively (weekends/holidays are a minority of days, so
  // the calendar span cannot need more than ~2× the target in raw days).
  let guard = 0;
  const maxIter = days * 3 + 30;
  while (counted < days) {
    if (guard++ > maxIter) return { resolved: false, reason: "court-day count did not terminate" };
    current = addDays(current, 1);
    if (year(current) > cal.covers.to) {
      return { resolved: false, reason: outsideCoversReason(cal, current) };
    }
    if (!isNonCourtDay(cal, current)) counted += 1;
  }
  steps.push({ rule: cite, detail: `landed on the ${days}th court day: ${current}` });
  return {
    resolved: true,
    date: current,
    steps,
    profile_id: profile.id,
    calendar_version: cal.version,
  };
}
