import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { scanParagraphs } from "./_scan.js";

const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTHS = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
];
const WD = WEEKDAYS.join("|");
const MO = MONTHS.join("|");
/** "Monday, March 3, 2026" and "Monday, 3 March 2026". */
const DATED = new RegExp(
  `\\b(${WD}),?\\s+(?:(${MO})\\s+(\\d{1,2})(?:st|nd|rd|th)?,?\\s+(\\d{4})|(\\d{1,2})(?:st|nd|rd|th)?\\s+(${MO}),?\\s+(\\d{4}))\\b`,
  "g",
);

/**
 * Each weekday the document gives a date that falls on another day. Pure
 * calendar arithmetic on the date as written — no clock enters it. A date
 * that does not exist (February 30) is TEMP-001's, and is skipped here.
 */
export function weekdayMismatches(
  text: string,
): Array<{ at: number; length: number; detail: string }> {
  const out: Array<{ at: number; length: number; detail: string }> = [];
  for (const m of text.matchAll(DATED)) {
    const month = MONTHS.indexOf((m[2] ?? m[6])!);
    const day = Number(m[3] ?? m[5]);
    const year = Number(m[4] ?? m[7]);
    const date = new Date(Date.UTC(year, month, day));
    if (date.getUTCMonth() !== month || date.getUTCDate() !== day) continue;
    const actual = WEEKDAYS[date.getUTCDay()]!;
    if (actual !== m[1]) {
      out.push({ at: m.index!, length: m[0].length, detail: `"${m[0]}" falls on a ${actual}` });
    }
  }
  return out;
}

/** PROOF-002 — Weekday does not match the date (info). */
export const rule: Rule = {
  id: "PROOF-002",
  version: "1.0.0",
  name: "Weekday does not match the date",
  category: "proofreading",
  default_severity: "info",
  description: "Flags a date written with a weekday that the date does not fall on.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hits = scanParagraphs(ctx, weekdayMismatches);
    if (hits.length === 0) return null;
    const first = hits[0]!;
    return emit(ctx, rule, {
      title: `Weekday does not match the date (${hits.length})`,
      description: `${first.detail}.`,
      excerpt: first.text,
      explanation:
        "A date written with the wrong weekday is ambiguous: a reader cannot tell whether the weekday or the date was meant, and a deadline or a meeting can turn on it.",
      recommendation: "Correct whichever of the weekday or the date is wrong.",
      position: first.position,
    });
  },
};
