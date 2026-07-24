import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * A date that belongs to a DIFFERENT, referenced instrument — "incorporated
 * into the Master Services Agreement between the parties dated January 1,
 * 2026" — is not this document's effective date, so it cannot evidence that
 * THIS document was back-dated. Requiring the determiner "the" (never "this")
 * before the instrument keeps the document's own "This Agreement, dated …"
 * out of the exclusion.
 */
const REFERENCED_INSTRUMENT_DATE =
  /\bthe\s+[^.;]{0,70}?\b(?:agreement|msa|dpa|baa|contract|sow|order\s+form|lease|note|policy|addendum|indenture)\b[^.;]{0,40}?\bdated\s+(?:as\s+of\s+)?$/i;

/**
 * A date that opens a stated PERIOD is a range boundary, not an effective
 * date: a HIPAA authorization covering "treatment notes from the period
 * 2024-01-01 through 2026-12-31" is not back-dated to 2024 — that is the span
 * of records it authorizes.
 */
const PERIOD_START_DATE =
  /\b(?:for\s+|from\s+|covering\s+)?(?:the\s+)?period\s+(?:from\s+|of\s+)?$/i;

/**
 * A BIRTHDATE ("I, Edwin Marsh, born April 4, 1955, …") is biography, not an
 * effective date — every will, directive, and POA recites one, and comparing
 * it against the execution date reported a decades-long "past-dated" anomaly
 * on routine estate documents.
 */
const BIRTHDATE = /\bborn\s+(?:on\s+)?$/i;

/**
 * A date inside a case-citation parenthetical — "(Del. Ch. Oct. 1, 2018)",
 * "(2d Cir. Mar. 3, 2021)" — dates the cited OPINION, not this document;
 * a brief citing decade-old precedent is not back-dated.
 */
const CITATION_DATE = /\(\s*(?:[A-Z0-9][\w.]*\s+){0,4}$/;

/** Absolute-date start offsets whose text reads as another instrument's date. */
function referencedDateStarts(ctx: RuleContext): Set<number> {
  const out = new Set<number>();
  forEachParagraph(ctx.tree, (p) => {
    for (const d of ctx.extracted.dates) {
      if (d.type !== "absolute" || !d.iso) continue;
      const start = d.position?.start;
      if (start === undefined || start < p.start || start >= p.start + p.text.length) continue;
      const before = p.text.slice(0, start - p.start);
      if (
        REFERENCED_INSTRUMENT_DATE.test(before) ||
        PERIOD_START_DATE.test(before) ||
        BIRTHDATE.test(before) ||
        CITATION_DATE.test(before)
      ) {
        out.add(start);
      }
    }
  });
  return out;
}

/** TEMP-002 — Past-dated effective date in a forward-looking contract (info). */
export const rule: Rule = {
  id: "TEMP-002",
  version: "1.2.0",
  name: "Past-dated effective date",
  category: "temporal",
  default_severity: "info",
  description:
    "Flags an Effective Date more than 30 days before the earliest other absolute date in the document.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const referenced = referencedDateStarts(ctx);
    const abs = ctx.extracted.dates.filter(
      (d) =>
        d.type === "absolute" &&
        d.iso &&
        !(d.position?.start !== undefined && referenced.has(d.position.start)),
    );
    // Back-dating shows up as the earliest date being an OUTLIER before the
    // document's other dates. With only two dates there is nothing to be an
    // outlier from: an effective date and a maturity/expiration date are the
    // contract's TERM, not evidence of back-dating — a five-year loan
    // (2026-03-01 → 2031-03-01) and a one-year insurance policy period
    // (2026-01-01 → 2027-01-01) are not back-dated.
    if (abs.length < 3) return null;
    const sorted = [...abs].sort((a, b) => (a.iso! < b.iso! ? -1 : 1));
    const earliest = new Date(sorted[0]!.iso!);
    const next = new Date(sorted[1]!.iso!);
    const gapDays = (next.getTime() - earliest.getTime()) / 86_400_000;
    if (gapDays <= 30) return null;
    // The gap must also exceed the spread of the remaining dates. Otherwise the
    // "gap" is just the front of a long term (a lease signed a month before it
    // commences and running five years), not a date sitting apart from the
    // document's own cluster.
    const last = new Date(sorted[sorted.length - 1]!.iso!);
    const restSpanDays = (last.getTime() - next.getTime()) / 86_400_000;
    if (gapDays <= restSpanDays) return null;
    return emit(ctx, rule, {
      title: "Earliest dated reference is far before other dates",
      description: `Earliest date ${sorted[0]!.iso} precedes the next date ${sorted[1]!.iso} by ${Math.round(gapDays)} days.`,
      excerpt: sorted[0]!.raw_text,
      explanation:
        "A contract dated significantly before its other date references may be intentionally back-dated. Confirm the intent before signing.",
      position: sorted[0]!.position ?? topPosition(ctx),
    });
  },
};
