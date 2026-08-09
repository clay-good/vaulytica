/**
 * v3 insurance amount, AM-Best rating, and endorsement extractor (spec-v3.md §25).
 *
 * Extracts a normalized insurance schedule from contract requirements. COI
 * (ACORD 25) layout parsing is a follow-up that depends on the v2 PDF
 * text-with-position output and is tracked alongside Step 29's addenda work.
 */

import type { DocumentTree } from "../../ingest/types.js";
import type {
  InsuranceAmount,
  InsuranceEndorsement,
  InsuranceLine,
  InsuranceSchedule,
} from "./types.js";
import { forEachParagraph, posInParagraph } from "../walk.js";

const LINE_PATTERNS: { line: InsuranceLine; rx: RegExp }[] = [
  {
    line: "commercial-general-liability",
    rx: /\bcommercial general liabilit(?:y|ies)\b|\bCGL\b|\bgeneral liabilit(?:y|ies)\b/i,
  },
  {
    line: "professional-liability",
    rx: /\bprofessional liabilit(?:y|ies)\b|\berrors? (?:and|&) omissions\b|\bE&O\b/i,
  },
  {
    line: "cyber-liability",
    rx: /\bcyber liabilit(?:y|ies)\b|\bcyber insurance\b|\bcyber risk\b/i,
  },
  { line: "umbrella-excess", rx: /\bumbrella\b|\bexcess liabilit(?:y|ies)\b/i },
  { line: "workers-compensation", rx: /\bworkers'?\s*compensation\b|\bworker[s']*\s*comp\b/i },
  { line: "employers-liability", rx: /\bemployers'?\s+liabilit(?:y|ies)\b/i },
  {
    line: "automobile-liability",
    rx: /\bauto(?:mobile)?\s+liabilit(?:y|ies)\b|\bbusiness auto\b/i,
  },
  {
    line: "employment-practices-liability",
    rx: /\bemployment practices liabilit(?:y|ies)\b|\bEPLI\b/i,
  },
  { line: "fiduciary-liability", rx: /\bfiduciary liabilit(?:y|ies)\b/i },
  {
    // The spelled "directors and officers" also names a governance body, so it
    // counts as a line only when an insurance noun follows within the clause;
    // the "D&O" abbreviation is insurance-specific and needs no such guard.
    line: "directors-officers-liability",
    rx: /\bD\s*&\s*O\b|\bdirectors?\s*(?:and|&|and\/or)\s*officers?\b(?=[^.]{0,30}?(?:insurance|coverage|policy))/i,
  },
  {
    line: "crime-fidelity",
    rx: /\bcrime\s+(?:insurance|coverage|policy)\b|\bcommercial\s+crime\b|\bfidelity\s+(?:bond|insurance|coverage)\b|\bemployee\s+dishonesty\b/i,
  },
];

// Insurance limits carry their currency on either side of the figure — a
// leading symbol/code (`$1,000,000`, `USD 1,000,000`) or a trailing code
// (`1,000,000 USD`). Anchoring on a leading `$` dropped every code-only form,
// leaving a schedule that named the currency but no limit. The leading and
// trailing currency markers are both optional in the pattern; a match with
// neither is a bare number (a section or year) and is rejected in code, so a
// currency marker on at least one side stays mandatory. The number must start
// with a digit so a stray comma cannot seed a junk match. Per-claim and
// each-accident are standard professional-liability and workers'-comp limit
// qualifiers alongside per-occurrence and aggregate.
const AMOUNT_RX =
  /(\$|USD|US\$)?\s*(\d[\d,]*(?:\.\d+)?)\s*(million|mm|m\b|thousand|k\b)?\s*(USD|dollars)?\s*(per occurrence|each occurrence|per claim|each claim|per accident|each accident|aggregate|in the aggregate|annual aggregate)?/gi;

const AM_BEST_RX =
  /\bA\.?M\.?\s*Best\b[^.]{0,80}?\b([A-Z]\+?\+?(?:[- ](?:I{1,3}|IV|V|VI{0,3}|IX|X{1,2}))?)\b/i;

const ENDORSEMENT_RX = /\b(CG\s*\d{2}\s*\d{2}(?:\s*\d{2})?|CA\s*\d{2}\s*\d{2})\b/g;

// Insurance clauses spell the notice period as "word (numeral)" — "thirty (30)
// days' prior written notice of cancellation" — and the parenthesized numeral
// is authoritative. Anchoring on a bare digit dropped every such period to a
// null notice value. The optional `(?:[^.()\d\n]*?\()?` skips the spelled words
// up to the numeral's open paren, bounded by the sentence and by parens so it
// never reaches an unrelated parenthetical; a plain "30 days" still matches.
const NOTICE_RX =
  /\b(?:[^.()\d\n]*?\()?(\d{1,3})\)?\s+days?['’]?\s+(?:prior )?(?:written )?notice of (?:cancellation|non[- ]renewal)/i;

function normalizeAmount(raw: string, multiplier?: string): number {
  const n = Number(raw.replace(/,/g, ""));
  if (!Number.isFinite(n)) return 0;
  if (!multiplier) return n;
  const m = multiplier.toLowerCase();
  if (m.startsWith("m")) return n * 1_000_000;
  if (m.startsWith("k") || m.startsWith("thousand")) return n * 1_000;
  return n;
}

export function extractInsuranceSchedule(tree: DocumentTree): InsuranceSchedule {
  const amounts: InsuranceAmount[] = [];
  const endorsements: InsuranceEndorsement[] = [];
  let required_am_best_rating: string | null = null;
  let notice_of_cancellation_days: number | null = null;

  forEachParagraph(tree, (ctx) => {
    const lineHits = LINE_PATTERNS.filter((p) => p.rx.test(ctx.text));
    if (lineHits.length > 0) {
      // Try to attach amounts in this paragraph to the detected line(s).
      const matches = Array.from(ctx.text.matchAll(AMOUNT_RX));
      for (const lp of lineHits) {
        for (const am of matches) {
          // Require a currency marker on one side; a bare number is not a limit.
          if (!am[1] && !am[4]) continue;
          if (!am[2]) continue;
          const amt = normalizeAmount(am[2], am[3]);
          const qualifier = (am[5] ?? "").toLowerCase();
          const isAggregate = qualifier.includes("aggregate");
          amounts.push({
            line: lp.line,
            per_occurrence_usd: isAggregate ? null : amt > 0 ? amt : null,
            aggregate_usd: isAggregate ? (amt > 0 ? amt : null) : null,
            raw_text: am[0].trim(),
            position: posInParagraph(ctx, am.index ?? 0, (am.index ?? 0) + am[0].length),
          });
        }
      }
    }
    for (const em of ctx.text.matchAll(ENDORSEMENT_RX)) {
      if (!em[1]) continue;
      endorsements.push({
        form_number: em[1].replace(/\s+/g, " ").toUpperCase(),
        raw_text: em[0],
        position: posInParagraph(ctx, em.index ?? 0, (em.index ?? 0) + em[0].length),
      });
    }
    if (!required_am_best_rating) {
      const am = AM_BEST_RX.exec(ctx.text);
      if (am && am[1]) required_am_best_rating = am[1];
    }
    if (notice_of_cancellation_days === null) {
      const nm = NOTICE_RX.exec(ctx.text);
      if (nm) notice_of_cancellation_days = Number(nm[1]);
    }
  });

  amounts.sort((a, b) =>
    a.position.start !== b.position.start
      ? a.position.start - b.position.start
      : a.line < b.line
        ? -1
        : a.line > b.line
          ? 1
          : 0,
  );
  endorsements.sort((a, b) => a.position.start - b.position.start);

  return { amounts, endorsements, required_am_best_rating, notice_of_cancellation_days };
}
