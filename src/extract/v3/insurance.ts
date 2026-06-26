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
];

const AMOUNT_RX =
  /\$\s*([\d,]+(?:\.\d+)?)\s*(?:(million|mm|m\b|thousand|k\b))?\s*(?:USD)?\s*(per occurrence|each occurrence|aggregate|in the aggregate|annual aggregate)?/gi;

const AM_BEST_RX =
  /\bA\.?M\.?\s*Best\b[^.]{0,80}?\b([A-Z]\+?\+?(?:[- ](?:I{1,3}|IV|V|VI{0,3}|IX|X{1,2}))?)\b/i;

const ENDORSEMENT_RX = /\b(CG\s*\d{2}\s*\d{2}(?:\s*\d{2})?|CA\s*\d{2}\s*\d{2})\b/g;

const NOTICE_RX =
  /\b(\d{1,3})\s+days?['’]?\s+(?:prior )?(?:written )?notice of (?:cancellation|non[- ]renewal)/i;

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
          if (!am[1]) continue;
          const amt = normalizeAmount(am[1], am[2]);
          const qualifier = (am[3] ?? "").toLowerCase();
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
