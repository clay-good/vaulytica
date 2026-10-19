/**
 * v3 insurance amount, AM-Best rating, and endorsement extractor (spec-v3.md §25).
 *
 * Extracts a normalized insurance schedule from two quite different shapes.
 *
 * **A contract requirement** states the sum and qualifies it afterwards:
 * "commercial general liability of not less than $1,000,000 per occurrence
 * and $2,000,000 in the aggregate". That is what this extractor was written
 * for, and a trailing qualifier is where it looked.
 *
 * **A certificate of insurance (ACORD 25) does the opposite.** Its LIMITS
 * column is a list of figures each *preceded* by its label, and in a PDF's
 * text layer the whole column arrives as one run:
 *
 *     COMMERCIAL GENERAL LIABILITY  EACH OCCURRENCE $1,000,000
 *     DAMAGE TO RENTED PREMISES $100,000  MED EXP $5,000
 *     PERSONAL & ADV INJURY $1,000,000  GENERAL AGGREGATE $2,000,000
 *
 * Reading only the trailing qualifier made the §58 insurance summary print
 * six rows all labelled "Commercial General Liability", the aggregate column
 * empty on every one of them, and **the general aggregate and the products
 * aggregate in the PER-OCCURRENCE column** — so a reader checking whether a
 * vendor carries $1M/$2M saw a per-occurrence limit of $2,000,000 the
 * certificate does not state, and no aggregate at all. A missing figure is a
 * gap; a figure in the wrong column is a confidently wrong number in a
 * lawyer's report. So the label that *precedes* a figure is read, it decides
 * the basis, and it is carried on the record as `limit_label` so every row
 * says which limit it is.
 *
 * Spatial parsing of the form's boxes is still not attempted and is not
 * needed: a certificate's label sits immediately before its figure in reading
 * order, whatever the geometry.
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
  // 🚨 The possessive is written four ways and the apostrophe may fall either
  // side of the `s`: "workers compensation", "workers' compensation",
  // "worker's compensation", "employer's liability", "employers' liability".
  // Requiring `employers` before the apostrophe missed the SINGULAR possessive
  // outright, so "employer's liability of $1,000,000" — the commonest drafting
  // of the commonest workers'-comp companion limit — named no line at all, and
  // once figures are attached to the line named nearest before them its figure
  // went to the workers'-compensation row instead.
  {
    line: "workers-compensation",
    rx: /\bworkers?['’]?s?\s*compensation\b|\bworkers?['’]?s?\s*comp\b/i,
  },
  { line: "employers-liability", rx: /\bemployers?['’]?s?\s+liabilit(?:y|ies)\b/i },
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
  /([$€£¥₹₩₽]|USD|US[$€£¥₹₩₽])?\s*(\d[\d,]*(?:\.\d+)?)\s*(million|mm|m\b|thousand|k\b)?\s*(USD|dollars)?\s*(per occurrence|each occurrence|per claim|each claim|per accident|each accident|aggregate|in the aggregate|annual aggregate)?/gi;

// Rating = a letter grade with an optional modifier (A++, A+, A, A-) and an
// optional financial-size category in Roman numerals (I–XV), separated by a
// space and/or hyphen. The old pattern only read a `+` modifier (so the very
// common minus grade "A-" was truncated to "A", a materially higher rating)
// and allowed only a single delimiter char (so "A- VII" — hyphen then space —
// dropped the numeral). The FSC tokens are longest-first and `\b`-terminated
// so a following lowercase word ("A video") can never be misread as a numeral.
const AM_BEST_RX =
  /\bA\.?M\.?\s*Best\b[^.]{0,80}?\b([A-Z](?:\+\+|\+|-)?(?:[-\s]*(?:XV|XIV|XIII|XII|XI|X|IX|VIII|VII|VI|V|IV|III|II|I)\b)?)(?![A-Za-z])/i;

// An endorsement is designated by a prefix, a two-pair form number and, for
// ISO forms, a two-pair edition date: `CG 20 10 04 13` is form CG 20 10,
// edition April 2013. The old pattern allowed at most three pairs and only the
// CG / CA prefixes, so every ISO form was TRUNCATED to a designation that does
// not exist ("CG 20 10 04") and the workers'-compensation waiver of
// subrogation — NCCI `WC 00 03 13`, the endorsement certificates cite most
// often after CG 20 10 — was not seen at all. The prefixes are the ISO
// commercial lines (CG general liability, CA auto, CU umbrella, CP property,
// CR crime, IL interline) plus NCCI's WC.
const ENDORSEMENT_RX = /\b((?:CG|CA|CU|CP|CR|IL|WC)(?:\s*\d{2}){2,4})\b/g;

// Insurance clauses spell the notice period as "word (numeral)" — "thirty (30)
// days' prior written notice of cancellation" — and the parenthesized numeral
// is authoritative. Anchoring on a bare digit dropped every such period to a
// null notice value. The optional `(?:[^.()\d\n]*?\()?` skips the spelled words
// up to the numeral's open paren, bounded by the sentence and by parens so it
// never reaches an unrelated parenthetical; a plain "30 days" still matches.
const NOTICE_RX =
  /\b(?:[^.()\d\n]{0,60}?\()?(\d{1,3})\)?\s+days?['’]?\s+(?:prior )?(?:written )?notice of (?:cancellation|non[- ]?renewal)/i;

// The same "word (numeral) days ... notice" shape with no "of cancellation"
// tail, for use only inside a sentence already known to be about cancellation.
// `calendar` and `advance` are the two modifiers certificates insert.
const CERT_NOTICE_RX =
  /\b(?:[^.()\d\n]{0,60}?\()?(\d{1,3})\)?\s+(?:calendar\s+)?days?['’]?\s+(?:prior\s+|advance\s+)?(?:written\s+)?notice\b/i;

/**
 * A limit's label, and what basis it states.
 *
 * Ordered most-specific first, and overlaps are resolved in favour of the
 * label that STARTS earliest and runs longest, so "GENERAL AGGREGATE" is not
 * reduced to "AGGREGATE" and "PRODUCTS - COMP/OP AGG" is not reduced to
 * "AGG". The `label` is what the report prints; the document's own casing is
 * not preserved, because a certificate shouts and a contract does not, and a
 * table of limits reads better in one voice.
 *
 * 🚨 The workers'-compensation disease limits are the pair most easily got
 * wrong: "E.L. DISEASE — EACH EMPLOYEE" is per-employee (an occurrence-basis
 * limit) and "E.L. DISEASE — POLICY LIMIT" is the aggregate for disease. They
 * differ by three words and sit on adjacent lines of every certificate.
 */
const LIMIT_LABELS: { rx: RegExp; basis: "per-occurrence" | "aggregate"; label: string }[] = [
  {
    // A certificate abbreviates it "PRODUCTS - COMP/OP AGG"; a prose schedule
    // spells it "Products and completed operations aggregate". Without the
    // spelled conjunction the second fell through to the bare "Aggregate"
    // label, and the report showed two $2,000,000 aggregate rows a reader
    // could not tell apart.
    rx: /\bproducts?\s*(?:[-–—/]|and|&)?\s*comp(?:leted)?\s*(?:[-–—/]|and|&)?\s*op(?:eration)?s?\s*agg(?:regate)?\b/i,
    basis: "aggregate",
    label: "Products / completed operations aggregate",
  },
  { rx: /\bgeneral\s+aggregate\b/i, basis: "aggregate", label: "General aggregate" },
  {
    rx: /\b(?:annual|policy|combined)\s+aggregate\b/i,
    basis: "aggregate",
    label: "Annual aggregate",
  },
  {
    rx: /\b(?:E\.?L\.?\s*)?disease\s*[-–—,]?\s*(?:each|per)\s+employee\b/i,
    basis: "per-occurrence",
    label: "Disease — each employee",
  },
  {
    rx: /\b(?:E\.?L\.?\s*)?disease\s*[-–—,]?\s*policy\s+limit\b/i,
    basis: "aggregate",
    label: "Disease — policy limit",
  },
  { rx: /\bpolicy\s+limit\b/i, basis: "aggregate", label: "Policy limit" },
  { rx: /\b(?:in\s+the\s+)?aggregate\b/i, basis: "aggregate", label: "Aggregate" },
  {
    rx: /\bcombined\s+single\s+limit\b|\bCSL\b/i,
    basis: "per-occurrence",
    label: "Combined single limit",
  },
  {
    rx: /\b(?:each|per|any\s+one)\s+occurrence\b/i,
    basis: "per-occurrence",
    label: "Each occurrence",
  },
  { rx: /\b(?:each|per)\s+accident\b/i, basis: "per-occurrence", label: "Each accident" },
  { rx: /\b(?:each|per)\s+claim\b/i, basis: "per-occurrence", label: "Each claim" },
  { rx: /\b(?:each|per)\s+employee\b/i, basis: "per-occurrence", label: "Each employee" },
  {
    rx: /\b(?:each|per|any\s+one)\s+(?:person|offen[cs]e|incident)\b/i,
    basis: "per-occurrence",
    label: "Each person",
  },
  {
    rx: /\bdamage\s+to\s+rented\s+premises\b|\bfire\s+damage\s+legal\s+liabilit(?:y|ies)\b/i,
    basis: "per-occurrence",
    label: "Damage to rented premises",
  },
  {
    rx: /\bmed(?:ical)?\.?\s*exp(?:ense)?s?\b|\bmedical\s+payments\b/i,
    basis: "per-occurrence",
    label: "Medical expense",
  },
  {
    rx: /\bpersonal\s*(?:and|&)\s*adv(?:ertising)?\.?\s*injury\b/i,
    basis: "per-occurrence",
    label: "Personal and advertising injury",
  },
  { rx: /\bbodily\s+injury\b/i, basis: "per-occurrence", label: "Bodily injury" },
  { rx: /\bproperty\s+damage\b/i, basis: "per-occurrence", label: "Property damage" },
];

/**
 * Labels that precede a figure which is NOT a limit of liability.
 *
 * A retention, a deductible or a premium is money the insured pays, not
 * coverage the certificate affords, and a certificate states them in the same
 * labelled-figure shape. Recording "Retention: $10,000" as an umbrella
 * per-occurrence limit of $10,000 would understate a $5,000,000 policy by
 * three orders of magnitude, so a figure whose nearest preceding label is one
 * of these is dropped rather than guessed at.
 */
const NOT_A_LIMIT_RX =
  /\b(?:self[-\s]?insured\s+retention\b|\bSIR\b|retention\b|deductible\b|premium\b|surcharge\b)/i;

/**
 * 🚨 A SUM THAT CAPS A PARTY'S LIABILITY IS NOT A COVERAGE LIMIT, however much
 * insurance vocabulary its clause carries. An architect's limitation reads
 * "The total aggregate liability of Architect to Owner … shall not exceed the
 * greater of $1,240,000 or the amount of professional liability insurance
 * proceeds actually available for the claim" — so the clause genuinely names
 * professional liability and the figure genuinely sits before it, and the
 * §58 Insurance Summary listed the architect's CAP as its professional-
 * liability limit. A reader checking cover against a requirement would have
 * read $1,240,000 as insurance the architect carries.
 *
 * ⚠️ Vocabulary cannot tell the two apart: the same figure in the same words
 * is a limit in an insurance schedule and a cap here. The SUBJECT can. A cap's
 * subject is the liability itself — "the total aggregate liability of X", "in
 * no event" — where a requirement's subject is the party ("Contractor shall
 * maintain …") or the limits ("limits of liability shall be not less than …").
 * That last one is why this matches a liability subject only under a
 * SUPERLATIVE determiner: "the limits of liability" names cover, "the total
 * aggregate liability" names exposure.
 */
const LIABILITY_CAP_SUBJECT =
  /^\s*(?:in\s+no\s+event\b|(?:the\s+)?(?:total|aggregate|maximum|entire|cumulative)\s+(?:aggregate\s+)?liabilit(?:y|ies)\b)/i;

/**
 * The paragraph from the start of the sentence `at` falls in. Only the START
 * matters to the one caller — `LIABILITY_CAP_SUBJECT` is anchored, because it
 * is the clause's subject that tells a cap from a limit — so the sentence's
 * end is not computed.
 */
function fromSentenceStart(text: string, at: number): string {
  let from = 0;
  for (const m of text.slice(0, at).matchAll(/[.;:]\s+/g)) from = (m.index ?? 0) + m[0].length;
  return text.slice(from);
}

/** The widest gap allowed between a label and the figure it labels. */
const LABEL_GAP = 40;

type LabelHit = {
  start: number;
  end: number;
  basis: "per-occurrence" | "aggregate" | null;
  label: string | null;
};

/**
 * Every limit label in a paragraph, in reading order, overlaps removed.
 */
function findLimitLabels(text: string): LabelHit[] {
  const hits: LabelHit[] = [];
  for (const entry of LIMIT_LABELS) {
    const rx = new RegExp(
      entry.rx.source,
      entry.rx.flags.includes("g") ? entry.rx.flags : entry.rx.flags + "g",
    );
    for (const m of text.matchAll(rx)) {
      const i = m.index ?? 0;
      hits.push({ start: i, end: i + m[0].length, basis: entry.basis, label: entry.label });
    }
  }
  for (const m of text.matchAll(new RegExp(NOT_A_LIMIT_RX.source, NOT_A_LIMIT_RX.flags + "g"))) {
    const i = m.index ?? 0;
    hits.push({ start: i, end: i + m[0].length, basis: null, label: null });
  }
  // Earliest start wins, and at equal starts the longest match, so a specific
  // label is never shortened into the generic one nested inside it.
  hits.sort((a, b) => (a.start !== b.start ? a.start - b.start : b.end - a.end));
  const kept: LabelHit[] = [];
  for (const h of hits) {
    const last = kept[kept.length - 1];
    if (last && h.start < last.end) continue;
    kept.push(h);
  }
  return kept;
}

/**
 * The label a figure at `at` is labelled by, or undefined when it is bare.
 *
 * 🚨 Nearness alone is not enough, and measured wrongly over the corpus.
 * "…$4,000,000 aggregate; automobile liability of $1,000,000" puts the word
 * "aggregate" 26 characters before a figure it has nothing to do with, and
 * four specimens had their automobile and workers'-comp limits reclassified as
 * aggregates by it. Three things disqualify a candidate:
 *
 *   - **another figure in between** — in a certificate's limits run,
 *     "PERSONAL & ADV INJURY $1,000,000 GENERAL AGGREGATE $2,000,000", the
 *     earlier label is within the gap but is already spoken for;
 *   - **a clause boundary** (`;` or a full stop) — a new clause is a new
 *     subject, which is exactly what the architect specimen proved;
 *   - **a coverage line named in between** — the label belongs to whatever
 *     the document moved on to naming.
 *
 * Among the survivors the EARLIEST wins, not the nearest, so a sublimit keeps
 * its own name rather than the basis note parenthesised inside it: "MED EXP
 * (Any one person) $5,000" is the medical-expense limit, and "(Any one
 * person)" is how it is measured.
 */
function labelFor(text: string, labels: LabelHit[], at: number): LabelHit | undefined {
  for (const h of labels) {
    if (h.start >= at) break;
    if (h.end > at || at - h.end > LABEL_GAP) continue;
    const gap = text.slice(h.end, at);
    if (/[;.]/.test(gap)) continue;
    if (CURRENCY_IN_GAP_RX.test(gap)) continue;
    if (LINE_PATTERNS.some((p) => p.rx.test(gap))) continue;
    return h;
  }
  return undefined;
}

/** A figure between a label and the figure it might otherwise have labelled. */
const CURRENCY_IN_GAP_RX = /[$€£¥₹₩₽]\s*\d|\d[\d,]*\s*(?:USD|dollars)\b/i;

/**
 * Where each coverage line is NAMED in a paragraph, in reading order.
 *
 * 🚨 One clause routinely names several lines — "commercial general liability
 * of $2,000,000 per occurrence and $4,000,000 aggregate; automobile liability
 * of $1,000,000; and employer's liability of $1,000,000" — and every figure in
 * it was attached to every line named in it. So the insurance summary gave the
 * automobile policy a $4,000,000 aggregate and a $2,000,000 per-occurrence
 * limit that the clause states for general liability, and gave general
 * liability the automobile figure: four wrong numbers out of a clause that is
 * perfectly clear about which limit belongs to which cover. Over the corpus it
 * was 182 rows of 312.
 *
 * A figure belongs to the line named nearest BEFORE it, which is the order
 * every such clause and every certificate row is written in.
 */
function findLineNames(text: string): { start: number; end: number; line: InsuranceLine }[] {
  const hits: { start: number; end: number; line: InsuranceLine }[] = [];
  for (const entry of LINE_PATTERNS) {
    const rx = new RegExp(
      entry.rx.source,
      entry.rx.flags.includes("g") ? entry.rx.flags : entry.rx.flags + "g",
    );
    for (const m of text.matchAll(rx)) {
      const i = m.index ?? 0;
      hits.push({ start: i, end: i + m[0].length, line: entry.line });
    }
  }
  return hits.sort((a, b) => a.start - b.start);
}

/**
 * The line a figure at `at` belongs to, or every line named when the paragraph
 * gives no order to go on.
 *
 * A figure that precedes every line name takes the first one named after it —
 * "not less than $1,000,000 of commercial general liability" is written that
 * way round too. Three figures in the corpus resolve that way.
 */
function linesForAmount(
  names: readonly { start: number; end: number; line: InsuranceLine }[],
  all: readonly InsuranceLine[],
  at: number,
): readonly InsuranceLine[] {
  if (names.length === 0) return all;
  let before: InsuranceLine | undefined;
  for (const n of names) {
    if (n.end <= at) before = n.line;
    else break;
  }
  if (before !== undefined) return [before];
  const after = names.find((n) => n.start >= at);
  return after ? [after.line] : all;
}

/**
 * Whether a paragraph is a continuation ROW of a certificate's limits column.
 *
 * A certificate puts the coverage line on one row and its limits on the rows
 * beneath, so the paragraphs that carry "General Aggregate: $2,000,000" name
 * no coverage line at all and every figure in them was dropped. A row is
 * claimed for the line above only when it OPENS with a limit label, which is
 * what a limits row does and what ordinary contract prose does not — and the
 * claim is given up at the first paragraph that is neither a limits row nor
 * names a line of its own, so it can never reach across a document.
 */
function opensWithLimitLabel(text: string, labels: LabelHit[]): boolean {
  const first = labels[0];
  if (!first || first.label === null) return false;
  return (
    text
      .slice(0, first.start)
      .trim()
      .replace(/^[-•*–—|]+/, "")
      .trim() === ""
  );
}

function normalizeAmount(raw: string, multiplier?: string): number {
  const n = Number(raw.replace(/,/g, ""));
  if (!Number.isFinite(n)) return 0;
  if (!multiplier) return n;
  const m = multiplier.toLowerCase();
  if (m.startsWith("m")) return n * 1_000_000;
  if (m.startsWith("k") || m.startsWith("thousand")) return n * 1_000;
  return n;
}

/**
 * The notice period in a certificate's cancellation legend.
 *
 * `NOTICE_RX` needs the words "notice of cancellation" in that order, which is
 * how a contract requirement is written. An ACORD 25 writes the legend the
 * other way round — "SHOULD ANY OF THE ABOVE DESCRIBED POLICIES BE CANCELLED
 * BEFORE THE EXPIRATION DATE THEREOF, THIRTY (30) DAYS WRITTEN NOTICE WILL BE
 * DELIVERED" — so the cancellation word comes first and the standard legend of
 * every certificate in the corpus yielded a null notice period.
 *
 * Scoped to the SENTENCE that mentions cancellation, so a termination clause's
 * own notice period elsewhere in the same paragraph cannot be read as the
 * insurer's. The ACORD legend as revised in 2010 states no number at all
 * ("NOTICE WILL BE DELIVERED IN ACCORDANCE WITH THE POLICY PROVISIONS"); that
 * correctly yields null, and the report omits the line rather than inventing
 * a period.
 *
 * 🚨 **The sentence must also name a POLICY**, and measuring it is what said
 * so: dropping "of cancellation" from the pattern made five more specimens
 * report an insurer's notice period, and the clearest of them was an
 * advertising insertion order — "the Agency may cancel any placement … on
 * fourteen (14) days prior written notice" — which is a party cancelling an
 * ad, not an insurer cancelling cover. Cancellation is something a contract
 * does to itself far more often than an insurer does to a policy, so the
 * insurance noun is what makes the sentence the insurance schedule's
 * business.
 */
function certificateNotice(text: string): RegExpExecArray | null {
  for (const sentence of text.split(/(?<=[.;])\s+/)) {
    if (!/\bcancel(?:l?ed|l?ation)?\b|\bnon[-\s]?renew/i.test(sentence)) continue;
    if (
      !/\bpolic(?:y|ies)\b|\binsurer\b|\bcoverage\b|\bcertificate\s+of\s+insurance\b/i.test(
        sentence,
      )
    )
      continue;
    const m = CERT_NOTICE_RX.exec(sentence);
    if (m) return m;
  }
  return null;
}

export function extractInsuranceSchedule(tree: DocumentTree): InsuranceSchedule {
  const amounts: InsuranceAmount[] = [];
  const endorsements: InsuranceEndorsement[] = [];
  let required_am_best_rating: string | null = null;
  let notice_of_cancellation_days: number | null = null;

  // The coverage line(s) a certificate's following limits rows belong to.
  let carried: InsuranceLine[] = [];

  forEachParagraph(tree, (ctx) => {
    const lineHits = LINE_PATTERNS.filter((p) => p.rx.test(ctx.text));
    const labels = findLimitLabels(ctx.text);
    const isLimitsRow = opensWithLimitLabel(ctx.text, labels);
    const lines: InsuranceLine[] =
      lineHits.length > 0 ? lineHits.map((p) => p.line) : isLimitsRow ? carried : [];

    if (lines.length > 0) {
      // Try to attach amounts in this paragraph to the detected line(s). A
      // carried line comes from the row above, so the names in THIS paragraph
      // order nothing; only a paragraph that names its own lines does.
      const names = lineHits.length > 0 ? findLineNames(ctx.text) : [];
      for (const am of ctx.text.matchAll(AMOUNT_RX)) {
        // Require a currency marker on one side; a bare number is not a limit.
        if (!am[1] && !am[4]) continue;
        if (!am[2]) continue;
        const at = am.index ?? 0;
        const labelled = labelFor(ctx.text, labels, at);
        // A retention, deductible or premium is not coverage: dropped, never
        // guessed at as the line's limit.
        if (labelled && labelled.basis === null) continue;
        // See LIABILITY_CAP_SUBJECT: a cap is exposure, not cover.
        if (LIABILITY_CAP_SUBJECT.test(fromSentenceStart(ctx.text, at))) continue;
        const amt = normalizeAmount(am[2], am[3]);
        const qualifier = am[5] ?? "";
        // 🚨 The qualifier that FOLLOWS a figure wins over the label that
        // precedes it, because it is adjacent and the label may not be.
        // "$1,000,000 per occurrence and $2,000,000 in the aggregate" puts
        // "per occurrence" nine characters before the aggregate figure, so
        // preferring the preceding label moved 21 corpus aggregates into the
        // per-occurrence column — the same wrong-column defect this change
        // exists to fix, running the other way. The label only speaks where
        // the figure is followed by nothing.
        const qualified = qualifier === "" ? undefined : findLimitLabels(qualifier)[0];
        const basis = qualified ?? labelled;
        const isAggregate = basis?.basis === "aggregate";
        for (const line of linesForAmount(names, lines, at)) {
          amounts.push({
            line,
            per_occurrence_usd: isAggregate ? null : amt > 0 ? amt : null,
            aggregate_usd: isAggregate ? (amt > 0 ? amt : null) : null,
            limit_label: basis?.label ?? null,
            raw_text: am[0].trim(),
            position: posInParagraph(ctx, at, at + am[0].length),
          });
        }
      }
    }

    // Hold the line only across a contiguous run of limits rows.
    if (lineHits.length > 0) carried = lineHits.map((p) => p.line);
    else if (!isLimitsRow) carried = [];

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
      const nm = NOTICE_RX.exec(ctx.text) ?? certificateNotice(ctx.text);
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
