/**
 * Clean-room legal-citation extractor. Parses PLAIN TEXT for case,
 * statute, rule, "Id.", "supra", and short-form case citations, entirely
 * from citation-grammar.ts (a from-first-principles grammar cited to The
 * Indigo Book, CC0 public domain). Citation SYSTEMS are unprotectable;
 * nothing here is derived from any proprietary citation manual.
 *
 * Total and deterministic: `extractCitations` never throws, does no IO, and
 * reads no clock — every offset comes from the input string alone.
 */

import { isKnownReporter } from "./citation-grammar.js";

export type CitationKind = "case" | "statute" | "rule" | "id" | "supra" | "short-case";

export type ParsedCitation = {
  kind: CitationKind;
  /** The exact matched text. */
  raw: string;
  /** Offset in the input string. */
  start: number;
  end: number;
  // case: volume/reporter/page; well_formed=false if reporter unknown or page missing
  volume?: string;
  reporter?: string;
  page?: string;
  well_formed?: boolean;
  // statute/rule
  title?: string;
  code?: string;
  section?: string;
  // supra/short-case: the party/name token it refers to
  refers_to?: string;
};

/**
 * Full case citation: "410 U.S. 113" / "123 Fake Rep. 45" (malformed).
 * The reporter is a run of abbreviation TOKENS each starting uppercase or
 * with a digit ("Cal. App. 5th") — a lowercase word ends the run, so the
 * pin-cite "950 F.3d at 106" no longer swallows " at" into the reporter
 * and prose like "15 U.S.C. class sizes exceed 40" no longer reads as a
 * malformed case (audit). Volume and reporter must share a line: a TOA
 * page-leader digit followed by a rule cite on the next line ("…1983 … 4\n
 * Fed. R. App. P. 32") is not a case citation.
 */
const CASE_RE =
  /\b(\d{1,4})[ \t]+([A-Z][A-Za-z0-9.']*(?:[ ][A-Z0-9][A-Za-z0-9.']*){0,5})[ \t]+(\d+)\b/g;

/** Federal statute: "28 U.S.C. § 1331". */
const STATUTE_USC_RE = /\b(\d+)\s+(U\.S\.C\.|C\.F\.R\.)\s+§+\s*([\d.]+[a-z0-9()]*)/g;

/** State code: "Cal. Rev. Stat. § 123" / "Tex. Code § 45.6". */
const STATUTE_STATE_RE = /\b([A-Z][a-z]+\.?\s+(?:Rev\.\s+)?(?:Stat\.|Code))\s+§+\s*([\d.]+)/g;

/** Procedural rule: "Fed. R. App. P. 32" / "FRAP 32" / "FRCP 12(b)". */
const RULE_RE =
  /\b(?:Fed\.\s*R\.\s*(?:Civ|App|Crim|Evid)\.\s*P\.|FRAP|FRCP)\s*§?\s*(\d+[a-z()0-9]*)/g;

/** "Id." at a token start. */
const ID_RE = /\bId\./gi;

/** "Roe, supra" / "Roe supra". */
const SUPRA_NAMED_RE = /\b([A-Z][A-Za-z]+)\s*,?\s+[Ss]upra\b/g;

/** Bare "supra" with no preceding name captured. */
const SUPRA_BARE_RE = /\b[Ss]upra\b/g;

/**
 * Citation signals that precede "supra" without being a case name — "See
 * supra Part II" captured "See" as the referenced authority and flagged a
 * ubiquitous internal cross-reference as dangling (audit).
 */
const SUPRA_SIGNAL_WORDS = new Set([
  "see",
  "compare",
  "accord",
  "contra",
  "cf",
  "but",
  "and",
  "also",
  "id",
  "the",
]);

/** "supra Part II" / "supra note 3" / "supra pp. 4-5" — an internal
 * cross-reference to this document, not a short-form authority cite. */
function isInternalCrossRef(text: string, endOfSupra: number): boolean {
  return /^\s*(?:part|note|section|§|p\.|pp\.|ch\.)/i.test(text.slice(endOfSupra, endOfSupra + 12));
}

/** Short-form case reference: "Brown v. Board". */
const SHORT_CASE_RE = /\b([A-Z][A-Za-z]+)\s+v\.\s+([A-Z][A-Za-z]+)\b/g;

/**
 * Extract every citation candidate from `text` and resolve overlaps,
 * preferring the more specific/longer match. Returns matches sorted by
 * `start`. Never throws.
 */
export function extractCitations(text: string): ParsedCitation[] {
  const candidates: ParsedCitation[] = [
    ...matchCases(text),
    ...matchStatutesUsc(text),
    ...matchStatutesState(text),
    ...matchRules(text),
    ...matchIds(text),
    ...matchSupraNamed(text),
    ...matchSupraBare(text),
    ...matchShortCases(text),
  ];
  return resolveOverlaps(candidates);
}

function matchCases(text: string): ParsedCitation[] {
  const out: ParsedCitation[] = [];
  for (const m of text.matchAll(CASE_RE)) {
    const volume = m[1] ?? "";
    const reporterRaw = m[2] ?? "";
    const page = m[3] ?? "";
    const reporter = reporterRaw.trim().replace(/\s+/g, " ");
    // A real reporter abbreviation carries a period ("U.S.", "F.3d", "N.W.2d")
    // or is a recognized period-less form. Without this guard the permissive
    // reporter group matched any capitalized run between two numbers, so an
    // ordinary address or quantity clause ("123 Main St Suite 4400", "10 Widget
    // Units 200") produced a malformed-citation candidate and a false CITE-001
    // accusation. Prose has no period and is not a known reporter — skip it.
    if (!reporter.includes(".") && !isKnownReporter(reporter)) continue;
    // A TOA page-leader digit followed by a rule citation ("… 4" + "Fed. R.
    // App. P. 32" on the next line, joined by flattening) is a RULE cite,
    // not a malformed case — and the longer bogus case match would swallow
    // it in overlap resolution (audit).
    if (/^Fed\.\s*R\./.test(reporter) || /^(?:FRAP|FRCP)\b/.test(reporter)) continue;
    const start = m.index ?? 0;
    out.push({
      kind: "case",
      raw: m[0],
      start,
      end: start + m[0].length,
      volume,
      reporter,
      page,
      well_formed: isKnownReporter(reporter) && page.length > 0,
    });
  }
  return out;
}

function matchStatutesUsc(text: string): ParsedCitation[] {
  const out: ParsedCitation[] = [];
  for (const m of text.matchAll(STATUTE_USC_RE)) {
    const start = m.index ?? 0;
    out.push({
      kind: "statute",
      raw: m[0],
      start,
      end: start + m[0].length,
      title: m[1],
      code: m[2],
      section: m[3],
    });
  }
  return out;
}

function matchStatutesState(text: string): ParsedCitation[] {
  const out: ParsedCitation[] = [];
  for (const m of text.matchAll(STATUTE_STATE_RE)) {
    const start = m.index ?? 0;
    out.push({
      kind: "statute",
      raw: m[0],
      start,
      end: start + m[0].length,
      code: m[1],
      section: m[2],
    });
  }
  return out;
}

function matchRules(text: string): ParsedCitation[] {
  const out: ParsedCitation[] = [];
  for (const m of text.matchAll(RULE_RE)) {
    const start = m.index ?? 0;
    out.push({
      kind: "rule",
      raw: m[0],
      start,
      end: start + m[0].length,
      section: m[1],
    });
  }
  return out;
}

function matchIds(text: string): ParsedCitation[] {
  const out: ParsedCitation[] = [];
  for (const m of text.matchAll(ID_RE)) {
    const start = m.index ?? 0;
    out.push({ kind: "id", raw: m[0], start, end: start + m[0].length });
  }
  return out;
}

function matchSupraNamed(text: string): ParsedCitation[] {
  const out: ParsedCitation[] = [];
  for (const m of text.matchAll(SUPRA_NAMED_RE)) {
    const start = m.index ?? 0;
    const end = start + m[0].length;
    // "See supra …" — the captured word is a signal, not an authority; an
    // internal cross-reference ("supra Part II") is not a citation at all.
    if (SUPRA_SIGNAL_WORDS.has((m[1] ?? "").toLowerCase())) continue;
    if (isInternalCrossRef(text, end)) continue;
    out.push({
      kind: "supra",
      raw: m[0],
      start,
      end,
      refers_to: m[1],
    });
  }
  return out;
}

function matchSupraBare(text: string): ParsedCitation[] {
  const out: ParsedCitation[] = [];
  for (const m of text.matchAll(SUPRA_BARE_RE)) {
    const start = m.index ?? 0;
    const end = start + m[0].length;
    if (isInternalCrossRef(text, end)) continue;
    out.push({ kind: "supra", raw: m[0], start, end });
  }
  return out;
}

function matchShortCases(text: string): ParsedCitation[] {
  const out: ParsedCitation[] = [];
  for (const m of text.matchAll(SHORT_CASE_RE)) {
    const start = m.index ?? 0;
    out.push({
      kind: "short-case",
      raw: m[0],
      start,
      end: start + m[0].length,
      refers_to: `${m[1]} v. ${m[2]}`,
    });
  }
  return out;
}

/** True when two [start, end) spans share any offset. */
function overlaps(a: ParsedCitation, b: ParsedCitation): boolean {
  return a.start < b.end && b.start < a.end;
}

/**
 * Resolve overlapping candidates by preferring the longer (more specific)
 * match, then the earlier start on ties; returns the survivors sorted by
 * `start`.
 */
function resolveOverlaps(candidates: ParsedCitation[]): ParsedCitation[] {
  const byPreference = [...candidates].sort((a, b) => {
    const lenA = a.end - a.start;
    const lenB = b.end - b.start;
    if (lenB !== lenA) return lenB - lenA;
    return a.start - b.start;
  });
  const selected: ParsedCitation[] = [];
  for (const candidate of byPreference) {
    if (!selected.some((s) => overlaps(s, candidate))) {
      selected.push(candidate);
    }
  }
  return selected.sort((a, b) => a.start - b.start);
}
