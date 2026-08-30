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
  /\b(\d{1,4})[ \t]+([A-Z][A-Za-z0-9.'’]*(?:[ ](?:[A-Z][A-Za-z0-9.'’]*|\d+[A-Za-z][A-Za-z0-9.'’]*)){0,5})[ \t]+(\d+)\b/g;

/**
 * Federal statute: "28 U.S.C. § 1331", and — the form the Supreme Court's own
 * rules prescribe — "28 U.S.C. 1254(1)" with no section sign at all. Without
 * the optional form, a cert petition's table of authorities read as TWO
 * malformed case citations, "28 U.S.C. 1254" being volume 28 of a reporter
 * called "U.S.C." that no reporter table knows.
 */
const STATUTE_USC_RE = /\b(\d+)\s+(U\.S\.C\.|C\.F\.R\.)\s+(?:§+\s*)?([\d.]+[a-z0-9()]*)/g;

/**
 * State statute, section-sign form. A run of jurisdiction/subject abbreviation
 * tokens (each capitalized and period-terminated — "Cal.", "N.Y.", "Gen.",
 * "Bus." — or a literal "&") followed by a code-type keyword (Code / Stat. /
 * Laws / Law / Statutes), an optional "Ann.", an optional "tit."/"ch."
 * subdivision, and a "§" section. Requiring each prefix token to be a
 * period-terminated abbreviation is what keeps ordinary capitalized prose
 * ("The Board Approved Plan § 4") from reading as a statute, while still
 * capturing the FULL jurisdiction name ("Cal. Civ. Code § 1234", not the bare
 * "Civ. Code" the old anchor-on-Code pattern produced). A leading title number
 * ("42 Pa. Cons. Stat. § 8542") is captured when present.
 */
const STATUTE_STATE_RE =
  /\b(\d{1,4}\s+)?((?:(?:[A-Z][A-Za-z'’.]*\.|&)\s+)+(?:Code|Codes|Stat\.|Stats\.|Statutes|Laws|Law))(\s+Ann\.)?(?:\s+(?:tit\.|ch\.)\s*[\w-]+,?)?\s*§+\s*(\d+[\d.\-a-z()]*)/g;

/**
 * Illinois Compiled Statutes, "740 ILCS 5/2" / "740 Ill. Comp. Stat. 14/15".
 * Distinctive chapter/section slash form with no "§". Without this the leading
 * "740 Ill. Comp. Stat. 14" read as a malformed CASE citation (unknown
 * reporter "Ill. Comp. Stat.") and drew a false CITE-001 accusation against a
 * perfectly valid statute. Captured whole so it wins overlap resolution over
 * the shorter bogus case candidate.
 */
const STATUTE_ILCS_RE = /\b(\d{1,4})\s+(ILCS|Ill\.\s+Comp\.\s+Stat\.)\s+(\d+\/[\d.]+[a-z0-9()]*)/g;

/**
 * Procedural / evidentiary rule: "Fed. R. App. P. 32" / "FRAP 32" /
 * "FRCP 12(b)" / "Fed. R. Evid. 403" / "Fed. R. Bankr. P. 3002".
 *
 * The Rules of Civil/Appellate/Criminal/Bankruptcy PROCEDURE end in "P.", but
 * the Rules of EVIDENCE do not — they are cited "Fed. R. Evid. 403" with no
 * trailing "P.". The old pattern demanded "Evid. P.", a form that never occurs,
 * so every Federal Rule of Evidence citation was silently missed. Evidence is
 * now its own branch, and Bankruptcy Procedure plus the FRE / FRBP shorthands
 * are recognized. Each alternative still requires an immediately-following rule
 * number, so a bare acronym in prose ("the FRE report") is not a citation.
 */
const RULE_RE =
  /\b(?:Fed\.\s*R\.\s*(?:Civ|App|Crim|Bankr)\.\s*P\.|Fed\.\s*R\.\s*Evid\.|FRAP|FRCP|FRBP|FRE)\s*§?\s*(\d+[a-z()0-9]*)/g;

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
    if (/^Fed\.\s*R\./.test(reporter) || /^(?:FRAP|FRCP|FRBP|FRE)\b/.test(reporter)) continue;
    // "U.S.C." and "C.F.R." are CODE titles, never reporters. Written without
    // the section sign — "28 U.S.C. 1254(1)", the form the Supreme Court's own
    // rules prescribe — the case pattern reads the same span as the statute
    // pattern, and the tie was resolved against the statute.
    if (/^(?:U\.S\.C\.|C\.F\.R\.)$/.test(reporter)) continue;
    // An IDENTIFIER NUMBER is not a citation. A motion's signature block runs
    // a phone number into an attorney registration number — "(312) 555-0192
    // ARDC No. 6318842" — and "0192 ARDC No. 6318842" parsed as volume,
    // reporter, page, drawing a malformed-citation finding against a filing
    // with none. Two independent tells, either of which is decisive: a
    // reporter abbreviation never ends in "No.", and a volume never carries a
    // leading zero.
    if (/\bNos?\.$/.test(reporter)) continue;
    if (/^0\d/.test(volume)) continue;
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
    const code = `${(m[1] ?? "").trim()} ${m[2] ?? ""}${m[3] ?? ""}`.trim();
    out.push({
      kind: "statute",
      raw: m[0],
      start,
      end: start + m[0].length,
      title: m[1]?.trim() || undefined,
      code,
      section: m[4],
    });
  }
  for (const m of text.matchAll(STATUTE_ILCS_RE)) {
    const start = m.index ?? 0;
    out.push({
      kind: "statute",
      raw: m[0],
      start,
      end: start + m[0].length,
      title: m[1],
      code: `${m[1] ?? ""} ${m[2] ?? ""}`.trim(),
      section: m[3],
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
