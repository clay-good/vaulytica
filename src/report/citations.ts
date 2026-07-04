/**
 * Citation formatting for the report (spec §21, build step 9; spec-v8 §16).
 *
 * US statutory/reporter materials (`U.S.C.`, `C.F.R.`, public-law
 * citations, US reporters) are formatted in a simple Bluebook flavor
 * with a parenthetical year, because that year is conventional and is
 * *not* part of the citation itself:
 *
 *   9 U.S.C. § 2 (2024) — https://uscode.house.gov/...
 *
 * The other legal-material families the DKB actually cites — EU/GDPR
 * regulations and directives, ISO/NIST standards, and secondary sources
 * (Restatements, model/uniform acts) — already carry their identifying
 * year *inside* the citation (`Regulation (EU) 2016/679`, `ISO/IEC
 * 27001:2022`, `NIST SP 800-53 Rev. 5`), so the formatter renders them
 * verbatim and does **not** append a redundant retrieval-year. Every
 * family passes the `source` string through unchanged, so pinpoint
 * subsections (`45 C.F.R. § 164.410(a)(1)`) are preserved, never
 * truncated to the base section.
 *
 * The classification is a pure, fixed pattern table (no model) and is
 * extended only to forms the DKB actually contains — the coverage matrix
 * in `docs/v8/citation-standard.md` §3 is the source of truth, and each
 * family is pinned by an exact-string fixture in `citations.test.ts`.
 *
 * The output is intended for both the inline finding citation footnotes
 * and the audit-trail bibliography.
 */

import type { SourceCitation } from "../dkb/types.js";

/**
 * The legal-material families the formatter recognizes. `us-statutory`
 * takes a Bluebook parenthetical year; every other family renders the
 * `source` verbatim (the identifying year is already embedded).
 */
export type CitationFamily = "us-statutory" | "eu" | "standard" | "secondary" | "other";

/**
 * US statutory / reporter forms. We anchor on common reporter-style
 * strings rather than parsing the URL, because the URL alone is not
 * authoritative (the eCFR mirror, govinfo.gov, and Cornell LII all serve
 * the same statute). These are the only forms that take an appended
 * parenthetical year.
 */
const US_LEGAL_PATTERNS: RegExp[] = [
  /\bU\.?S\.?C\.?\s*§/i, // 9 U.S.C. § 2
  /\bC\.?F\.?R\.?\s*§/i, // 17 C.F.R. § 240; 45 C.F.R. § 164.410(a)(1)
  /\bPub\.?\s*L\.?\s*\d/i, // Pub. L. 116-...
  /\bStat\.?\s*\d/i, // 86 Stat. 1241
  /\bU\.?S\.?\s+\d+\b/, // 410 U.S. 113
  /^[A-Z][a-z]+\.?\s*(?:Code|Stat\.?|Rev\.?)\s*§/, // Cal. Civ. Code § 1542
  /\bUCC\s*§/i, // UCC § 2-201
];

/**
 * EU / international instruments. The year (e.g. `2016/679`) is intrinsic
 * to the citation, so no parenthetical is appended.
 */
const EU_PATTERNS: RegExp[] = [
  /\bGDPR\b/i, // GDPR Art. 28; UK GDPR
  /\bRegulation\s*\(EU\)\s*\d{4}\/\d+/i, // Regulation (EU) 2016/679
  /\bDirective\s*\d{4}\/\d+/i, // Directive 2016/680; 2002/58/EC
];

/**
 * Standards-body materials. The version/edition (`:2022`, `Rev. 5`) is
 * intrinsic to the citation.
 */
const STANDARD_PATTERNS: RegExp[] = [
  /\bISO(?:\/IEC)?\s*\d/i, // ISO/IEC 27001:2022
  /\bNIST\b/i, // NIST SP 800-53 Rev. 5; NIST AI RMF 1.0
];

/**
 * Secondary sources — Restatements and model/uniform acts.
 */
const SECONDARY_PATTERNS: RegExp[] = [
  /\bRestatement\b/i, // Restatement (Third) of Unfair Competition § 39
  /\b(?:Model|Uniform)\s+[A-Z]/, // Uniform Easement Relocation Act; ABA Model Rule
];

/**
 * Classify a citation `source` into one of the recognized families. The
 * order is significant: US statutory patterns win first (a `17 C.F.R.`
 * embedded in an SEC-rule citation is still US-statutory), then EU,
 * standards, and secondary. Anything unmatched is `other` and renders as
 * a flat `Source — URL`.
 */
export function citationFamily(source: string): CitationFamily {
  if (US_LEGAL_PATTERNS.some((p) => p.test(source))) return "us-statutory";
  if (EU_PATTERNS.some((p) => p.test(source))) return "eu";
  if (STANDARD_PATTERNS.some((p) => p.test(source))) return "standard";
  if (SECONDARY_PATTERNS.some((p) => p.test(source))) return "secondary";
  return "other";
}

function publishedYear(source: SourceCitation): string | undefined {
  const stamp = source.source_published_at ?? source.retrieved_at;
  const m = stamp?.match(/^(\d{4})/);
  return m?.[1];
}

/**
 * The ISO calendar date (YYYY-MM-DD) embedded in an ISO 8601 timestamp,
 * or `undefined` if the stamp is empty/unparseable. Pure and
 * deterministic — it only reshapes the *stored* timestamp; it never reads
 * a clock, so the freshness signal stays posture-clean (spec-v8 §17). We
 * surface the retrieval *date*, never a computed elapsed-days "age",
 * because elapsed time depends on when the report is opened and would
 * break determinism.
 */
function isoDate(stamp: string | undefined): string | undefined {
  const m = stamp?.trim().match(/^(\d{4}-\d{2}-\d{2})/);
  return m?.[1];
}

/**
 * The reader-facing freshness signal: how old the *pinned* source text is,
 * stated as the retrieval date and (when genuinely known) the source's
 * publication date. Honest and inert — it never auto-refetches and draws
 * no automated staleness line (spec-v8 Open Q #4); the date itself is the
 * signal. Returns `undefined` when no retrieval date is recorded (the
 * URL-less custom-playbook case), so callers omit the segment cleanly.
 */
export function freshnessSignal(source: SourceCitation): string | undefined {
  const retrieved = isoDate(source.retrieved_at);
  if (!retrieved) return undefined;
  const published = isoDate(source.source_published_at);
  return published ? `published ${published}, retrieved ${retrieved}` : `retrieved ${retrieved}`;
}

/**
 * Citation-currency reference (fix-legal-authority-currency): the anchor
 * date and horizon a renderer uses to decide whether a cited authority is
 * old enough to need re-verification. `as_of` is the DKB's own `built_at`
 * — never the wall clock — so identical inputs render identical labels on
 * any machine, forever.
 */
export type CitationCurrency = { as_of: string; horizon_months: number };

/** Default currency horizon when the DKB manifest carries no knob. */
export const DEFAULT_CURRENCY_HORIZON_MONTHS = 12;

/** Build a {@link CitationCurrency} from a DKB manifest. */
export function dkbCurrency(manifest: {
  built_at: string;
  currency_horizon_months?: number;
}): CitationCurrency {
  return {
    as_of: manifest.built_at,
    horizon_months: manifest.currency_horizon_months ?? DEFAULT_CURRENCY_HORIZON_MONTHS,
  };
}

/**
 * "verify currency (retrieved <date>)" when the citation's retrieval date
 * is more than `horizon_months` before `as_of`; `undefined` otherwise.
 * Pure calendar arithmetic on the two ISO dates — no wall clock.
 */
export function currencyLabel(
  source: SourceCitation,
  currency: CitationCurrency | undefined,
): string | undefined {
  if (!currency) return undefined;
  const retrieved = isoDate(source.retrieved_at);
  const asOf = isoDate(currency.as_of);
  if (!retrieved || !asOf) return undefined;
  const [ry, rm, rd] = retrieved.split("-").map(Number);
  const [ay, am, ad] = asOf.split("-").map(Number);
  // The node ages out the day after `retrieved + horizon months`. Date.UTC
  // on the two *stored* dates — never a clock read — so the label is a pure
  // function of (citation, DKB build date).
  const threshold = Date.UTC(ry!, rm! - 1 + currency.horizon_months, rd!);
  if (Date.UTC(ay!, am! - 1, ad!) <= threshold) return undefined;
  return `verify currency (retrieved ${retrieved})`;
}

/**
 * Split a string into wrap-friendly segments whose concatenation is the
 * original text exactly (no characters added or removed). A long unbroken
 * token — in practice a citation URL — is sub-split *after* a
 * break-friendly character (`/ ? & = . _ -`) so a renderer can place a
 * wrap opportunity between segments: in DOCX, between adjacent `TextRun`s;
 * in HTML, the `<wbr>`-equivalent `overflow-wrap: anywhere`. This is the
 * never-truncate / always-wrap mechanism of spec-v8 §18 — because the
 * segments rejoin to the original, the citation always renders in full.
 *
 * Pure and deterministic: identical input → identical segmentation.
 */
export function breakLongTokens(text: string, maxToken = 24): string[] {
  const segments: string[] = [];
  for (const token of text.split(/(\s+)/)) {
    if (token.length === 0) continue;
    if (token.length <= maxToken || /^\s+$/.test(token)) {
      segments.push(token);
      continue;
    }
    let chunk = "";
    for (const ch of token) {
      chunk += ch;
      if (/[/?&=._-]/.test(ch) && chunk.length >= 8) {
        segments.push(chunk);
        chunk = "";
      }
    }
    if (chunk.length > 0) segments.push(chunk);
  }
  return segments;
}

/**
 * Render a single citation as a one-line string suitable for either
 * the inline finding callout or the bibliography list.
 */
export function formatCitation(source: SourceCitation): string {
  const year = publishedYear(source);
  // Only US statutory/reporter forms take a Bluebook parenthetical year;
  // EU/standards/secondary forms embed their identifying year already
  // (spec-v8 §16). The `source` is never rewritten, so pinpoint
  // subsections survive intact.
  const yearPart = citationFamily(source.source) === "us-statutory" && year ? ` (${year})` : "";
  const head = `${source.source}${yearPart}`;
  // Omit the " — URL" segment when there is no URL (spec-v8 §14): a cited
  // custom-playbook rule with no source_url must render cleanly as
  // "Policy 4.2", not "Policy 4.2 — " with a dangling em-dash.
  const url = source.source_url?.trim();
  return url ? `${head} — ${url}` : head;
}

/**
 * Bibliography-form citation. Same content as the inline form but
 * starts with a leading number and includes the attribution string
 * when present, retrieval date, and license. Suitable for the
 * audit-trail "Bibliography" section.
 */
export function formatBibliographyEntry(
  index: number,
  source: SourceCitation,
  currency?: CitationCurrency,
): string {
  const parts: string[] = [];
  parts.push(`[${index}]`);
  parts.push(formatCitation(source));
  if (source.attribution) parts.push(`(${source.attribution})`);
  // Surface the genuine publication date when known (spec-v8 §17). Never
  // fabricated: this renders only when the field is populated, so a source
  // whose real publication date is unknown shows nothing here — additive,
  // zero golden churn for the citations that lack it.
  const published = isoDate(source.source_published_at);
  if (published) parts.push(`(published ${published})`);
  // Render the retrieval/license segment honestly (spec-v8 §14): a cited
  // custom-playbook rule with no retrieval date must not print
  // "[retrieved ; license: Team policy]" with a blank date.
  const retrieved = source.retrieved_at?.trim();
  const license = source.license?.trim();
  if (retrieved && license) parts.push(`[retrieved ${retrieved}; license: ${license}]`);
  else if (retrieved) parts.push(`[retrieved ${retrieved}]`);
  else if (license) parts.push(`(cited — ${license})`);
  // Citation-currency label (fix-legal-authority-currency): flags a node
  // retrieved further back than the DKB's horizon, relative to the DKB's
  // own build date — deterministic, never wall-clock.
  const stale = currencyLabel(source, currency);
  if (stale) parts.push(`⚠ ${stale}`);
  return parts.join(" ");
}
