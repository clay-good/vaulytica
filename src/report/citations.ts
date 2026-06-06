/**
 * Citation formatting for the report (spec §21, build step 9).
 *
 * US legal materials (`U.S.C.`, `C.F.R.`, public-law citations) are
 * formatted in a simple Bluebook flavor:
 *
 *   9 U.S.C. § 2 (2024) — https://uscode.house.gov/...
 *
 * Everything else falls back to a plain `Source Name — URL` line.
 * The output is intended for both the inline finding citation footnotes
 * and the audit-trail bibliography.
 */

import type { SourceCitation } from "../dkb/types.js";

/**
 * Pattern that matches the most common US legal citation forms in the
 * `source` field. We anchor on common reporter-style strings rather
 * than parsing the URL, because the URL alone is not authoritative
 * (the eCFR mirror, govinfo.gov, and Cornell LII all serve the same
 * statute).
 */
const US_LEGAL_PATTERNS: RegExp[] = [
  /\bU\.?S\.?C\.?\s*§/i,        // 9 U.S.C. § 2
  /\bC\.?F\.?R\.?\s*§/i,        // 17 C.F.R. § 240
  /\bPub\.?\s*L\.?\s*\d/i,       // Pub. L. 116-...
  /\bStat\.?\s*\d/i,             // 86 Stat. 1241
  /\bU\.?S\.?\s+\d+\b/,          // 410 U.S. 113
  /^[A-Z][a-z]+\.?\s*(?:Code|Stat\.?|Rev\.?)\s*§/, // Cal. Civ. Code § 1542
  /\bUCC\s*§/i,                  // UCC § 2-201
];

function isUsLegalCitation(source: string): boolean {
  return US_LEGAL_PATTERNS.some((p) => p.test(source));
}

function publishedYear(source: SourceCitation): string | undefined {
  const stamp = source.source_published_at ?? source.retrieved_at;
  const m = stamp?.match(/^(\d{4})/);
  return m?.[1];
}

/**
 * Render a single citation as a one-line string suitable for either
 * the inline finding callout or the bibliography list.
 */
export function formatCitation(source: SourceCitation): string {
  const year = publishedYear(source);
  const yearPart = isUsLegalCitation(source.source) && year ? ` (${year})` : "";
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
export function formatBibliographyEntry(index: number, source: SourceCitation): string {
  const parts: string[] = [];
  parts.push(`[${index}]`);
  parts.push(formatCitation(source));
  if (source.attribution) parts.push(`(${source.attribution})`);
  // Render the retrieval/license segment honestly (spec-v8 §14): a cited
  // custom-playbook rule with no retrieval date must not print
  // "[retrieved ; license: Team policy]" with a blank date.
  const retrieved = source.retrieved_at?.trim();
  const license = source.license?.trim();
  if (retrieved && license) parts.push(`[retrieved ${retrieved}; license: ${license}]`);
  else if (retrieved) parts.push(`[retrieved ${retrieved}]`);
  else if (license) parts.push(`(cited — ${license})`);
  return parts.join(" ");
}
