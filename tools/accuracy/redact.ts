/**
 * Corpus redaction tool (spec-v5 §4, Step 67).
 *
 * Mechanically scrubs identifying detail from a corpus document and logs the
 * scrub, so a third party can confirm the redaction masked *identities only*
 * and did not perturb the structural features the engine reads (clause
 * headings, defined terms, governing-law phrasing survive untouched — only
 * identities are masked). Deterministic: same input → same redacted text and
 * same log, every time.
 *
 * This is a mechanical first pass for the structured PII categories (emails,
 * phone numbers, SSN/EIN, account numbers). Party-name masking is *not*
 * guessed — names are supplied explicitly by the human preparing the document
 * (`partyNames`), because a regex cannot reliably tell "Acme Corporation" the
 * party from "the Corporation" the common noun, and a wrong guess would
 * corrupt the very defined-term structure the engine depends on.
 */

import type { RedactionEntry } from "./schema.js";

export type RedactionResult = {
  text: string;
  log: RedactionEntry[];
};

type Pattern = {
  kind: RedactionEntry["kind"];
  re: RegExp;
  replacement: string;
};

// Order matters: more specific patterns first so an email isn't half-masked
// by the phone pattern. All patterns are global + case-insensitive where
// relevant. None touch clause/heading/defined-term structure.
const PATTERNS: Pattern[] = [
  {
    kind: "email",
    re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
    replacement: "[EMAIL]",
  },
  {
    // North-American phone numbers in common shapes. Run before the dash-
    // number id pattern so a phone's "555-0199" tail isn't half-masked.
    kind: "phone",
    re: /(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g,
    replacement: "[PHONE]",
  },
  {
    // US EIN (12-3456789) and SSN (123-45-6789).
    kind: "account-number",
    re: /\b\d{2,3}-\d{2,7}(?:-\d{4})?\b/g,
    replacement: "[ID-NUMBER]",
  },
  {
    // Long bare account / routing numbers (10+ digits).
    kind: "account-number",
    re: /\b\d{10,}\b/g,
    replacement: "[ACCOUNT]",
  },
];

/**
 * Redact a document. `partyNames` are exact strings the preparer wants masked
 * (e.g. the parties' legal names); each maps to a stable placeholder
 * `[PARTY-1]`, `[PARTY-2]`, … assigned in the order given so the redaction is
 * reproducible and the document stays internally consistent.
 */
export function redact(text: string, partyNames: ReadonlyArray<string> = []): RedactionResult {
  let out = text;
  const log: RedactionEntry[] = [];

  // Party names first — longest first so "Acme Corporation, Inc." is masked
  // before a substring "Acme Corporation" would be.
  const ordered = [...partyNames]
    .map((name, i) => ({ name, placeholder: `[PARTY-${i + 1}]` }))
    .sort((a, b) => b.name.length - a.name.length);
  for (const { name, placeholder } of ordered) {
    if (!name) continue;
    const re = new RegExp(escapeRegExp(name), "g");
    let count = 0;
    out = out.replace(re, () => {
      count++;
      return placeholder;
    });
    if (count > 0) {
      log.push({ kind: "party-name", count, replacement: placeholder });
    }
  }

  for (const p of PATTERNS) {
    let count = 0;
    out = out.replace(p.re, () => {
      count++;
      return p.replacement;
    });
    if (count > 0) {
      // Merge into an existing entry for the same kind+replacement.
      const existing = log.find((e) => e.kind === p.kind && e.replacement === p.replacement);
      if (existing) existing.count += count;
      else log.push({ kind: p.kind, count, replacement: p.replacement });
    }
  }

  // Stable log order: by kind then replacement, so the provenance record is
  // byte-reproducible regardless of pattern evaluation order.
  log.sort((a, b) =>
    a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : a.replacement < b.replacement ? -1 : 1,
  );
  return { text: out, log };
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
