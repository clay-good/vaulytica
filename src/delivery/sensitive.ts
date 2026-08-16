/**
 * The sensitive-data pattern scan (spec-v9 §13/§14, HANDOFF-005). A
 * deterministic pass over the document text for data routinely meant to be
 * redacted before disclosure: SSN, EIN, payment-card (Luhn-validated),
 * bank-routing (ABA-checksum), context-gated DOB, and lower-confidence email
 * and phone.
 *
 * Honesty contract (§14, the corollary-3 step): a hit is phrased as "N spans
 * match SSN format", never "contains N SSNs", and the scan never reports its
 * silence as a clean bill of health. Every matched value is **masked** before
 * it is stored (§Part XIV invariant) — the report warning about exposed PII
 * never reproduces it.
 *
 * Every pattern is linear and the scanned text is length-bounded, preserving
 * the repo's ReDoS-free guarantee.
 */

import type { SensitiveFact } from "./types.js";
import { maskDigits, maskEmail, luhnValid, ssnStructurallyValid } from "./mask.js";

/** Cap the scanned text — a 5 MB body is already an enormous document. */
const MAX_SCAN_CHARS = 5 * 1024 * 1024;
/** Cap distinct hits per type so a pathological input cannot produce unbounded output. */
const MAX_PER_TYPE = 200;

const SSN = /\b(\d{3})-(\d{2})-(\d{4})\b/g;
const EIN = /\b(\d{2})-(\d{7})\b/g;
// First alternative: the 4-4-4-… grouping (Visa/MC 16-digit, and a contiguous
// 15-digit Amex, whose last group absorbs into \d{1,7}). Second: American
// Express's canonical *spaced* 4-6-5 grouping ("3782 822463 10005"), which the
// first alternative cannot form once the separators are present. Every hit is
// Luhn-gated below, so the broader pattern cannot surface a non-card run.
const CARD = /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}\b|\b\d{4}[ -]\d{6}[ -]\d{5}\b/g;
const ROUTING = /\b(\d{9})\b/g;
const DOB = /(?:DOB|D\.O\.B\.|date of birth)\D{0,20}(\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4})/gi;
const EMAIL = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b/g;
const PHONE = /\b(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b/g;

export function scanSensitive(text: string): SensitiveFact[] {
  const body = text.length > MAX_SCAN_CHARS ? text.slice(0, MAX_SCAN_CHARS) : text;
  const out: SensitiveFact[] = [];
  // Dedup on the RAW value per type, so a value repeated across the document
  // counts once and the output stays bounded and meaningful.
  //
  // Keying on the *masked* value instead silently merged genuinely different
  // values: masking reveals only a suffix, so `alice@example.com` and
  // `adam@example.com` both mask to `a***@example.com`, and `123-45-6789` and
  // `234-56-6789` both mask to `***-**-6789` — the second value vanished from
  // the count and the evidence, under-reporting how much sensitive data the
  // document actually carries. Every revealing type (ssn/ein/card/routing/
  // phone reveal a suffix, email reveals one character) had the same collision.
  //
  // Separators are stripped and case folded so the same value written two ways
  // ("123-45-6789" / "123456789") still counts once. Raw values are used only
  // as set keys and never leave this function — `out` carries masks alone.
  const seen = new Set<string>();
  const push = (
    type: string,
    confidence: SensitiveFact["confidence"],
    masked: string,
    raw: string,
  ): void => {
    const key = `${type}:${raw.toLowerCase().replace(/[^a-z0-9@.]/g, "")}`;
    if (seen.has(key)) return;
    const perType = out.filter((f) => f.type === type).length;
    if (perType >= MAX_PER_TYPE) return;
    seen.add(key);
    out.push({ type, confidence, masked });
  };

  let m: RegExpExecArray | null;

  while ((m = SSN.exec(body)) !== null) {
    if (ssnStructurallyValid(m[1]!, m[2]!, m[3]!)) {
      push("ssn", "high", maskDigits(m[0], 4), m[0]);
    }
  }
  while ((m = EIN.exec(body)) !== null) {
    push("ein", "medium", maskDigits(m[0], 3), m[0]);
  }
  while ((m = CARD.exec(body)) !== null) {
    if (luhnValid(m[0])) push("card", "high", maskDigits(m[0], 4), m[0]);
  }
  while ((m = ROUTING.exec(body)) !== null) {
    if (abaValid(m[1]!)) push("routing", "medium", maskDigits(m[0], 2), m[0]);
  }
  while ((m = DOB.exec(body)) !== null) {
    push("dob", "medium", maskDigits(m[1]!, 0), m[1]!);
  }
  while ((m = EMAIL.exec(body)) !== null) {
    push("email", "low", maskEmail(m[0]), m[0]);
  }
  while ((m = PHONE.exec(body)) !== null) {
    push("phone", "low", maskDigits(m[0], 4), m[0]);
  }

  // Canonical order: by type then masked value, so the hash is stable.
  out.sort((a, b) => (a.type === b.type ? cmp(a.masked, b.masked) : cmp(a.type, b.type)));
  return out;
}

/** ABA routing-number checksum — suppresses random 9-digit runs. */
function abaValid(digits: string): boolean {
  if (digits.length !== 9) return false;
  const d = [...digits].map((c) => c.charCodeAt(0) - 48);
  const sum = 3 * (d[0]! + d[3]! + d[6]!) + 7 * (d[1]! + d[4]! + d[7]!) + (d[2]! + d[5]! + d[8]!);
  return sum % 10 === 0 && sum > 0;
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
