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
import {
  maskAlphanumeric,
  maskDigits,
  maskEmail,
  luhnValid,
  ssnStructurallyValid,
  itinStructurallyValid,
} from "./mask.js";

/** Cap the scanned text — a 5 MB body is already an enormous document. */
export const MAX_SCAN_CHARS = 5 * 1024 * 1024;

/**
 * Did the cap actually bite? Exported because the truncation must be SAID.
 *
 * Everything past `MAX_SCAN_CHARS` is invisible to the scan, and for a check
 * whose whole proposition is "this document is safe to send" a silently partial
 * read is the worst possible failure: an SSN a megabyte past the cap produces
 * the same clean report as a document that has none. `readContainer` composes
 * this into the report's `note`, beside the PDF scan's own reach caveat.
 */
export function sensitiveScanTruncated(text: string): boolean {
  return text.length > MAX_SCAN_CHARS;
}
/** Cap distinct hits per type so a pathological input cannot produce unbounded output. */
export const MAX_PER_TYPE = 200;

/**
 * Which types hit the per-type cap, so the caveat can name them.
 *
 * Same rule as `sensitiveScanTruncated`: a bound that is not SAID is a number
 * the reader trusts and should not. The finding still fires when the cap bites —
 * the document is never called clean — but its count becomes a floor rather
 * than a total, and "247 SSNs" and "200 SSNs" are different facts to act on.
 */
export function cappedTypes(facts: readonly SensitiveFact[]): SensitiveFact["type"][] {
  const counts = new Map<SensitiveFact["type"], number>();
  for (const f of facts) counts.set(f.type, (counts.get(f.type) ?? 0) + 1);
  return [...counts]
    .filter(([, n]) => n >= MAX_PER_TYPE)
    .map(([t]) => t)
    .sort();
}

const SSN = /\b(\d{3})-(\d{2})-(\d{4})\b/g;
// The same nine digits written with no separators — the form a spreadsheet
// cell, an unformatted intake field or OCR output produces. Nothing else caught
// it: it has no dashes for `SSN`, and while `ROUTING` does scan bare 9-digit
// runs it drops everything failing the ABA checksum, so a bare SSN produced no
// finding at all and went out unmasked. This module's own dedup comment already
// treats "123-45-6789" and "123456789" as one SSN, so the bare form was always
// meant to be reachable. Reported at LOW confidence, because nine bare digits
// are genuinely ambiguous (an invoice or part number can look identical) and
// the §14 honesty contract phrases every hit as "spans match SSN format"
// rather than as a count of SSNs. Still gated on `ssnStructurallyValid`.
const SSN_BARE = /\b(\d{3})(\d{2})(\d{4})\b/g;
/** An ITIN in the dashed form. Structure is checked by `itinStructurallyValid`. */
const ITIN = /\b(9\d{2})-(\d{2})-(\d{4})\b/g;
const EIN = /\b(\d{2})-(\d{7})\b/g;
// First alternative: the 4-4-4-… grouping (Visa/MC 16-digit, and a contiguous
// 15-digit Amex, whose last group absorbs into \d{1,7}). Second: American
// Express's canonical *spaced* 4-6-5 grouping ("3782 822463 10005"), which the
// first alternative cannot form once the separators are present. Every hit is
// Luhn-gated below, so the broader pattern cannot surface a non-card run.
const CARD = /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}\b|\b\d{4}[ -]\d{6}[ -]\d{5}\b/g;
const ROUTING = /\b(\d{9})\b/g;
const DOB = /(?:DOB|D\.O\.B\.|date of birth)\D{0,20}(\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4})/gi;
/**
 * Driver's-licence and passport numbers — LABEL-GATED, like the DOB above.
 *
 * 🚨 CCPA § 1798.140(ae)(1)(A) names four identifiers in one sentence: "a
 * consumer's social security, **driver's license**, state identification card,
 * or **passport** number". This scan detected the first and neither of the
 * other two, so a document carrying a licence or passport number was reported
 * clean before disclosure — the failure direction that matters most in this
 * module.
 *
 * 🥇 They have to be label-gated and the DOB detector shows why. A driver's
 * licence number has **no national format** (California `D1234567`, New York
 * nine digits, Florida a letter plus twelve), and a US passport number is nine
 * alphanumerics with no checksum. A bare pattern for either would match a
 * contract number, an invoice reference or a policy number on every second
 * page. The label is the evidence, so these are `medium` confidence: the
 * document said what the value is, and nothing verifies the value itself.
 */
const DRIVER_LICENCE =
  /\b(?:driver['’]?s?|driving)\s+licen[sc]e\s*(?:no\.?|number|#)?\s*[:#]?\s*([A-Za-z0-9][A-Za-z0-9-]{4,17}[A-Za-z0-9])\b/gi;
/**
 * The rest of the identifiers the statutes this tool cites actually name.
 *
 * A positive control over the whole scanner — plant each identifier in turn —
 * showed the labelled ones below were not detected at all. Each is named in a
 * rule the engine already cites elsewhere:
 *
 *   - **state identification card number** completes CCPA
 *     § 1798.140(ae)(1)(A)'s four ("social security, driver's license, state
 *     identification card, or passport");
 *   - **medical record number** and **health plan beneficiary number** are
 *     HIPAA identifiers 6 and 7, 45 C.F.R. § 164.514(b)(2)(i)(F)–(G).
 *
 * Label-gated for the same reason as the licence and passport: none has a
 * format to recognise, and a bare pattern would match an invoice or a policy
 * number on every page.
 *
 * ⚠️ The captured value admits hyphens and NEVER a space. Allowing one let the
 * capture walk out of the identifier and into the sentence — "MRN-8842119 for
 * the patient" masked as `***-******* *** the`, which puts three words of the
 * document into evidence that is supposed to be a mask and nothing else.
 *
 * 🥇 And it must contain a DIGIT, because a document that ENUMERATES these
 * categories is not a document that contains them. `data-sharing.txt` defines
 * PHI as "…Social Security number, **medical record number**, health plan
 * number, account number…", and the label matched with the following word as
 * its value: two findings whose evidence was the mask `***ber` — the word
 * "number". An identifier without a digit is a word.
 *
 * That is the mirror of the `hipaa-names` fix in 9.675.0 and worth holding
 * both ways: for a CATEGORY extractor a list of categories is the signal, and
 * for a VALUE scanner the same list is the noise.
 */
const STATE_ID =
  /\bstate\s+(?:identification|id)\s+(?:card\s+)?(?:no\.?|number|#)?\s*[:#]?\s*([A-Za-z0-9][A-Za-z0-9-]{4,17}[A-Za-z0-9])\b/gi;
const MEDICAL_RECORD =
  /\b(?:medical\s+record|MRN)\s*(?:no\.?|number|#)?\s*[:#]?\s*([A-Za-z0-9][A-Za-z0-9-]{3,17}[A-Za-z0-9])\b/gi;
const HEALTH_PLAN =
  /\bhealth\s+plan\s+(?:beneficiary|member|subscriber)\s*(?:no\.?|number|#|id)?\s*[:#]?\s*([A-Za-z0-9][A-Za-z0-9-]{3,17}[A-Za-z0-9])\b/gi;

const PASSPORT = /\bpassports?\s*(?:no\.?|number|#)?\s*[:#]?\s*([A-Za-z0-9]{6,9})\b/gi;

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
    // Digit-based types carry pure formatting noise — "123-45-6789" and
    // "123456789" are one SSN — so they normalize by stripping separators.
    // An email must NOT: `+`, `_`, `%` and `-` are significant in a local
    // part, and stripping them merged user+tag@example.com with
    // usertag@example.com. That reintroduced, one layer down, the very
    // under-count that keying on the raw value instead of the masked value
    // was added to fix.
    const normalized =
      type === "email" ? raw.toLowerCase() : raw.toLowerCase().replace(/[^a-z0-9@.]/g, "");
    const key = `${type}:${normalized}`;
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
  while ((m = SSN_BARE.exec(body)) !== null) {
    // A validated bank routing number is not a Social Security Number. Wire and
    // ACH details are ordinary contract content, and nine digits that satisfy
    // the ABA checksum are overwhelmingly a routing number — which the ROUTING
    // scan below already reports. Without this the same span was pushed twice,
    // under two types, because dedup keys include the type.
    if (ssnStructurallyValid(m[1]!, m[2]!, m[3]!) && !abaValid(m[0])) {
      // Dedup normalizes digit types by stripping separators, so a document
      // carrying both "123-45-6789" and "123456789" still reports one SSN —
      // and the dashed hit, pushed first, keeps its "high" confidence.
      push("ssn", "low", maskDigits(m[0], 4), m[0]);
    }
  }
  while ((m = EIN.exec(body)) !== null) {
    push("ein", "medium", maskDigits(m[0], 3), m[0]);
  }
  // The captured group, not the whole match: the label is context, not the
  // identifier, and echoing it back would put "Driver's License Number" in the
  // evidence beside a mask that is meant to be the only thing shown.
  while ((m = DRIVER_LICENCE.exec(body)) !== null) {
    const v = m[1]!.trim();
    if (/\d/.test(v)) push("driver-licence", "medium", maskAlphanumeric(v, 3), v);
  }
  while ((m = PASSPORT.exec(body)) !== null) {
    if (/\d/.test(m[1]!)) push("passport", "medium", maskAlphanumeric(m[1]!, 3), m[1]!);
  }
  /** An identifier carries a digit; a word does not. */
  const looksLikeValue = (v: string): boolean => /\d/.test(v);

  while ((m = STATE_ID.exec(body)) !== null) {
    const v = m[1]!.trim();
    if (looksLikeValue(v)) push("state-id", "medium", maskAlphanumeric(v, 3), v);
  }
  while ((m = MEDICAL_RECORD.exec(body)) !== null) {
    const v = m[1]!.trim();
    if (looksLikeValue(v)) push("medical-record", "medium", maskAlphanumeric(v, 3), v);
  }
  while ((m = HEALTH_PLAN.exec(body)) !== null) {
    const v = m[1]!.trim();
    if (looksLikeValue(v)) push("health-plan-id", "medium", maskAlphanumeric(v, 3), v);
  }
  // An ITIN is 9XX-GG-SSSS, which `ssnStructurallyValid` rejects on purpose
  // (the SSA never issues 900+) — so it fell through the SSN detector by
  // design and through everything else by omission. It is what a non-resident
  // or undocumented worker has INSTEAD of an SSN.
  ITIN.lastIndex = 0;
  while ((m = ITIN.exec(body)) !== null) {
    if (itinStructurallyValid(m[1]!, m[2]!, m[3]!)) {
      push("itin", "high", maskDigits(m[0], 4), m[0]);
    }
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
