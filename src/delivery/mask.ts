/**
 * Masking + structural-validation helpers for the sensitive-data scan
 * (spec-v9 §13/§14, HANDOFF-005). Hard invariant (§Part XIV): no handoff
 * finding, in any format, may ever contain an unmasked matched value. The
 * report that *warns about* exposed PII must not itself reproduce it.
 *
 * Every function here is pure.
 */

/**
 * Mask a digit run, revealing only the last `revealLast` digits and
 * preserving the separator shape. Non-digits (dashes, spaces) pass through so
 * the masked value keeps the original's recognizable structure
 * (`***-**-6789`), but no leading digit is ever revealed.
 */
export function maskDigits(value: string, revealLast = 4): string {
  const digits = value.replace(/\D/g, "");
  const keep = Math.min(revealLast, Math.max(0, digits.length));
  const hideCount = digits.length - keep;
  let seen = 0;
  let out = "";
  for (const ch of value) {
    if (/\d/.test(ch)) {
      out += seen < hideCount ? "*" : ch;
      seen += 1;
    } else {
      out += ch;
    }
  }
  return out;
}

/**
 * Mask an email, revealing only the first character of the local part and the
 * domain (the domain is rarely the sensitive half): `j***@example.com`.
 */
export function maskEmail(value: string): string {
  const at = value.indexOf("@");
  if (at <= 0) return "***";
  const local = value.slice(0, at);
  const domain = value.slice(at);
  const head = local[0] ?? "";
  return `${head}***${domain}`;
}

/**
 * Luhn checksum validation — suppresses the obvious payment-card false
 * positives (a 16-digit invoice number that is not a card). A Luhn-valid run
 * is a *candidate*, surfaced for human confirmation; it is never asserted to
 * be a real card (§14).
 */
export function luhnValid(digits: string): boolean {
  const clean = digits.replace(/\D/g, "");
  if (clean.length < 13 || clean.length > 19) return false;
  let sum = 0;
  let dbl = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let d = clean.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

/**
 * Structural validation for a US SSN in `NNN-NN-NNNN` form. Rejects the
 * ranges the SSA never issues (area 000/666/900-999, group 00, serial 0000)
 * so a random nine-digit run does not masquerade as an SSN.
 */
export function ssnStructurallyValid(area: string, group: string, serial: string): boolean {
  const a = Number(area);
  const g = Number(group);
  const s = Number(serial);
  if (a === 0 || a === 666 || a >= 900) return false;
  if (g === 0) return false;
  if (s === 0) return false;
  return true;
}
