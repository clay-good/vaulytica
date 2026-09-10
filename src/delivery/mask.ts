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
/**
 * Mask an ALPHANUMERIC identifier, revealing only a suffix.
 *
 * 🚨 `maskDigits` passes every non-digit through verbatim, which is right for
 * an SSN or a card number and wrong for anything carrying letters: a passport
 * number `X12345678` would come back `X*****678`, leaking the leading
 * character of the very identifier the scan exists to flag. This module's rule
 * is that a revealing type reveals a SUFFIX — never a prefix — and a driver's
 * licence or passport number is alphanumeric by construction.
 *
 * Separators (spaces, hyphens) are preserved so the shape stays legible; every
 * other character before the last `revealLast` alphanumerics becomes `*`.
 */
export function maskAlphanumeric(value: string, revealLast = 4): string {
  const alnum = value.replace(/[^A-Za-z0-9]/g, "");
  const keep = Math.min(revealLast, alnum.length);
  const hideCount = alnum.length - keep;
  let seen = 0;
  let out = "";
  for (const ch of value) {
    if (/[A-Za-z0-9]/.test(ch)) {
      out += seen < hideCount ? "*" : ch;
      seen += 1;
    } else {
      out += ch;
    }
  }
  return out;
}

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
/**
 * Whether a 9-digit value is structurally a US **ITIN**.
 *
 * 🚨 `ssnStructurallyValid` rejects any area of 900 or above, which is right —
 * the SSA has never issued one — and that is precisely the range the IRS uses
 * for Individual Taxpayer Identification Numbers. So an ITIN fell through the
 * SSN detector by design and through everything else by omission, and an ITIN
 * is what a non-resident or undocumented worker has *instead of* an SSN. A
 * scan that catches one and not the other is not protecting the same people.
 *
 * The structure is precise enough to stand on its own: `9XX-GG-SSSS` where the
 * GROUP is 50–65, 70–88, 90–92 or 94–99. Everything else in the 9XX range is
 * unassigned, which keeps a nine-digit invoice number from reading as one.
 */
export function itinStructurallyValid(area: string, group: string, serial: string): boolean {
  const a = Number(area);
  const g = Number(group);
  const s = Number(serial);
  if (a < 900 || a > 999) return false;
  if (s === 0) return false;
  return (
    (g >= 50 && g <= 65) || (g >= 70 && g <= 88) || (g >= 90 && g <= 92) || (g >= 94 && g <= 99)
  );
}

export function ssnStructurallyValid(area: string, group: string, serial: string): boolean {
  const a = Number(area);
  const g = Number(group);
  const s = Number(serial);
  if (a === 0 || a === 666 || a >= 900) return false;
  if (g === 0) return false;
  if (s === 0) return false;
  return true;
}
