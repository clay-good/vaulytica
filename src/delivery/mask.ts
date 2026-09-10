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

/**
 * IBAN check, ISO 13616 / ISO 7064 mod-97-10.
 *
 * Move the first four characters to the end, map each letter to two digits
 * (A=10 … Z=35), and take the whole thing mod 97; a valid IBAN gives 1. The
 * checksum is mandatory and universal, which is what makes a bare pattern safe
 * here where it would not be for a licence or passport number: an arbitrary
 * alphanumeric run has a ~1% chance of passing, and it has to be
 * IBAN-SHAPED first.
 *
 * Computed digit by digit rather than with BigInt: an IBAN can be 34
 * characters, which becomes a 68-digit number, and `Number` loses precision
 * long before that.
 */
export function ibanValid(value: string): boolean {
  const compact = value.replace(/[\s-]/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(compact)) return false;
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const chunk = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
    for (const d of chunk) remainder = (remainder * 10 + Number(d)) % 97;
  }
  return remainder === 1;
}

/**
 * North American VIN check digit (FMVSS 115, 49 C.F.R. § 565.15).
 *
 * Position 9 is a weighted mod-11 check over the other sixteen characters.
 * ⚠️ It is NOT universal — a European or Japanese VIN carries no valid check
 * digit — so the caller must accept a labelled VIN as well, or lose every
 * vehicle not sold into the US market.
 */
export function vinCheckDigitValid(value: string): boolean {
  const v = value.toUpperCase();
  if (!/^[A-HJ-NPR-Z0-9]{17}$/.test(v)) return false;
  const translit = "0123456789.ABCDEFGH..JKLMN.P.R..STUVWXYZ";
  const weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 17; i += 1) {
    const idx = translit.indexOf(v[i]!);
    if (idx < 0) return false;
    sum += (idx % 10) * weights[i]!;
  }
  const check = sum % 11;
  const expected = check === 10 ? "X" : String(check);
  return v[8] === expected;
}

/**
 * NPI check digit — Luhn over `80840` + the ten-digit number (CMS).
 *
 * The 80840 prefix is the ISO 7812 issuer identifier the NPI standard borrows
 * so the number validates as a card-style Luhn value. Verified against three
 * published NPIs and against one of them with a digit changed.
 */
export function npiValid(digits: string): boolean {
  if (!/^[12]\d{9}$/.test(digits)) return false;
  return luhnValid("80840" + digits);
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
