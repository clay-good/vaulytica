/**
 * Bates-number extraction from production member FILENAMES. Matches the
 * dominant conventions — a prefix followed by a zero-padded number, with or
 * without a separator ("ACME_000123.pdf", "ACME000123.pdf"), and the RANGE
 * form a multi-page document is produced under ("ACME_000123-000145.pdf") —
 * entirely from the filename string. Pure and total: no IO, no clock, never
 * throws.
 */

export type BatesId = {
  raw: string;
  prefix: string;
  /** The FIRST Bates number the member carries. */
  number: number;
  /**
   * The last Bates number the member carries, when the filename encodes a
   * RANGE ("ACME_000123-000145.pdf" — one multi-page document spanning
   * 000123 through 000145). Absent for a single-number filename, where the
   * member spans `number` alone. Consumers that reason about coverage must
   * read `end_number ?? number` as the span's upper bound.
   */
  end_number?: number;
  padding: number;
  filename: string;
};

/** Strip a trailing `.ext` extension, if present. */
function stripExtension(filename: string): string {
  const idx = filename.lastIndexOf(".");
  if (idx <= 0) return filename;
  return filename.slice(0, idx);
}

const BATES_RE = /^(.*?)[_-]?(\d{2,})$/;

/**
 * A filename encoding a Bates RANGE: prefix, start number, separator, end
 * number ("ACME_000123-000145.pdf"). This is the standard convention for a
 * single multi-page document, and it must be read as a range rather than as a
 * number, because {@link BATES_RE} alone matches it too — its lazy prefix and
 * trailing-digit capture swallow `ACME_000123-` into the PREFIX and report
 * only 145. That parse is silently destructive: every ranged member gets its
 * own distinct prefix, so `groupByPrefix` puts each one in a singleton group
 * and cross-member sequence reconciliation (PROD-001/010/011) can never see a
 * gap. The start number is lost outright.
 */
const BATES_RANGE_RE = /^(.*?)[_-]?(\d{2,})[-–](\d{2,})$/;

/**
 * Parse a single filename into a {@link BatesId}, or `null` when the
 * filename does not match the Bates grammar `prefix + zero-padded number`,
 * optionally followed by `-` and an end number.
 *
 * The range reading is deliberately NARROW: it applies only when both numbers
 * are padded to the SAME width and the end is not below the start. Hyphens
 * appear inside ordinary Bates ids ("ABC-000124") and inside other identifier
 * schemes that reach this parser ("INV-2024-0001"), and reading one of those
 * as a range would widen the span a member is credited with covering — which
 * HIDES a real gap rather than reporting a false one. Where the two readings
 * are genuinely ambiguous, the single-number reading wins.
 */
export function parseBates(filename: string): BatesId | null {
  const stem = stripExtension(filename);
  const range = BATES_RANGE_RE.exec(stem);
  if (range) {
    const startDigits = range[2] ?? "";
    const endDigits = range[3] ?? "";
    const start = parseInt(startDigits, 10);
    const end = parseInt(endDigits, 10);
    if (
      startDigits.length === endDigits.length &&
      Number.isFinite(start) &&
      Number.isFinite(end) &&
      end >= start
    ) {
      return {
        raw: stem,
        prefix: (range[1] ?? "").replace(/[_-]+$/, ""),
        number: start,
        end_number: end,
        padding: startDigits.length,
        filename,
      };
    }
  }
  const m = BATES_RE.exec(stem);
  if (!m) return null;
  const prefixRaw = m[1] ?? "";
  const digits = m[2] ?? "";
  const prefix = prefixRaw.replace(/[_-]+$/, "");
  const number = parseInt(digits, 10);
  if (!Number.isFinite(number)) return null;
  return {
    raw: stem,
    prefix,
    number,
    padding: digits.length,
    filename,
  };
}

/**
 * Parse every filename that matches the Bates grammar; filenames that don't
 * are silently dropped. Result is sorted by (prefix, number).
 */
export function extractBatesSet(filenames: readonly string[]): BatesId[] {
  const out: BatesId[] = [];
  for (const filename of filenames) {
    const parsed = parseBates(filename);
    if (parsed) out.push(parsed);
  }
  out.sort((a, b) => {
    if (a.prefix !== b.prefix) return a.prefix < b.prefix ? -1 : 1;
    return a.number - b.number;
  });
  return out;
}
