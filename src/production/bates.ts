/**
 * Bates-number extraction from production member FILENAMES. Matches the
 * dominant convention — a prefix followed by a zero-padded number, with or
 * without a separator (e.g. "ACME_000123.pdf", "ACME000123.pdf") — entirely
 * from the filename string. Pure and total: no IO, no clock, never throws.
 */

export type BatesId = {
  raw: string;
  prefix: string;
  number: number;
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
 * Parse a single filename into a {@link BatesId}, or `null` when the
 * filename does not match the Bates grammar `prefix + zero-padded number`.
 */
export function parseBates(filename: string): BatesId | null {
  const stem = stripExtension(filename);
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
