/**
 * Deterministic RFC-4180 CSV parser for a privilege log. Pure and total:
 * no IO, no clock, never throws — malformed input is recovered from as best
 * as possible and surfaced as a warning rather than an exception.
 *
 * The tokenizer mirrors the escaping rules of the `csvField` encoder in
 * ../report/exports.ts (double-quote wrapping, `""` for an embedded quote,
 * commas/CR/LF inside quoted fields) so a CSV this project emits round-trips
 * back through this parser.
 */

import { parseBates } from "./bates.js";

export type PrivilegeLogEntry = {
  control?: string;
  bates_start?: string;
  bates_end?: string;
  date?: string;
  author?: string;
  recipients?: string;
  privilege?: string;
  description?: string;
  row_index: number;
};

export type PrivilegeLog = {
  entries: PrivilegeLogEntry[];
  warnings: string[];
  unmapped_columns: string[];
};

type MappedField =
  | "control"
  | "bates_start"
  | "bates_end"
  | "bates_range"
  | "date"
  | "author"
  | "recipients"
  | "privilege"
  | "description";

/** Conservative, case-insensitive, trimmed header synonym table. */
const SYNONYMS: Record<string, MappedField> = {
  control: "control",
  "log no": "control",
  "log number": "control",
  "priv no": "control",
  entry: "control",
  "bates start": "bates_start",
  begbates: "bates_start",
  "beg bates": "bates_start",
  "bates begin": "bates_start",
  "start bates": "bates_start",
  bates_start: "bates_start",
  "bates end": "bates_end",
  endbates: "bates_end",
  "end bates": "bates_end",
  bates_end: "bates_end",
  bates: "bates_range",
  "bates range": "bates_range",
  date: "date",
  author: "author",
  from: "author",
  recipients: "recipients",
  to: "recipients",
  cc: "recipients",
  privilege: "privilege",
  "privilege asserted": "privilege",
  basis: "privilege",
  claim: "privilege",
  description: "description",
  subject: "description",
  summary: "description",
};

/**
 * Tokenize RFC-4180 CSV text into rows of raw field strings. Records are
 * split on CRLF or LF; a quoted field may contain commas, newlines, and `""`
 * as an escaped quote. Never throws: an unterminated quote at end-of-input
 * is closed implicitly (the `truncatedQuote` flag reports this).
 */
function tokenizeCsv(csv: string): { rows: string[][]; truncatedQuote: boolean } {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let truncatedQuote = false;
  let sawAnyField = false;

  const endField = () => {
    row.push(field);
    field = "";
  };
  const endRow = () => {
    endField();
    rows.push(row);
    row = [];
    sawAnyField = false;
  };

  let i = 0;
  const n = csv.length;
  while (i < n) {
    const ch = csv[i];
    if (inQuotes) {
      if (ch === '"') {
        if (csv[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      field += ch;
      i += 1;
      continue;
    }
    if (ch === '"' && field.length === 0) {
      inQuotes = true;
      sawAnyField = true;
      i += 1;
      continue;
    }
    if (ch === ",") {
      endField();
      sawAnyField = true;
      i += 1;
      continue;
    }
    if (ch === "\r") {
      if (csv[i + 1] === "\n") i += 1;
      endRow();
      i += 1;
      continue;
    }
    if (ch === "\n") {
      endRow();
      i += 1;
      continue;
    }
    field += ch;
    sawAnyField = true;
    i += 1;
  }
  if (inQuotes) truncatedQuote = true;
  if (sawAnyField || field.length > 0 || row.length > 0) {
    endRow();
  }
  // Drop a single trailing empty row produced by a final newline.
  if (rows.length > 0) {
    const last = rows[rows.length - 1];
    if (last && last.length === 1 && last[0] === "") rows.pop();
  }
  return { rows, truncatedQuote };
}

/** Map a header cell to a known field, or `null` when no synonym matches. */
function mapHeader(cell: string): MappedField | null {
  const key = cell.trim().toLowerCase();
  return SYNONYMS[key] ?? null;
}

/**
 * Split a combined "bates range" cell into start/end on `-`, `–`, or "to".
 * Hyphen-convention Bates numbers contain hyphens themselves
 * ("ABC-000124 - ABC-000125"), so a first-hyphen split yielded start="ABC"
 * and the entry was silently skipped for every range check (audit finding).
 * Whitespace-delimited separators win; a bare hyphen splits only where BOTH
 * halves parse as Bates ids.
 */
function splitBatesRange(value: string): { start?: string; end?: string } {
  const trimmed = value.trim();
  if (trimmed.length === 0) return {};
  const spaced = /^(.+?)\s+(?:-|–|to)\s+(.+)$/i.exec(trimmed);
  if (spaced) {
    return { start: spaced[1]?.trim() || undefined, end: spaced[2]?.trim() || undefined };
  }
  const enDash = /^(.+?)\s*–\s*(.+)$/.exec(trimmed); // en-dash never appears inside a Bates id
  if (enDash) {
    return { start: enDash[1]?.trim() || undefined, end: enDash[2]?.trim() || undefined };
  }
  for (let i = trimmed.indexOf("-"); i !== -1; i = trimmed.indexOf("-", i + 1)) {
    const left = trimmed.slice(0, i).trim();
    const right = trimmed.slice(i + 1).trim();
    if (left && right && parseBates(left) && parseBates(right)) {
      return { start: left, end: right };
    }
  }
  const m = /^(.+?)\s*(?:-|\bto\b)\s*(.+)$/i.exec(trimmed);
  if (!m) return { start: trimmed };
  return { start: m[1]?.trim() || undefined, end: m[2]?.trim() || undefined };
}

/**
 * Parse a privilege-log CSV. Never throws. Returns empty entries plus a
 * warning when no header row can be recognized.
 */
export function parsePrivilegeLog(csv: string): PrivilegeLog {
  const warnings: string[] = [];
  const { rows, truncatedQuote } = tokenizeCsv(csv);
  if (truncatedQuote) {
    warnings.push("Unterminated quoted field near end of input; closed implicitly.");
  }
  if (rows.length === 0) {
    return { entries: [], warnings: ["Empty input: no rows found."], unmapped_columns: [] };
  }

  const header = rows[0] ?? [];
  const columnMap: (MappedField | null)[] = header.map(mapHeader);
  const unmapped_columns: string[] = [];
  for (let c = 0; c < header.length; c++) {
    if (columnMap[c] === null) {
      const cell = header[c] ?? "";
      if (cell.trim().length > 0) unmapped_columns.push(cell.trim());
    }
  }

  const hasAnyMapped = columnMap.some((m) => m !== null);
  if (!hasAnyMapped) {
    warnings.push("No recognizable header row found; treating file as having no entries.");
    return { entries: [], warnings, unmapped_columns };
  }

  const entries: PrivilegeLogEntry[] = [];
  let rowIndex = 0;
  for (let r = 1; r < rows.length; r++) {
    const dataRow = rows[r];
    if (!dataRow) continue;
    // Blank line — including Excel-export artifacts like ",,," where every
    // field is empty; those rows were accused of missing FRCP 26(b)(5)(A)
    // fields (audit finding).
    if (dataRow.every((f) => (f ?? "").trim().length === 0)) continue;
    const entry: PrivilegeLogEntry = { row_index: rowIndex };
    for (let c = 0; c < dataRow.length; c++) {
      const field = columnMap[c];
      if (!field) continue;
      const raw = (dataRow[c] ?? "").trim();
      if (raw.length === 0) continue;
      if (field === "bates_range") {
        const { start, end } = splitBatesRange(raw);
        if (start && !entry.bates_start) entry.bates_start = start;
        if (end && !entry.bates_end) entry.bates_end = end;
        continue;
      }
      entry[field] = raw;
    }
    entries.push(entry);
    rowIndex += 1;
  }

  return { entries, warnings, unmapped_columns };
}
