/**
 * Findings-to-action exports (spec-v6 Part III, Steps 87–88).
 *
 * Three tool-agnostic artifacts derived purely from a completed run and
 * its extracted data:
 *
 *  1. A **fix list** — the findings as a severity-ordered checklist, in
 *     Markdown (for a comment thread / tracker) and CSV (for a sheet).
 *  2. An **obligations CSV** — the obligations ledger the engine already
 *     extracts, ready to drop into a spreadsheet or CLM.
 *  3. A **deadlines `.ics`** — extracted temporal facts and the notice
 *     deadlines the engine can compute *deterministically* (an absolute
 *     date, or a relative offset from an anchor whose definition pins a
 *     concrete date). Anything ambiguous is reported as unresolved, never
 *     guessed (spec-v6 §13: "No fabricated dates, ever.").
 *
 * Every function here is a pure function of its input: same run / same
 * extracted data → byte-identical output. No wall-clock, no randomness —
 * the same canonicalization discipline `result_hash` honors. The `.ics`
 * uses a fixed DTSTAMP and a content-derived UID so two runs on two
 * machines produce identical calendars.
 */

import type { EngineRun, Finding, Severity } from "../engine/finding.js";
import type { DateReference, ExtractedData } from "../extract/types.js";

const SEVERITY_ORDER: Severity[] = ["critical", "warning", "info"];
const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  warning: "Warning",
  info: "Info",
};

// ---------------------------------------------------------------------------
// Fix list
// ---------------------------------------------------------------------------

/** Source-authority names for a finding (deduped, in citation order). */
function citationLine(f: Finding): string {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const c of f.source_citations) {
    const s = c.source.trim();
    if (s && !seen.has(s)) {
      seen.add(s);
      out.push(s);
    }
  }
  return out.join("; ");
}

/**
 * Markdown-link form of the authority (spec-v8 §14): `[source](url)` when the
 * citation has a resolvable URL, the bare name otherwise — so the action-item
 * fix-list a user pastes into a ticket stays *verifiable*, not stripped to a
 * bare name as it was before v8.
 */
function citationLineMarkdown(f: Finding): string {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const c of f.source_citations) {
    const s = c.source.trim();
    if (!s || seen.has(s)) continue;
    seen.add(s);
    const url = c.source_url?.trim();
    out.push(url ? `[${s}](${url})` : s);
  }
  return out.join("; ");
}

/** Resolvable authority URLs for a finding (deduped) — the CSV `authority_url` column. */
function citationUrls(f: Finding): string {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const c of f.source_citations) {
    const url = c.source_url?.trim();
    if (url && !seen.has(url)) {
      seen.add(url);
      out.push(url);
    }
  }
  return out.join("; ");
}

/**
 * The findings as a Markdown checklist, grouped by severity. When
 * `extracted` is supplied, a trailing "Dates to verify manually" section
 * lists temporal facts the deadlines export could not resolve, so an
 * ambiguous date becomes a manual-verify action item rather than silence
 * (spec-v6 §13).
 */
export function buildFixListMarkdown(run: EngineRun, extracted?: ExtractedData): string {
  const lines: string[] = [];
  lines.push("# Vaulytica fix list");
  lines.push("");
  lines.push(`**Document:** ${run.source_file.name}`);
  lines.push(
    `**Playbook:** ${run.playbook_id} · **DKB:** ${run.dkb_version} · **Engine:** ${run.version}`,
  );
  lines.push(`**Result hash:** \`${run.result_hash}\``);
  lines.push("");
  lines.push(
    "Each item below is a finding to resolve, ordered by severity. This list is a deterministic projection of the run — it adds no judgment beyond what the report contains.",
  );

  for (const sev of SEVERITY_ORDER) {
    const group = run.findings.filter((f) => f.severity === sev);
    lines.push("");
    lines.push(`## ${SEVERITY_LABEL[sev]} (${group.length})`);
    if (group.length === 0) {
      lines.push("");
      lines.push("_None._");
      continue;
    }
    for (const f of group) {
      lines.push("");
      lines.push(`- [ ] **${f.rule_id}** — ${f.title}`);
      const section = f.excerpt.section_id;
      if (section) lines.push(`  - Section: ${section}`);
      if (f.explanation) lines.push(`  - ${f.explanation}`);
      if (f.recommendation) lines.push(`  - Recommendation: ${f.recommendation}`);
      const cites = citationLineMarkdown(f);
      if (cites) lines.push(`  - Authority: ${cites}`);
    }
  }

  if (extracted) {
    const { unresolved } = collectDeadlines(extracted);
    if (unresolved.length > 0) {
      lines.push("");
      lines.push(`## Dates to verify manually (${unresolved.length})`);
      lines.push("");
      lines.push(
        "These dates were detected but could not be resolved to a concrete calendar date, so they are **not** in the deadlines export. Verify each by hand.",
      );
      for (const u of unresolved) {
        const where = u.section ? ` (section ${u.section})` : "";
        lines.push(`- [ ] \`${u.raw_text}\`${where} — ${u.reason}`);
      }
    }
  }

  lines.push("");
  return lines.join("\n");
}

/**
 * RFC 4180 field: quote when it contains a comma, quote, CR, or LF.
 *
 * Also neutralizes CSV formula injection (CWE-1236): a cell whose first
 * character is a spreadsheet formula trigger (`= + - @`, or a leading
 * tab/CR used to bypass) is prefixed with a single quote so Excel/Sheets
 * render it as text instead of executing it. The fix-list and obligations
 * CSVs carry verbatim clause text and custom-playbook rule titles — both
 * untrusted — so a clause like `=HYPERLINK(...)` must not become live.
 */
function csvField(value: string): string {
  const guarded = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  if (/[",\r\n]/.test(guarded)) {
    return `"${guarded.replace(/"/g, '""')}"`;
  }
  return guarded;
}

function csvRow(fields: string[]): string {
  return fields.map(csvField).join(",");
}

/** The findings as a CSV, one row per finding, in the run's sorted order. */
export function buildFixListCsv(run: EngineRun): string {
  const rows: string[] = [];
  rows.push(
    csvRow([
      "severity",
      "rule_id",
      "section",
      "title",
      "explanation",
      "recommendation",
      "authority",
      "authority_url",
    ]),
  );
  for (const f of run.findings) {
    rows.push(
      csvRow([
        f.severity,
        f.rule_id,
        f.excerpt.section_id ?? "",
        f.title,
        f.explanation ?? "",
        f.recommendation ?? "",
        citationLine(f),
        citationUrls(f), // spec-v8 §14 — verifiable URL alongside the name
      ]),
    );
  }
  // CRLF line endings — the de-facto interchange convention for CSV.
  return rows.join("\r\n") + "\r\n";
}

// ---------------------------------------------------------------------------
// Obligations CSV
// ---------------------------------------------------------------------------

/**
 * The obligations ledger as CSV: obligor, modal, action, trigger,
 * qualifier, section, source clause. Rows follow the extractor's
 * document order, which is already deterministic.
 */
export function buildObligationsCsv(extracted: ExtractedData): string {
  const rows: string[] = [];
  rows.push(csvRow(["obligor", "modal", "action", "trigger", "qualifier", "section", "source_text"]));
  for (const o of extracted.obligations) {
    rows.push(
      csvRow([
        o.obligor,
        o.modal,
        o.action,
        o.trigger ?? "",
        o.qualifier ?? "",
        o.position.section_id,
        o.raw_text,
      ]),
    );
  }
  return rows.join("\r\n") + "\r\n";
}

// ---------------------------------------------------------------------------
// Deadlines (.ics)
// ---------------------------------------------------------------------------

export type DeadlineEvent = {
  /** ISO date (YYYY-MM-DD) the event falls on. */
  iso: string;
  /** Human summary for the calendar entry. */
  summary: string;
  /** Section the source clause lives in, when known. */
  section?: string;
  /** The raw text the date was extracted from. */
  raw_text: string;
  /** True when the date was computed (anchor + offset), not literal. */
  computed: boolean;
  /** True when this is a notice deadline (a "before"-an-anchor date). */
  notice: boolean;
};

export type UnresolvedDate = {
  raw_text: string;
  reason: string;
  section?: string;
};

export type DeadlinesResult = {
  events: DeadlineEvent[];
  unresolved: UnresolvedDate[];
};

const ABS_ISO = /\b(\d{4})-(\d{2})-(\d{2})\b/;
const ABS_US = /\b(\d{1,2})\/(\d{1,2})\/(\d{2,4})\b/;
const ABS_MONTHS =
  "January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec";
const ABS_PROSE = new RegExp(String.raw`\b(${ABS_MONTHS})\.?\s+(\d{1,2}),?\s+(\d{4})\b`, "i");

const MONTH_NUM: Record<string, number> = {
  january: 1, jan: 1, february: 2, feb: 2, march: 3, mar: 3, april: 4, apr: 4,
  may: 5, june: 6, jun: 6, july: 7, jul: 7, august: 8, aug: 8,
  september: 9, sep: 9, sept: 9, october: 10, oct: 10, november: 11, nov: 11,
  december: 12, dec: 12,
};

function isValidIso(y: number, mo: number, d: number): boolean {
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return false;
  const dt = new Date(Date.UTC(y, mo - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === mo - 1 && dt.getUTCDate() === d;
}

function pad(n: number, w: number): string {
  return n.toString().padStart(w, "0");
}

/** Parse the first concrete absolute date in `text` → ISO, or undefined. */
function firstAbsoluteIso(text: string): string | undefined {
  let m = ABS_ISO.exec(text);
  if (m) {
    const y = +m[1]!, mo = +m[2]!, d = +m[3]!;
    if (isValidIso(y, mo, d)) return `${pad(y, 4)}-${pad(mo, 2)}-${pad(d, 2)}`;
  }
  m = ABS_PROSE.exec(text);
  if (m) {
    const mo = MONTH_NUM[m[1]!.toLowerCase().replace(/\./g, "")];
    const d = +m[2]!, y = +m[3]!;
    if (mo !== undefined && isValidIso(y, mo, d)) return `${pad(y, 4)}-${pad(mo, 2)}-${pad(d, 2)}`;
  }
  m = ABS_US.exec(text);
  if (m) {
    const mo = +m[1]!, d = +m[2]!;
    let y = +m[3]!;
    if (m[3]!.length === 2) y = y < 70 ? 2000 + y : 1900 + y;
    if (isValidIso(y, mo, d)) return `${pad(y, 4)}-${pad(mo, 2)}-${pad(d, 2)}`;
  }
  return undefined;
}

/** Add `days` to an ISO date deterministically (UTC). */
function addDays(iso: string, days: number): string {
  const [y, mo, d] = iso.split("-").map(Number) as [number, number, number];
  const dt = new Date(Date.UTC(y, mo - 1, d));
  dt.setUTCDate(dt.getUTCDate() + days);
  return `${pad(dt.getUTCFullYear(), 4)}-${pad(dt.getUTCMonth() + 1, 2)}-${pad(dt.getUTCDate(), 2)}`;
}

function normalizeAnchor(anchor: string): string {
  return anchor.trim().toLowerCase().replace(/\s+/g, " ");
}

/**
 * Build the map from a date-anchor name (e.g. "effective date") to the
 * concrete ISO date its definition pins. Only definitions whose text
 * contains a single unambiguous absolute date contribute — this is the
 * "term + notice period" arithmetic of spec-v6 §13, never a guess.
 */
function buildAnchorMap(extracted: ExtractedData): Map<string, string> {
  const map = new Map<string, string>();
  for (const entry of extracted.definitions.entries) {
    const iso = firstAbsoluteIso(entry.definition);
    if (iso) map.set(normalizeAnchor(entry.term), iso);
  }
  return map;
}

/**
 * Resolve the engine's extracted dates into calendar events and a list of
 * dates that could not be resolved. Pure and deterministic.
 */
export function collectDeadlines(extracted: ExtractedData): DeadlinesResult {
  const anchors = buildAnchorMap(extracted);
  const events: DeadlineEvent[] = [];
  const unresolved: UnresolvedDate[] = [];

  for (const date of extracted.dates) {
    const section = date.position.section_id;
    if (date.type === "absolute") {
      if (date.iso) {
        events.push({
          iso: date.iso,
          summary: date.raw_text,
          section,
          raw_text: date.raw_text,
          computed: false,
          notice: false,
        });
      } else {
        unresolved.push({
          raw_text: date.raw_text,
          reason: "date present but not machine-readable",
          section,
        });
      }
      continue;
    }
    if (date.type === "relative") {
      // A disjunctive / range deadline has no single calendar date; we
      // surface it for manual verification rather than guessing a bound.
      if (date.offset_days_max !== undefined) {
        unresolved.push({
          raw_text: date.raw_text,
          reason: "range deadline — verify the controlling bound manually",
          section,
        });
        continue;
      }
      const resolved = resolveRelative(date, anchors);
      if (resolved) {
        events.push(resolved);
      } else {
        unresolved.push({
          raw_text: date.raw_text,
          reason: date.anchor
            ? `relative to "${date.anchor}", which has no defined calendar date`
            : "relative date with no resolvable anchor",
          section,
        });
      }
      continue;
    }
    if (date.type === "fiscal-period") {
      unresolved.push({
        raw_text: date.raw_text,
        reason: "fiscal period — no fixed calendar date; verify against the fiscal calendar",
        section,
      });
      continue;
    }
    // named-anchor / anchor-definition: a reference, not a dated event.
    unresolved.push({
      raw_text: date.raw_text,
      reason: "named anchor — no concrete date attached",
      section,
    });
  }

  // Deterministic order: by date, then summary, then section.
  events.sort(
    (a, b) =>
      a.iso.localeCompare(b.iso, "en") ||
      a.summary.localeCompare(b.summary, "en") ||
      (a.section ?? "").localeCompare(b.section ?? "", "en"),
  );
  unresolved.sort(
    (a, b) =>
      a.raw_text.localeCompare(b.raw_text, "en") ||
      (a.section ?? "").localeCompare(b.section ?? "", "en"),
  );
  return { events, unresolved };
}

function resolveRelative(
  date: DateReference,
  anchors: Map<string, string>,
): DeadlineEvent | null {
  if (date.anchor === undefined || date.offset_days === undefined) return null;
  const base = anchors.get(normalizeAnchor(date.anchor));
  if (!base) return null;
  const iso = addDays(base, date.offset_days);
  const notice = date.offset_days < 0;
  return {
    iso,
    summary: date.raw_text,
    section: date.position.section_id,
    raw_text: date.raw_text,
    computed: true,
    notice,
  };
}

/** Escape an ICS text value per RFC 5545 §3.3.11. */
function icsEscape(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/;/g, "\\;")
    .replace(/,/g, "\\,")
    .replace(/\r\n|\n|\r/g, "\\n");
}

/** UTF-8 octet length of a string (RFC 5545 folds by octets, not characters). */
function octetLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

/** Longest prefix of `value` whose UTF-8 length ≤ `maxOctets`, split on a code-point boundary. */
function splitByOctets(value: string, maxOctets: number): [string, string] {
  const encoder = new TextEncoder();
  let octets = 0;
  let cut = 0;
  for (const ch of value) {
    const width = encoder.encode(ch).length;
    if (octets + width > maxOctets) break;
    octets += width;
    cut += ch.length;
  }
  return [value.slice(0, cut), value.slice(cut)];
}

/**
 * Fold a content line to ≤75 octets per RFC 5545 §3.1 (CRLF + space).
 * Folds on octet boundaries — pure-ASCII lines fold identically to a char split,
 * but multi-byte text (accents, currency symbols, emoji) never overruns the limit.
 */
function icsFold(line: string): string {
  if (octetLength(line) <= 73) return line;
  const out: string[] = [];
  let rest = line;
  let first = true;
  while (rest.length > 0) {
    const [head, tail] = splitByOctets(rest, first ? 73 : 72);
    out.push(first ? head : " " + head);
    rest = tail;
    first = false;
  }
  return out.join("\r\n");
}

/** Deterministic FNV-1a 32-bit hash → 8 lowercase hex chars (for UIDs). */
function fnv1a(str: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i += 1) {
    h ^= str.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

// Fixed DTSTAMP — the calendar carries no generation wall-clock, so two
// machines produce byte-identical files (same discipline as result_hash).
const FIXED_DTSTAMP = "20200101T000000Z";

/**
 * Serialize the resolvable deadlines to an iCalendar (`.ics`) string.
 * All-day VEVENTs, deterministic UIDs, fixed DTSTAMP, CRLF line endings.
 * Notice deadlines (a "before"-an-anchor date) carry a DISPLAY alarm at
 * the deadline so they surface in the user's calendar.
 */
export function buildDeadlinesIcs(extracted: ExtractedData): string {
  const { events, unresolved } = collectDeadlines(extracted);
  const lines: string[] = [];
  lines.push("BEGIN:VCALENDAR");
  lines.push("VERSION:2.0");
  lines.push("PRODID:-//Vaulytica//Deadlines Export//EN");
  lines.push("CALSCALE:GREGORIAN");

  events.forEach((ev, i) => {
    const ymd = ev.iso.replace(/-/g, "");
    const ymdEnd = addDays(ev.iso, 1).replace(/-/g, "");
    const uid = `${pad(i, 4)}-${fnv1a(`${ev.iso}|${ev.summary}|${ev.section ?? ""}`)}@vaulytica`;
    const prefix = ev.notice ? "Notice deadline: " : ev.computed ? "Deadline: " : "Date: ";
    const desc =
      `${ev.computed ? "Computed from " : "Extracted from "}` +
      `${ev.section ? `section ${ev.section}` : "the document"}: ${ev.raw_text}`;
    lines.push("BEGIN:VEVENT");
    lines.push(`UID:${uid}`);
    lines.push(`DTSTAMP:${FIXED_DTSTAMP}`);
    lines.push(`DTSTART;VALUE=DATE:${ymd}`);
    lines.push(`DTEND;VALUE=DATE:${ymdEnd}`);
    lines.push(icsFold(`SUMMARY:${icsEscape(prefix + ev.summary)}`));
    lines.push(icsFold(`DESCRIPTION:${icsEscape(desc)}`));
    if (ev.notice) {
      lines.push("BEGIN:VALARM");
      lines.push("ACTION:DISPLAY");
      lines.push(icsFold(`DESCRIPTION:${icsEscape(prefix + ev.summary)}`));
      lines.push("TRIGGER:PT0S");
      lines.push("END:VALARM");
    }
    lines.push("END:VEVENT");
  });

  // Unresolved deadlines (no calendar date) are surfaced as all-day
  // "verify manually" events on a fixed sentinel date rather than being
  // silently dropped, each carrying its source section and the reason it
  // could not be resolved. The sentinel (the epoch DTSTAMP date) is
  // obviously artificial, so the user reads it as "needs attention," and
  // it keeps the file deterministic. (spec-v7 §17.)
  unresolved.forEach((u, i) => {
    const ymd = SENTINEL_VERIFY_DATE.replace(/-/g, "");
    const ymdEnd = addDays(SENTINEL_VERIFY_DATE, 1).replace(/-/g, "");
    const uid = `verify-${pad(i, 4)}-${fnv1a(`${u.raw_text}|${u.section ?? ""}`)}@vaulytica`;
    const desc = `Verify manually — ${u.reason}${u.section ? ` (from section ${u.section})` : ""}: ${u.raw_text}`;
    lines.push("BEGIN:VEVENT");
    lines.push(`UID:${uid}`);
    lines.push(`DTSTAMP:${FIXED_DTSTAMP}`);
    lines.push(`DTSTART;VALUE=DATE:${ymd}`);
    lines.push(`DTEND;VALUE=DATE:${ymdEnd}`);
    lines.push(icsFold(`SUMMARY:${icsEscape(`Verify manually: ${u.raw_text}`)}`));
    lines.push(icsFold(`DESCRIPTION:${icsEscape(desc)}`));
    lines.push("END:VEVENT");
  });

  lines.push("END:VCALENDAR");
  return lines.join("\r\n") + "\r\n";
}

/** Fixed sentinel date for unresolved "verify manually" calendar events. */
const SENTINEL_VERIFY_DATE = "2020-01-01";

// ---------------------------------------------------------------------------
// Blob helpers (UI convenience — same pattern as report/json.ts)
// ---------------------------------------------------------------------------

export function fixListMarkdownBlob(run: EngineRun, extracted?: ExtractedData): Blob {
  return new Blob([buildFixListMarkdown(run, extracted)], { type: "text/markdown" });
}

export function fixListCsvBlob(run: EngineRun): Blob {
  return new Blob([buildFixListCsv(run)], { type: "text/csv" });
}

export function obligationsCsvBlob(extracted: ExtractedData): Blob {
  return new Blob([buildObligationsCsv(extracted)], { type: "text/csv" });
}

export function deadlinesIcsBlob(extracted: ExtractedData): Blob {
  return new Blob([buildDeadlinesIcs(extracted)], { type: "text/calendar" });
}
