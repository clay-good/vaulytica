/**
 * v9 Thrust C — Tracked to Its Dates (spec-v9 §25–§30, companion
 * `docs/v9/critical-dates.md`).
 *
 * Turns the relative temporal terms the extractor already pulls
 * ([`src/extract/dates.ts`](../extract/dates.ts)) into the **absolute**
 * deadlines a lawyer must calendar. The work splits cleanly:
 *
 *   - {@link deriveDate} — the pure arithmetic. `anchor ± N {days | weeks
 *     | months | years}`, month-end-clamped and leap-year-correct. It
 *     takes **no clock**: it cannot read "today", so its output is a pure
 *     function of (reference, anchor) and is `result_hash`-stable forever.
 *   - {@link resolveAnchors} — binds an anchor name ("Effective Date") to
 *     its absolute date, from the definition that pins it or from an
 *     absolute date co-located with the anchor's parenthetical.
 *   - {@link buildCriticalDates} — the canonically-sorted register, with a
 *     `critical_dates_hash` of its own, **additive to and namespaced apart
 *     from** the engine `result_hash` (the v8 Step-146 / v9 Thrust-A
 *     "field outside the run" precedent — a document with no derivable
 *     dates yields an empty register and moves no golden).
 *
 * THE WALL-CLOCK BOUNDARY (companion §6, spec §3 corollary 4): only the
 * **absolute** `computed_date` ever enters this artifact or its hash. A
 * relative-to-today view ("due in 12 days", "overdue", soonest-first) is
 * render-only and computed elsewhere at display time — never here. This
 * module imports no clock; Step 164's metamorphic test re-runs a document
 * under two "today" values and asserts a byte-identical register, so the
 * trap cannot be sprung by a later edit.
 *
 * It is not a determination that a deadline is met, missed, or
 * enforceable — only that "the document's terms place this date at X"
 * (companion §7). Legal sufficiency stays attorney-gated (Part XVI).
 */

import type { DocumentTree } from "../ingest/types.js";
import type { DateReference, ExtractedData, Obligation } from "../extract/types.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import { forEachParagraph } from "../extract/walk.js";
import { computeCourtDays, computeDeadline, type DeadlineStep } from "../deadlines/compute.js";
import type { DeadlineProfile, ServiceMethod } from "../deadlines/profile.js";

/** The five derived-deadline families (spec §27 / companion §4). */
export type CriticalDateKind =
  | "auto-renewal-notice"
  | "cure-window"
  | "opt-out-window"
  | "survival-end"
  | "notice-period";

/** Stable rule id per kind (DATE-001…005). */
const KIND_RULE_ID: Record<CriticalDateKind, string> = {
  "auto-renewal-notice": "DATE-001",
  "cure-window": "DATE-002",
  "opt-out-window": "DATE-003",
  "survival-end": "DATE-004",
  "notice-period": "DATE-005",
};

/** The pure output of {@link deriveDate}. */
export type DerivedDate = {
  resolved: boolean;
  /** ISO 8601 absolute date, or `null` when the anchor is unresolved. */
  computed_date: string | null;
  /** For disjunctive ranges ("30 to 60 days after"): both computed bounds. */
  window?: [string, string];
  /** When unresolved, why (so the register can say "verify manually"). */
  reason?: string;
};

/** One row of the critical-dates register (companion §5). */
export type CriticalDate = {
  /** DATE-001…005 — the deadline family. */
  rule_id: string;
  kind: CriticalDateKind;
  resolved: boolean;
  /** Absolute computed date (ISO), or null when unresolved. Hashed. */
  computed_date: string | null;
  /** Both bounds, for a disjunctive range. */
  window?: [string, string];
  /** The clause the deadline derives from — the self-citation. */
  trigger: string;
  /** The anchor the offset is measured from ("Effective Date"). */
  anchor: string;
  /** Responsible party from obligations.ts; "" when unattributable. */
  responsible: string;
  /** Source section, when known. */
  section?: string;
  /** Why unresolved (verify-manually reason), when applicable. */
  reason?: string;
  /**
   * Deadline-computation provenance (add-deadline-computation). Present ONLY
   * when a `--deadline-profile` was asserted and this row was resolved (or
   * re-rolled) under it — the applied steps, the profile id, and the calendar
   * version. Omitted otherwise, so an unprofiled register is byte-identical to
   * before this feature and its `critical_dates_hash` is unchanged.
   */
  deadline_steps?: DeadlineStep[];
  deadline_profile_id?: string;
  deadline_calendar_version?: string;
};

/** Opt-in court-deadline resolution config (add-deadline-computation). */
export type DeadlineResolution = { profile: DeadlineProfile; service_method?: ServiceMethod };

/**
 * A drafting note derived from the resolved register (add-deadline-computation,
 * DDL follow-up). Advisory — computed only when a deadline profile is asserted,
 * lives OUTSIDE `critical_dates_hash` (the hash is over `register` only).
 */
export type DeadlineNote = {
  code: "DDL-001";
  severity: "info";
  title: string;
  detail: string;
};

export type CriticalDatesRegister = {
  register: CriticalDate[];
  resolved_count: number;
  unresolved_count: number;
  /** SHA-256 over the canonical register — independent of `result_hash`. */
  critical_dates_hash: string;
  /**
   * Deadline drafting notes (DDL-###). Present only when a deadline profile was
   * asserted and at least one note applies. Outside the hash.
   */
  deadline_notes?: DeadlineNote[];
};

/**
 * DDL-001 — the document's own math lands on a non-court day before rolling.
 * A drafting observation: the drafter chose a period that expires on a
 * weekend/holiday, so the court rule rolls it forward. Derived from the roll
 * steps the profile recorded.
 */
function buildDeadlineNotes(rows: readonly CriticalDate[]): DeadlineNote[] {
  const rolled = rows.filter(
    (r) => r.resolved && r.deadline_steps?.some((s) => /rolled forward/.test(s.detail)),
  );
  if (rolled.length === 0) return [];
  const examples = rolled
    .slice(0, 6)
    .map((r) => `"${r.trigger}" → ${r.computed_date}`)
    .join("; ");
  return [
    {
      code: "DDL-001",
      severity: "info",
      title: `${rolled.length} deadline${rolled.length === 1 ? " falls" : "s fall"} on a non-court day before rolling forward`,
      detail: `The document's own date math lands on a weekend or holiday; the selected court rule rolls it to the next court day: ${examples}. Confirm the intended deadline.`,
    },
  ];
}

// ---------------------------------------------------------------------------
// The arithmetic (spec §25, companion §3) — pure, clock-free.
// ---------------------------------------------------------------------------

function pad(n: number, w: number): string {
  return n.toString().padStart(w, "0");
}

function toIso(y: number, m: number, d: number): string {
  return `${pad(y, 4)}-${pad(m, 2)}-${pad(d, 2)}`;
}

function parseIso(iso: string): [number, number, number] | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso);
  if (!m) return null;
  return [+m[1]!, +m[2]!, +m[3]!];
}

/** Days in a Gregorian month (1-indexed), leap-year-correct. */
function daysInMonth(year: number, month1: number): number {
  return new Date(Date.UTC(year, month1, 0)).getUTCDate();
}

/** Add `n` calendar days (n may be negative), UTC, deterministic. */
function addDays(iso: string, n: number): string {
  const p = parseIso(iso);
  if (!p) return iso;
  const dt = new Date(Date.UTC(p[0], p[1] - 1, p[2]));
  dt.setUTCDate(dt.getUTCDate() + n);
  return toIso(dt.getUTCFullYear(), dt.getUTCMonth() + 1, dt.getUTCDate());
}

/**
 * Add `n` calendar months (n may be negative), clamping the day at the
 * target month's end: `Jan 31 + 1 month = Feb 28` (or Feb 29 in a leap
 * year), `Mar 31 − 1 month = Feb 28`. The single rule the companion §3
 * pins and the property tests check at every February boundary.
 */
function addMonths(iso: string, n: number): string {
  const p = parseIso(iso);
  if (!p) return iso;
  const [y, m, d] = p;
  // Zero-indexed absolute month, floor-divided so negatives wrap correctly.
  const total = y * 12 + (m - 1) + n;
  const ny = Math.floor(total / 12);
  const nm = total - ny * 12 + 1; // back to 1-indexed
  const clampedDay = Math.min(d, daysInMonth(ny, nm));
  return toIso(ny, nm, clampedDay);
}

/**
 * The derivation contract: `anchor ± count {unit}`. Calendar arithmetic
 * only, no clock. Returns an unresolved {@link DerivedDate} (never a
 * guess) when the anchor is absent, the unit is business-days (no holiday
 * calendar is asserted — companion §3), or the count is missing.
 */
export function deriveDate(reference: DateReference, anchorIso: string | null): DerivedDate {
  if (!anchorIso) {
    return {
      resolved: false,
      computed_date: null,
      reason: reference.anchor
        ? `relative to "${reference.anchor}", which has no defined calendar date`
        : "relative date with no resolvable anchor",
    };
  }
  const unit = reference.offset_unit;
  if (unit === "business-days") {
    const n = reference.offset_count;
    return {
      resolved: false,
      computed_date: null,
      reason: `business-day deadline (${n === undefined ? "n" : Math.abs(n)} business days) — no holiday calendar is asserted; verify manually`,
    };
  }
  if (unit === undefined || reference.offset_count === undefined) {
    // Fall back to the day-collapsed offset when the calendar unit was not
    // captured (older reference shapes) — still deterministic.
    if (reference.offset_days === undefined) {
      return { resolved: false, computed_date: null, reason: "no offset to apply" };
    }
    return { resolved: true, computed_date: addDays(anchorIso, reference.offset_days) };
  }
  const apply = (count: number): string => addByUnit(anchorIso, unit, count);
  // Disjunctive range → derive both bounds; the register shows the window.
  if (
    reference.offset_count_max !== undefined &&
    reference.offset_count_max !== reference.offset_count
  ) {
    const a = apply(reference.offset_count);
    const b = apply(reference.offset_count_max);
    const lo = a <= b ? a : b;
    const hi = a <= b ? b : a;
    return { resolved: true, computed_date: lo, window: [lo, hi] };
  }
  return { resolved: true, computed_date: apply(reference.offset_count) };
}

function addByUnit(
  iso: string,
  unit: "days" | "weeks" | "months" | "years",
  count: number,
): string {
  switch (unit) {
    case "days":
      return addDays(iso, count);
    case "weeks":
      return addDays(iso, count * 7);
    case "months":
      return addMonths(iso, count);
    case "years":
      return addMonths(iso, count * 12);
  }
}

// ---------------------------------------------------------------------------
// Anchor resolution (spec §26 / companion §2).
// ---------------------------------------------------------------------------

const ABS_ISO = /\b(\d{4})-(\d{2})-(\d{2})\b/;
const ABS_MONTHS =
  "January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec";
const ABS_PROSE = new RegExp(String.raw`\b(${ABS_MONTHS})\.?\s+(\d{1,2}),?\s+(\d{4})\b`, "i");
const ABS_US = /\b(\d{1,2})\/(\d{1,2})\/(\d{2,4})\b/;
const MONTH_NUM: Record<string, number> = {
  january: 1,
  jan: 1,
  february: 2,
  feb: 2,
  march: 3,
  mar: 3,
  april: 4,
  apr: 4,
  may: 5,
  june: 6,
  jun: 6,
  july: 7,
  jul: 7,
  august: 8,
  aug: 8,
  september: 9,
  sep: 9,
  sept: 9,
  october: 10,
  oct: 10,
  november: 11,
  nov: 11,
  december: 12,
  dec: 12,
};

function validIso(y: number, m: number, d: number): boolean {
  if (m < 1 || m > 12 || d < 1 || d > 31) return false;
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

/** First absolute date in `text` → ISO, or undefined. Mirrors exports.ts. */
function firstAbsoluteIso(text: string): string | undefined {
  let m = ABS_ISO.exec(text);
  if (m && validIso(+m[1]!, +m[2]!, +m[3]!)) return toIso(+m[1]!, +m[2]!, +m[3]!);
  m = ABS_PROSE.exec(text);
  if (m) {
    const mo = MONTH_NUM[m[1]!.toLowerCase().replace(/\./g, "")];
    if (mo !== undefined && validIso(+m[3]!, mo, +m[2]!)) return toIso(+m[3]!, mo, +m[2]!);
  }
  m = ABS_US.exec(text);
  if (m) {
    let y = +m[3]!;
    if (m[3]!.length === 2) y = y < 70 ? 2000 + y : 1900 + y;
    if (validIso(y, +m[1]!, +m[2]!)) return toIso(y, +m[1]!, +m[2]!);
  }
  return undefined;
}

function normalizeAnchor(anchor: string): string {
  return anchor
    .trim()
    .toLowerCase()
    .replace(/^the\s+/, "")
    .replace(/\s+/g, " ");
}

/**
 * Build the anchor → ISO map. Two sources, both deterministic:
 *   1. A definition whose text pins a single absolute date
 *      ("'Effective Date' means January 1, 2025").
 *   2. An absolute date co-located in the same paragraph as the anchor's
 *      defining parenthetical ("as of January 1, 2025 (the 'Effective
 *      Date')") — recovered by walking the tree once.
 * Never a guess: an anchor with no concrete date simply stays unmapped,
 * and the derived date is unresolved.
 */
export function resolveAnchors(extracted: ExtractedData, tree?: DocumentTree): Map<string, string> {
  const map = new Map<string, string>();
  for (const entry of extracted.definitions.entries) {
    const iso = firstAbsoluteIso(entry.definition);
    if (iso) map.set(normalizeAnchor(entry.term), iso);
  }
  if (tree) {
    // Co-location: a paragraph that both states an absolute date and
    // names an anchor (via "(the 'X Date')" or a bare "X Date") binds them.
    const anchorParen =
      /\(\s*(?:the\s+)?["“”']?([A-Z][\w\s-]{2,40}?\s+Date|Date\s+Hereof)["“”']?\s*\)/g;
    forEachParagraph(tree, (ctx) => {
      const iso = firstAbsoluteIso(ctx.text);
      if (!iso) return;
      anchorParen.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = anchorParen.exec(ctx.text)) !== null) {
        const key = normalizeAnchor(m[1]!);
        if (!map.has(key)) map.set(key, iso);
      }
    });
  }
  return map;
}

// ---------------------------------------------------------------------------
// Classification (spec §27 / companion §4).
// ---------------------------------------------------------------------------

const KIND_PATTERNS: Array<{ kind: CriticalDateKind; re: RegExp }> = [
  {
    kind: "auto-renewal-notice",
    re: /\b(?:auto[-\s]?renew\w*|renew\w*|non[-\s]?renewal|anniversary|roll(?:s|ing)?\s+over|evergreen)\b/i,
  },
  {
    kind: "cure-window",
    re: /\b(?:cure|cured|remed\w+|default|breach|failure\s+to\s+(?:pay|perform))\b/i,
  },
  {
    kind: "opt-out-window",
    re: /\b(?:terminat\w+\s+for\s+convenience|opt[-\s]?out|terminat\w+\s+(?:this\s+)?(?:agreement|contract)|without\s+cause|for\s+any\s+reason)\b/i,
  },
  {
    kind: "survival-end",
    re: /\b(?:surviv\w+|continue\s+in\s+(?:full\s+)?(?:force|effect)\s+for|remain\s+in\s+effect\s+for)\b/i,
  },
];

/**
 * Classify a relative date into a deadline family from the clause text
 * around it. The classification is render/grouping metadata; it never
 * changes the computed date. Defaults to the general notice-period family.
 */
function classifyDeadline(ref: DateReference, contextText: string): CriticalDateKind {
  const hay = `${ref.raw_text} ${contextText}`;
  for (const { kind, re } of KIND_PATTERNS) {
    if (re.test(hay)) return kind;
  }
  return "notice-period";
}

/** Find the responsible party for a date from obligations in its section. */
function responsibleFor(ref: DateReference, obligations: readonly Obligation[]): string {
  const section = ref.position.section_id;
  const inSection = obligations.filter((o) => o.position.section_id === section);
  if (inSection.length === 0) return "";
  // Prefer an obligation whose clause overlaps the date's raw text.
  const overlap = inSection.find(
    (o) => ref.raw_text.length > 0 && o.raw_text.includes(ref.raw_text.slice(0, 24)),
  );
  const chosen = overlap ?? inSection[0]!;
  const obligor = chosen.obligor.trim();
  // A bare "each party" / generic obligor is not a named responsible party.
  if (!obligor || /^(?:each|either|both|the)\s+part/i.test(obligor)) return "";
  return obligor;
}

// ---------------------------------------------------------------------------
// The register (spec §29 / companion §5).
// ---------------------------------------------------------------------------

/**
 * Build the canonically-sorted critical-dates register. Each relative
 * date with a captured offset becomes one row; the anchor is resolved and
 * the absolute date computed (or marked unresolved). Pure and clock-free;
 * carries its own hash, namespaced apart from `result_hash`.
 */
/**
 * Apply an asserted deadline profile to one register row. Handles exactly two
 * offset kinds — "business-days" (court-day counting) and "days" (FRCP 6(a)
 * roll-forward + 6(d) service) — leaving every other unit and any unanchored
 * row untouched. Returns a new row carrying the computed date and the applied
 * steps, or the original row unchanged when the profile does not apply or the
 * computation lands outside the calendar's covered range.
 */
function resolveUnderProfile(
  row: CriticalDate,
  ref: DateReference,
  anchorIso: string,
  deadline: DeadlineResolution,
): CriticalDate {
  const count = ref.offset_count;
  if (count === undefined) return row;
  const { profile, service_method } = deadline;

  const result =
    ref.offset_unit === "business-days"
      ? computeCourtDays({ trigger: anchorIso, days: Math.abs(count), profile })
      : ref.offset_unit === "days"
        ? computeDeadline({ trigger: anchorIso, days: Math.abs(count), profile, service_method })
        : null;
  if (!result) return row; // unit the profile does not compute (weeks/months/years)

  if (!result.resolved) {
    // The profile could not compute (e.g. outside the calendar's covers). If the
    // row was already resolved by plain arithmetic (a "days" offset needs no
    // calendar), keep that resolved date — the profile just adds nothing here.
    // If it was unresolved (a "business-days" offset), keep it unresolved but
    // attribute the reason to the asserted profile.
    if (row.resolved) return row;
    return { ...row, resolved: false, computed_date: null, reason: result.reason };
  }
  return {
    ...row,
    resolved: true,
    computed_date: result.date,
    reason: undefined,
    deadline_steps: result.steps,
    deadline_profile_id: result.profile_id,
    deadline_calendar_version: result.calendar_version,
  };
}

export async function buildCriticalDates(
  extracted: ExtractedData,
  tree?: DocumentTree,
  deadline?: DeadlineResolution,
): Promise<CriticalDatesRegister> {
  const anchors = resolveAnchors(extracted, tree);
  const sectionText = tree ? buildSectionText(tree) : new Map<string, string>();

  const rows: CriticalDate[] = [];
  for (const ref of extracted.dates) {
    if (ref.type !== "relative") continue;
    // Need an offset to derive a deadline at all.
    if (ref.offset_count === undefined && ref.offset_days === undefined) continue;
    const anchorIso = ref.anchor ? (anchors.get(normalizeAnchor(ref.anchor)) ?? null) : null;
    const derived = deriveDate(ref, anchorIso);
    const context = sectionText.get(ref.position.section_id ?? "") ?? "";
    const kind = classifyDeadline(ref, context);
    const responsible = responsibleFor(ref, extracted.obligations);
    const base: CriticalDate = {
      rule_id: KIND_RULE_ID[kind],
      kind,
      resolved: derived.resolved,
      computed_date: derived.computed_date,
      ...(derived.window ? { window: derived.window } : {}),
      trigger: ref.raw_text,
      anchor: ref.anchor ?? "",
      responsible,
      ...(ref.position.section_id ? { section: ref.position.section_id } : {}),
      ...(derived.reason ? { reason: derived.reason } : {}),
    };
    // add-deadline-computation — opt-in resolution. Only touches "business-days"
    // (court-day counting) and "days" (roll-forward + service adjustment) units
    // and only when a profile is asserted and an anchor is present. Every other
    // row is left byte-identical, so an unprofiled register never moves.
    rows.push(deadline && anchorIso ? resolveUnderProfile(base, ref, anchorIso, deadline) : base);
  }

  // Canonical order: resolved dates ascending, then unresolved grouped at
  // the end by clause text (companion §5). Stable and machine-independent.
  rows.sort((a, b) => {
    if (a.resolved !== b.resolved) return a.resolved ? -1 : 1;
    if (a.resolved && b.resolved) {
      const cmp = (a.computed_date ?? "").localeCompare(b.computed_date ?? "", "en");
      if (cmp) return cmp;
    }
    return (
      a.rule_id.localeCompare(b.rule_id, "en") ||
      a.trigger.localeCompare(b.trigger, "en") ||
      (a.section ?? "").localeCompare(b.section ?? "", "en")
    );
  });

  const resolved_count = rows.filter((r) => r.resolved).length;
  const critical_dates_hash = await sha256Hex(stableStringify({ register: rows }));
  // DDL drafting notes — advisory, only when a profile was asserted; outside the hash.
  const deadline_notes = deadline ? buildDeadlineNotes(rows) : [];
  return {
    register: rows,
    resolved_count,
    unresolved_count: rows.length - resolved_count,
    critical_dates_hash,
    ...(deadline_notes.length > 0 ? { deadline_notes } : {}),
  };
}

function buildSectionText(tree: DocumentTree): Map<string, string> {
  const map = new Map<string, string>();
  forEachParagraph(tree, (ctx) => {
    const prev = map.get(ctx.section.id) ?? "";
    map.set(ctx.section.id, prev ? `${prev} ${ctx.text}` : ctx.text);
  });
  return map;
}
