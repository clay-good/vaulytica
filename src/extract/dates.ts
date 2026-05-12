import type { DocumentTree } from "../ingest/types.js";
import type { DateReference } from "./types.js";
import { forEachParagraph, posInParagraph } from "./walk.js";

/**
 * Extract every date reference from the document. Three categories:
 *
 * 1. Absolute dates: `2025-01-01`, `1/1/2025`, `01/01/25`, `January 1, 2025`.
 * 2. Relative dates: `thirty (30) days after the Effective Date`,
 *    `within 60 days of the date hereof`.
 * 3. Named-anchor references: bare uses of defined date terms such as
 *    `the Effective Date` or `the Closing Date`. (The actual definition
 *    is resolved by the definitions extractor, not here.)
 */

const MONTHS =
  "January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec";

const ISO = /\b(\d{4})-(\d{2})-(\d{2})\b/g;
const US_NUMERIC = /\b(\d{1,2})\/(\d{1,2})\/(\d{2,4})\b/g;
const PROSE = new RegExp(
  String.raw`\b(${MONTHS})\.?\s+(\d{1,2}),?\s+(\d{4})\b`,
  "gi",
);

const NUMBER_WORDS: Record<string, number> = {
  zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7,
  eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13,
  fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17, eighteen: 18,
  nineteen: 19, twenty: 20, thirty: 30, forty: 40, fifty: 50, sixty: 60,
  seventy: 70, eighty: 80, ninety: 90, hundred: 100,
};

const RELATIVE = new RegExp(
  String.raw`\b(?:within\s+)?(\w+(?:[-\s]\w+)?)\s*\(?\s*(\d+)?\s*\)?\s*(day|days|week|weeks|month|months|year|years|business\s+day|business\s+days)\s+(?:after|before|of|from|following|prior\s+to)\s+(?:the\s+)?([A-Z][\w\s]{2,40}?)(?=[.,;)]|$)`,
  "gi",
);

const NAMED_ANCHOR = /\bthe\s+(Effective|Closing|Commencement|Termination|Expiration|Renewal|Execution)\s+Date\b/gi;

export function extractDates(tree: DocumentTree): DateReference[] {
  const out: DateReference[] = [];
  let counter = 0;
  const nextId = (): string => `date-${++counter}`;

  forEachParagraph(tree, (ctx) => {
    ISO.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = ISO.exec(ctx.text)) !== null) {
      const iso = `${m[1]}-${m[2]}-${m[3]}`;
      const valid = isValidIso(iso);
      out.push({
        id: nextId(),
        type: "absolute",
        raw_text: m[0],
        iso: valid ? iso : undefined,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
    US_NUMERIC.lastIndex = 0;
    while ((m = US_NUMERIC.exec(ctx.text)) !== null) {
      const mm = parseInt(m[1]!, 10);
      const dd = parseInt(m[2]!, 10);
      let yyyy = parseInt(m[3]!, 10);
      if (m[3]!.length === 2) yyyy = yyyy < 70 ? 2000 + yyyy : 1900 + yyyy;
      const iso = `${yyyy.toString().padStart(4, "0")}-${mm.toString().padStart(2, "0")}-${dd.toString().padStart(2, "0")}`;
      out.push({
        id: nextId(),
        type: "absolute",
        raw_text: m[0],
        iso: isValidIso(iso) ? iso : undefined,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
    PROSE.lastIndex = 0;
    while ((m = PROSE.exec(ctx.text)) !== null) {
      const month = monthNumber(m[1]!);
      const day = parseInt(m[2]!, 10);
      const year = parseInt(m[3]!, 10);
      const iso =
        month !== null
          ? `${year.toString().padStart(4, "0")}-${month.toString().padStart(2, "0")}-${day.toString().padStart(2, "0")}`
          : undefined;
      out.push({
        id: nextId(),
        type: "absolute",
        raw_text: m[0],
        iso: iso && isValidIso(iso) ? iso : undefined,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
    RELATIVE.lastIndex = 0;
    while ((m = RELATIVE.exec(ctx.text)) !== null) {
      const wordCount = m[1] ? parseWordNumber(m[1]) : null;
      const numericCount = m[2] ? parseInt(m[2], 10) : null;
      const unit = (m[3] ?? "").toLowerCase().replace(/\s+/g, " ").trim();
      const anchor = (m[4] ?? "").trim();
      const count = numericCount ?? wordCount;
      const direction = /\bbefore\b|\bprior\s+to\b/i.test(m[0]) ? -1 : 1;
      const days = count !== null ? count * unitToDays(unit) * direction : undefined;
      out.push({
        id: nextId(),
        type: "relative",
        raw_text: m[0],
        anchor,
        offset_days: days,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
    NAMED_ANCHOR.lastIndex = 0;
    while ((m = NAMED_ANCHOR.exec(ctx.text)) !== null) {
      const word = m[1]!;
      const title = word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
      out.push({
        id: nextId(),
        type: "named-anchor",
        raw_text: m[0].replace(/^the\s+/i, ""),
        anchor: `${title} Date`,
        position: posInParagraph(ctx, m.index, m.index + m[0].length),
      });
    }
  });

  return out;
}

function monthNumber(name: string): number | null {
  const map: Record<string, number> = {
    january: 1, jan: 1, february: 2, feb: 2, march: 3, mar: 3, april: 4, apr: 4,
    may: 5, june: 6, jun: 6, july: 7, jul: 7, august: 8, aug: 8,
    september: 9, sep: 9, sept: 9, october: 10, oct: 10,
    november: 11, nov: 11, december: 12, dec: 12,
  };
  const v = map[name.toLowerCase().replace(/\./g, "")];
  return v ?? null;
}

function isValidIso(iso: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso);
  if (!m) return false;
  const y = +m[1]!;
  const mo = +m[2]!;
  const d = +m[3]!;
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return false;
  const date = new Date(Date.UTC(y, mo - 1, d));
  return date.getUTCFullYear() === y && date.getUTCMonth() === mo - 1 && date.getUTCDate() === d;
}

function parseWordNumber(raw: string): number | null {
  const parts = raw.toLowerCase().split(/[-\s]+/);
  let total = 0;
  let recognized = false;
  for (const p of parts) {
    const v = NUMBER_WORDS[p];
    if (v === undefined) continue;
    recognized = true;
    if (v === 100) total = (total || 1) * 100;
    else total += v;
  }
  return recognized ? total : null;
}

function unitToDays(unit: string): number {
  if (unit.startsWith("business day")) return 1;
  if (unit.startsWith("day")) return 1;
  if (unit.startsWith("week")) return 7;
  if (unit.startsWith("month")) return 30;
  if (unit.startsWith("year")) return 365;
  return 1;
}
