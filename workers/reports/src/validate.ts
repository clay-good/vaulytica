/**
 * What the report endpoint accepts (spec-v53 §5).
 *
 * **Built so a contract cannot fit through it.** A JSON body of at most 4 KB
 * with an exact set of keys. `rule` and `type` must be ids in the shipped
 * catalog — the Worker carries a generated list — so a custom id is rejected
 * even if a client sends one. The note is capped at 280 characters and
 * stripped of control and bidirectional-override characters. There is no key
 * for an excerpt, a filename, a document hash, or a `result_hash`, and an
 * unknown key is an error rather than something to ignore.
 */

export const MAX_BODY_BYTES = 4096;
export const NOTE_MAX = 280;
export const TOKEN_MAX = 2048;

export const KINDS = ["wrong-finding", "missed", "wrong-type", "site"] as const;
export type Kind = (typeof KINDS)[number];

/** The exact keys of a request body. Anything else is refused. */
export const BODY_KEYS = ["kind", "rule", "rv", "engine", "dkb", "type", "near", "note", "token"] as const;

/** Ids as the catalog ships them. */
export type Catalog = { rules: ReadonlySet<string>; types: ReadonlySet<string> };

export type Report = {
  kind: Kind;
  rule_id: string | null;
  rule_version: string | null;
  engine_version: string;
  dkb_version: string | null;
  document_type: string | null;
  near_family: string | null;
  note: string | null;
};

export type Parsed =
  | { ok: true; report: Report; token: string }
  | { ok: false; status: 400 | 413; error: string };

const VERSION = /^\d{1,3}\.\d{1,5}\.\d{1,3}$/;
const DKB = /^v[0-9A-Za-z.-]{1,40}$/;

/** Control characters and bidirectional overrides: stripped, never stored. */
// eslint-disable-next-line no-control-regex, no-misleading-character-class
const UNPRINTABLE = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029\ufeff]/g;

export function cleanNote(note: string): string {
  return note.replace(UNPRINTABLE, " ").replace(/\s+/g, " ").trim();
}

const refuse = (error: string, status: 400 | 413 = 400): Parsed => ({ ok: false, status, error });

export function parseReport(bodyText: string, catalog: Catalog): Parsed {
  if (new TextEncoder().encode(bodyText).length > MAX_BODY_BYTES) {
    return refuse("body too large", 413);
  }
  let body: unknown;
  try {
    body = JSON.parse(bodyText);
  } catch {
    return refuse("body is not JSON");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return refuse("body is not an object");
  }
  const b = body as Record<string, unknown>;
  const allowed: ReadonlySet<string> = new Set(BODY_KEYS);
  for (const key of Object.keys(b)) {
    if (!allowed.has(key)) return refuse("unknown key");
  }
  // Every value is a string or absent. A nested object is one more place text could hide.
  for (const key of BODY_KEYS) {
    if (b[key] !== undefined && typeof b[key] !== "string") return refuse(`${key} is not a string`);
  }
  const s = b as Partial<Record<(typeof BODY_KEYS)[number], string>>;

  if (!s.kind || !(KINDS as readonly string[]).includes(s.kind)) return refuse("unknown kind");
  if (!s.engine || !VERSION.test(s.engine)) return refuse("bad engine version");
  if (!s.token || s.token.length > TOKEN_MAX) return refuse("missing token");
  if (s.rule !== undefined && !catalog.rules.has(s.rule)) return refuse("unknown rule");
  if (s.rv !== undefined && !VERSION.test(s.rv)) return refuse("bad rule version");
  if (s.rv !== undefined && s.rule === undefined) return refuse("rule version without a rule");
  if (s.dkb !== undefined && !DKB.test(s.dkb)) return refuse("bad knowledge base version");
  if (s.type !== undefined && !catalog.types.has(s.type)) return refuse("unknown document type");
  if (s.near !== undefined && !catalog.types.has(s.near)) return refuse("unknown document type");
  if (s.kind === "wrong-finding" && s.rule === undefined) return refuse("a wrong finding names its rule");

  let note: string | null = null;
  if (s.note !== undefined) {
    const cleaned = cleanNote(s.note);
    if (cleaned.length > NOTE_MAX) return refuse("note too long");
    note = cleaned.length > 0 ? cleaned : null;
  }

  return {
    ok: true,
    token: s.token,
    report: {
      kind: s.kind as Kind,
      rule_id: s.rule ?? null,
      rule_version: s.rv ?? null,
      engine_version: s.engine,
      dkb_version: s.dkb ?? null,
      document_type: s.type ?? null,
      near_family: s.near ?? null,
      note,
    },
  };
}
