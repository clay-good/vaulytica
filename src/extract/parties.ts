import type { DocumentTree } from "../ingest/types.js";
import type { Party, DocPosition } from "./types.js";
import { forEachParagraph } from "./walk.js";

/**
 * Extract contracting parties from the document preamble and signature
 * blocks. Heuristics, in order:
 *
 * 1. Preamble pattern: `between X and Y` / `by and between X, … and Y, …`,
 *    looked up in the first 25% of the document.
 * 2. Defined-role pattern: `X, a Delaware corporation ("Provider")`. The
 *    quoted label is the role; the leading entity name is the party.
 * 3. Signature-block pattern: lines containing `By: ___` near the end of
 *    the document anchor the canonical party names. Names from signature
 *    blocks are unioned with preamble matches.
 *
 * Conservative: when no clean match is found, an empty array is returned.
 * Downstream rules (STRUCT-001) catch the absence.
 */

const ENTITY_TYPES = [
  "corporation",
  "company",
  "inc\\.?",
  "llc",
  "l\\.l\\.c\\.",
  "ltd\\.?",
  "limited liability company",
  "limited partnership",
  "partnership",
  "trust",
  "individual",
  "sole proprietorship",
  "professional corporation",
  "pllc",
  "gmbh",
  "ag",
  "plc",
];

const US_STATE = "(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming|District of Columbia|D\\.C\\.)";

// `g` only (not `gi`) — the case-insensitive flag would defeat the
// capitalized-word name pattern and let the engine slurp lowercase
// connectives like `is`, `made`, `between`, `and` into the captured
// name. Entity-type tokens in the text are lowercase by convention
// ("a Delaware corporation"); the `ENTITY_TYPES` list mirrors that.
const PARTY_DECL = new RegExp(
  String.raw`([A-Z][\w&.,'’-]*(?:\s+[A-Z][\w&.,'’-]*){0,6})\s*,?\s*(?:a|an)?\s*(?:(${US_STATE})\s+)?(${ENTITY_TYPES.join("|")})\s*(?:\(\s*["“”']([^"”'’\)]+)["“”']\s*\))?`,
  "g",
);

const BETWEEN_RE = /\bbetween\s+(.+?)\s+and\s+(.+?)(?:[.;,]|$)/i;

const SIGNATURE_LINE = /^(?:By|Name|Title|Date)\s*:?\s*/i;

/**
 * Every "By:" / "Name:" segment in a signature paragraph, not just the
 * leading one. Two-column e-signature blocks flatten to one line with
 * both parties' "By:"/"Name:" fields; capturing each segment recovers
 * the second party the leading-anchored regex drops. (v7 §7.)
 */
const SIGNATURE_FIELD =
  /\b(?:By|Name)\s*:\s*(?:\/s\/\s*)?([A-Z][\w.'’-]*(?:\s+[A-Z][\w.'’-]*){0,4}?)(?=\s+(?:By|Name|Title|Date|its)\b|[,;]|\t|\s{2,}|$)/g;

/**
 * "doing business as" / "d/b/a" operating name following a legal name.
 * Capture both names; the operating name becomes the party's `dba`.
 */
const DBA_RE =
  /\b(?:d\/b\/a|d\.b\.a\.|dba|doing business as)\s+["“”']?([A-Z][\w&.,'’-]*(?:\s+[A-Z][\w&.,'’-]*){0,5})/gi;

export function extractParties(tree: DocumentTree): Party[] {
  const partyMap = new Map<string, Party>();
  const allText: { text: string; pos: (start: number, end: number) => DocPosition }[] = [];

  forEachParagraph(tree, (ctx) => {
    allText.push({
      text: ctx.text,
      pos: (start, end) => ({
        section_id: ctx.section.id,
        paragraph_id: ctx.paragraph.id,
        start: ctx.start + start,
        end: ctx.start + end,
      }),
    });
  });

  // Determine the preamble: first 25% by paragraph count.
  const preambleCount = Math.max(1, Math.ceil(allText.length * 0.25));

  for (let i = 0; i < preambleCount && i < allText.length; i += 1) {
    const { text, pos } = allText[i]!;
    PARTY_DECL.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = PARTY_DECL.exec(text)) !== null) {
      const name = (m[1] ?? "").trim();
      const state = m[2];
      const entity = m[3];
      const role = m[4];
      if (!name || isBoilerplateName(name)) continue;
      registerParty(partyMap, name, {
        role,
        entity_type: entity,
        jurisdiction_of_formation: state,
        position: pos(m.index, m.index + m[0].length),
      });
    }
    DBA_RE.lastIndex = 0;
    let dm: RegExpExecArray | null;
    while ((dm = DBA_RE.exec(text)) !== null) {
      const dba = cleanPartyName(dm[1] ?? "");
      if (!dba) continue;
      // Attach to the party whose declaration ends nearest before the
      // d/b/a phrase (the legal name it operates under).
      const before = text.slice(0, dm.index);
      PARTY_DECL.lastIndex = 0;
      let pm: RegExpExecArray | null;
      let legal = "";
      while ((pm = PARTY_DECL.exec(before)) !== null) {
        const cand = (pm[1] ?? "").trim();
        if (cand && !isBoilerplateName(cand)) legal = cand;
      }
      const target = legal ? partyMap.get(legal.toLowerCase()) : undefined;
      if (target && !target.dba) target.dba = dba;
    }
    const betweenMatch = BETWEEN_RE.exec(text);
    if (betweenMatch) {
      const a = cleanPartyName(betweenMatch[1] ?? "");
      const b = cleanPartyName(betweenMatch[2] ?? "");
      if (a) {
        registerParty(partyMap, a, {
          position: pos(betweenMatch.index, betweenMatch.index + (betweenMatch[1]?.length ?? 0)),
        });
      }
      if (b) {
        registerParty(partyMap, b, {
          position: pos(
            betweenMatch.index + (betweenMatch[1]?.length ?? 0) + 5,
            betweenMatch.index + betweenMatch[0].length,
          ),
        });
      }
    }
  }

  // Signature blocks: last 15% of paragraphs.
  const sigStart = Math.floor(allText.length * 0.85);
  for (let i = sigStart; i < allText.length; i += 1) {
    const { text, pos } = allText[i]!;
    if (SIGNATURE_LINE.test(text)) {
      const after = text.replace(SIGNATURE_LINE, "").trim();
      if (after && /[A-Z]/.test(after) && !/^_+$/.test(after)) {
        const name = cleanPartyName(after);
        if (name) {
          registerParty(partyMap, name, { position: pos(0, text.length) });
        }
      }
    }
    // Two-column / tabular signature blocks: pick up every "By:"/"Name:"
    // field on the line, including the second party's column.
    SIGNATURE_FIELD.lastIndex = 0;
    let sm: RegExpExecArray | null;
    while ((sm = SIGNATURE_FIELD.exec(text)) !== null) {
      const name = cleanPartyName(sm[1] ?? "");
      if (name && !isBoilerplateName(name)) {
        registerParty(partyMap, name, {
          position: pos(sm.index, sm.index + sm[0].length),
        });
      }
    }
  }

  // Resolve alias / role chains: a short form, an upper-cased variant,
  // the defined role, and any d/b/a name all point at one entity.
  for (const party of partyMap.values()) {
    const aliases = computeAliases(party);
    if (aliases.length > 0) party.aliases = aliases;
  }

  // Record every additional occurrence of each known party name.
  for (const party of partyMap.values()) {
    const needle = new RegExp(`\\b${escapeRegExp(party.name)}\\b`, "g");
    for (const { text, pos } of allText) {
      needle.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = needle.exec(text)) !== null) {
        party.positions.push(pos(m.index, m.index + m[0].length));
      }
    }
    // Deduplicate by start offset.
    const seen = new Set<number>();
    party.positions = party.positions.filter((p) => {
      if (seen.has(p.start)) return false;
      seen.add(p.start);
      return true;
    });
  }

  return [...partyMap.values()];
}

function registerParty(
  map: Map<string, Party>,
  name: string,
  extras: {
    role?: string;
    entity_type?: string;
    jurisdiction_of_formation?: string;
    position?: DocPosition;
  },
): void {
  const key = name.toLowerCase();
  const existing = map.get(key);
  if (existing) {
    existing.role = existing.role ?? extras.role;
    existing.entity_type = existing.entity_type ?? extras.entity_type;
    existing.jurisdiction_of_formation =
      existing.jurisdiction_of_formation ?? extras.jurisdiction_of_formation;
    if (extras.position) existing.positions.push(extras.position);
    return;
  }
  map.set(key, {
    id: `party-${map.size + 1}`,
    name,
    role: extras.role,
    entity_type: extras.entity_type,
    jurisdiction_of_formation: extras.jurisdiction_of_formation,
    positions: extras.position ? [extras.position] : [],
  });
}

/**
 * Build the alternate surface forms that refer to the same entity:
 * a short form (the leading distinctive word of a multi-word legal
 * name), an all-caps variant, the defined role, and the d/b/a name.
 * Excludes the canonical name itself and dedupes.
 */
function computeAliases(party: Party): string[] {
  const out: string[] = [];
  const add = (s: string | undefined): void => {
    if (!s) return;
    const v = s.trim();
    if (v && v.toLowerCase() !== party.name.toLowerCase() && !out.includes(v)) out.push(v);
  };
  if (party.role) add(party.role);
  if (party.dba) add(party.dba);
  // Short form: leading word(s) before a corporate suffix, tolerant of
  // trailing punctuation ("Acme Corp.," → "Acme"; "Globex International
  // Ltd." → "Globex International").
  const base = party.name.replace(/[\s.,;]+$/, "");
  const short = base.replace(
    /[\s,]+(?:Corp|Corporation|Inc|LLC|L\.L\.C\.|Ltd|Limited|Co|Company|GmbH|AG|PLC|LP|LLP|PLLC)\b\.?$/i,
    "",
  );
  if (short && short !== base && /\s/.test(base)) {
    add(short);
    const firstWord = short.split(/\s+/)[0];
    if (firstWord && firstWord.length >= 3) add(firstWord);
  }
  // All-caps variant ("ACME") when the name is mixed-case single-token-ish.
  const upper = party.name.toUpperCase();
  if (upper !== party.name && party.name.length <= 24) add(upper);
  return out;
}

function cleanPartyName(raw: string): string {
  let n = raw.trim().replace(/^["“”'’\s]+|["“”'’\s]+$/g, "");
  // Strip trailing entity descriptor like ", a Delaware corporation".
  n = n.replace(/,\s*(?:a|an)\s+.+$/i, "");
  n = n.replace(/[.,;]+$/, "");
  if (n.length < 2 || n.length > 80) return "";
  if (!/[A-Z]/.test(n.charAt(0))) return "";
  return n;
}

function isBoilerplateName(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    lower === "agreement" ||
    lower === "parties" ||
    lower === "preamble" ||
    lower.startsWith("the agreement") ||
    lower === "effective date"
  );
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
