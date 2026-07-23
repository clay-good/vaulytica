import type { DocumentTree } from "../ingest/types.js";
import type { DefinitionMap, DefinitionEntry, DocPosition } from "./types.js";
import { forEachParagraph, forEachSection, posInParagraph } from "./walk.js";

/**
 * Find every defined term and every use of each. Two recognition paths:
 *
 * 1. Section-level: a section whose heading matches `definitions`,
 *    `defined terms`, or `glossary` is treated as a definitions section;
 *    each paragraph within is parsed for `"Term" means …` or
 *    `Term means …` definitions.
 * 2. Inline: anywhere in the document, `"Term" means …` (with explicit
 *    quotes) is treated as an inline definition.
 *
 * After collecting definitions, the document is re-scanned to record every
 * occurrence of each defined term *outside* its definition. Terms with
 * zero outside-uses populate {@link DefinitionMap.unused_terms}.
 *
 * Finally, Title-Case multi-word phrases that appear in the body but are
 * not defined (and are not party names) are recorded as
 * `undefined_capitalized`. The list is downstream input to STRUCT-006.
 */

// Case-insensitive on `means`: a quoted term followed by "Means"/"MEANS" (common
// after a list marker, in ALL-CAPS drafting, or from OCR) is still a definition;
// without the `i` flag the whole defined term was silently dropped from
// STRUCT-004/005/006 and the definitions appendix. The quoted-term requirement
// keeps this from matching an ordinary sentence that merely contains "means".
const DEFINITION_INLINE = /["“”']([A-Z][\w\s\-&]{1,80}?)["“”']\s+(?:shall\s+)?means?\b/gi;
const DEFINITION_BARE = /^\s*([A-Z][\w\s\-&]{1,80}?)\s+(?:shall\s+)?means?\b/i;

/**
 * The other inline convention, and the dominant one in commercial drafting:
 * the term is introduced by a parenthetical after the phrase it names —
 * `Acme Corp, a Delaware corporation ("Customer")`, `any Statement of Work
 * ("SOW")`, `its pre-existing tools and methodologies ("Vendor Background
 * IP")`. Recognizing only `"Term" means …` made STRUCT-004 report "Vaulytica
 * did not find a Definitions section or any inline-defined terms" on 15 of the
 * 19 minimal-PASS fixtures, every one of which defines its terms this way.
 *
 * The closing `)` must follow the quote immediately, so a quoted phrase used
 * mid-parenthetical (`(the "Services" described in Exhibit A)`) is not read as
 * a definition.
 */
const DEFINITION_PARENTHETICAL =
  /\((?:\s*(?:the|each|an?|collectively|together|individually|hereinafter|referred\s+to\s+as)[,]?\s+)*["\u201C]([A-Z][\w\s\-&/'\u2019.]{1,60}?)["\u201D]\s*\)/g;

/** A definition that points at an exhibit/schedule/section rather than stating its own text. */
const DEFINITION_REFERENCE =
  /\b(?:attached\s+(?:hereto\s+)?as|set\s+forth\s+in|described\s+in|defined\s+in|as\s+set\s+out\s+in|in)\s+((?:Exhibit|Schedule|Appendix|Annex|Attachment|Section|Article)\s+[A-Z0-9][\w.()-]*)/i;

/** A scope-gating prefix that confines a definition to a section/clause. */
const DEFINITION_SCOPE =
  /\b(?:for\s+(?:the\s+)?purposes\s+of|as\s+used\s+in|solely\s+for\s+purposes\s+of)\s+(?:this\s+)?((?:Section|Article|Clause|Paragraph)\s+[\w.()-]+)[,:\s]*$/i;

const DEFINITIONS_HEADING = /\b(definitions?|defined\s+terms|glossary)\b/i;
const TITLE_CASE_PHRASE = /\b((?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4}))\b/g;
const COMMON_WORDS = new Set([
  "Effective Date",
  "Agreement",
  "Section",
  "Article",
  "Exhibit",
  "Schedule",
  "Attachment",
]);

/**
 * Sentence-initial words that are commonly capitalized but never
 * function as defined terms. Filtering by *first word* eliminates the
 * "Each Party," "If Client," "Neither Party" style false positives
 * that arose every time a sentence began with one of these words
 * followed by a capitalized noun. We match on the first word of the
 * candidate phrase, not on the full phrase, so legitimate phrases
 * like "Each Statement of Work" still fail this filter and so do
 * cases like "The Services" (where "The" is the leading stopword).
 */
const TITLE_CASE_LEADING_STOPWORDS = new Set([
  "Each",
  "If",
  "Neither",
  "Either",
  "Both",
  "All",
  "Any",
  "Some",
  "This",
  "These",
  "That",
  "Those",
  "The",
  "A",
  "An",
  "It",
  "He",
  "She",
  "They",
  "We",
  "You",
  "I",
  "Such",
  "Other",
  "Another",
  "No",
  "Not",
  "Nothing",
  "When",
  "Where",
  "While",
  "As",
  "For",
  "From",
  "In",
  "On",
  "Of",
  "To",
  "At",
  "Upon",
  "With",
  "By",
  "And",
  "Or",
  "But",
  "Nor",
  "So",
  "Yet",
  "After",
  "Before",
  "During",
  "Until",
  "Without",
  "Within",
  "Notwithstanding",
  "Provided",
  "Subject",
  "Including",
  "Furthermore",
  "Moreover",
  "Therefore",
  "However",
  "Otherwise",
  "Failure",
  "Each Party",
  "Either Party",
  "Neither Party",
  "Both Parties",
  "The Parties",
  "The Party",
]);

export function extractDefinitions(tree: DocumentTree): DefinitionMap {
  const definitions = new Map<string, DefinitionEntry>();

  // Pass 1: section-level definitions sections.
  forEachSection(tree, (section) => {
    if (!DEFINITIONS_HEADING.test(section.heading)) return;
    let _pIdx = 0;
    for (const p of section.paragraphs) {
      const text = p.runs.map((r) => r.text).join("");
      const inline = scanInlineDefinitions(text, {
        section_id: section.id,
        paragraph_id: p.id,
        start: p.runs[0]?.start ?? 0,
        end: p.runs[p.runs.length - 1]?.end ?? 0,
      });
      for (const d of inline) registerDefinition(definitions, d);
      const bare = DEFINITION_BARE.exec(text);
      if (bare) {
        const term = bare[1]!.trim();
        const def = text
          .slice(bare.index + bare[0].length)
          .trim()
          .replace(/^[-:]+\s*/, "");
        const start = p.runs[0]?.start ?? 0;
        const reference = cleanRef(DEFINITION_REFERENCE.exec(def)?.[1]);
        registerDefinition(definitions, {
          term,
          definition: def,
          defined_at: {
            section_id: section.id,
            paragraph_id: p.id,
            start,
            end: start + text.length,
          },
          used_at: [],
          ...(reference ? { reference } : {}),
        });
      }
      _pIdx += 1;
    }
  });

  // Pass 2: inline definitions everywhere.
  forEachParagraph(tree, (ctx) => {
    for (const d of scanInlineDefinitions(ctx.text, {
      section_id: ctx.section.id,
      paragraph_id: ctx.paragraph.id,
      start: ctx.start,
      end: ctx.end,
    })) {
      registerDefinition(definitions, d);
    }
  });

  // Pass 3: record every use of each term outside its definition.
  for (const entry of definitions.values()) {
    const needle = new RegExp(`\\b${escapeRegExp(entry.term)}\\b`, "g");
    forEachParagraph(tree, (ctx) => {
      // Skip the definition itself. For an express definition that is the
      // whole paragraph — a term repeated inside its own definition body
      // ("… but Confidential Information does not include …") is a
      // self-reference, not a use. A PARENTHETICAL is different: it defines
      // the term mid-sentence in the operative text, and the same paragraph
      // routinely goes on to use it ('any Statement of Work ("SOW") … the SOW
      // shall control'). Skipping that whole paragraph reported the term as
      // never used.
      if (entry.form !== "parenthetical" && ctx.paragraph.id === entry.defined_at.paragraph_id) {
        return;
      }
      needle.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = needle.exec(ctx.text)) !== null) {
        const pos = posInParagraph(ctx, m.index, m.index + m[0].length);
        if (pos.start >= entry.defined_at.start && pos.end <= entry.defined_at.end) continue;
        entry.used_at.push(pos);
      }
    });
  }

  const unused_terms = [...definitions.values()]
    .filter((e) => e.used_at.length === 0)
    .map((e) => e.term)
    .sort();

  // Pass 4: undefined Title-Case phrases.
  const definedNames = new Set([...definitions.keys()]);
  const undefinedHits = new Map<string, DocPosition[]>();
  forEachParagraph(tree, (ctx) => {
    TITLE_CASE_PHRASE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = TITLE_CASE_PHRASE.exec(ctx.text)) !== null) {
      const phrase = m[1]!;
      if (definedNames.has(phrase.toLowerCase())) continue;
      if (COMMON_WORDS.has(phrase)) continue;
      if (TITLE_CASE_LEADING_STOPWORDS.has(phrase)) continue;
      // Only strip sentence-initial-stopword patterns from the candidate
      // list when the phrase is short (2 words). Longer phrases like
      // "The Special Reserve Fund" or "The Annual Operating Plan" are
      // ordinary capitalized noun phrases worth flagging when undefined.
      const words = phrase.split(/\s+/);
      if (words.length === 2 && TITLE_CASE_LEADING_STOPWORDS.has(words[0]!)) continue;
      const list = undefinedHits.get(phrase) ?? [];
      list.push(posInParagraph(ctx, m.index, m.index + phrase.length));
      undefinedHits.set(phrase, list);
    }
  });
  const undefined_capitalized = [...undefinedHits.entries()]
    .filter(([, positions]) => positions.length >= 2)
    .map(([term, positions]) => ({ term, positions }))
    .sort((a, b) => a.term.localeCompare(b.term, "en"));

  const circular_terms = detectCircularDefinitions([...definitions.values()]);

  return {
    entries: [...definitions.values()].sort((a, b) => a.term.localeCompare(b.term, "en")),
    unused_terms,
    undefined_capitalized,
    ...(circular_terms.length > 0 ? { circular_terms } : {}),
  };
}

/**
 * Walk the definition graph (term A → term B when A's definition text
 * references defined term B) and return each cycle as an ordered list
 * of terms. Deterministic: terms are processed in sorted order and each
 * cycle is canonicalized to start at its alphabetically-first term.
 */
function detectCircularDefinitions(entries: DefinitionEntry[]): string[][] {
  const byTerm = new Map<string, DefinitionEntry>();
  for (const e of entries) byTerm.set(e.term, e);
  const terms = [...byTerm.keys()].sort();
  // Adjacency: A → B when B (a defined term other than A) appears in A's definition.
  const edges = new Map<string, string[]>();
  for (const a of terms) {
    const def = byTerm.get(a)!.definition;
    const targets = terms.filter(
      (b) => b !== a && new RegExp(`\\b${escapeRegExp(b)}\\b`).test(def),
    );
    edges.set(a, targets);
  }
  const cyclesByKey = new Map<string, string[]>();
  const visit = (start: string, node: string, path: string[], seen: Set<string>): void => {
    if (path.length > 8) return; // bound DFS on dense definition graphs
    for (const next of edges.get(node) ?? []) {
      if (next === start && path.length >= 2) {
        const cycle = [...path];
        const min = cycle.indexOf([...cycle].sort()[0]!);
        const rotated = [...cycle.slice(min), ...cycle.slice(0, min)];
        cyclesByKey.set(rotated.join(" "), rotated);
      } else if (!seen.has(next)) {
        seen.add(next);
        visit(start, next, [...path, next], seen);
        seen.delete(next);
      }
    }
  };
  for (const t of terms) visit(t, t, [t], new Set([t]));
  return [...cyclesByKey.values()].sort((a, b) => a.join().localeCompare(b.join(), "en"));
}

/** Trim a captured reference/scope label and strip trailing sentence punctuation. */
function cleanRef(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const v = raw.trim().replace(/[.,;:]+$/, "");
  return v || undefined;
}

/** The first clause of a string — up to the first sentence-ending `.`/`;`. */
function firstClause(text: string): string {
  const m = /[.;]/.exec(text);
  return m ? text.slice(0, m.index) : text;
}

function scanInlineDefinitions(text: string, base: DocPosition): DefinitionEntry[] {
  const out: DefinitionEntry[] = [];
  DEFINITION_INLINE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = DEFINITION_INLINE.exec(text)) !== null) {
    const term = m[1]!.trim();
    const after = text.slice(m.index + m[0].length).trim();
    if (!after) continue;
    // Only the term's own defining clause (up to the first sentence break) can
    // supply its by-reference target — otherwise an unrelated later sentence in
    // the same paragraph ("… Exhibit B for reference only.") is mis-attributed
    // as this term's reference.
    const reference = cleanRef(DEFINITION_REFERENCE.exec(firstClause(after))?.[1]);
    const scope = cleanRef(DEFINITION_SCOPE.exec(text.slice(0, m.index))?.[1]);
    out.push({
      term,
      definition: after,
      defined_at: {
        section_id: base.section_id,
        paragraph_id: base.paragraph_id,
        start: base.start + m.index,
        end: base.start + m.index + m[0].length,
      },
      used_at: [],
      ...(reference ? { reference } : {}),
      ...(scope ? { scope } : {}),
    });
  }
  DEFINITION_PARENTHETICAL.lastIndex = 0;
  while ((m = DEFINITION_PARENTHETICAL.exec(text)) !== null) {
    const term = m[1]!.trim();
    // The phrase the parenthetical names: the run of text before it, back to
    // the nearest clause break. That is what the drafter defined the term to
    // mean, and it keeps the entry's `definition` from swallowing the whole
    // paragraph.
    const before = text.slice(Math.max(0, m.index - 160), m.index);
    const definition =
      before
        .split(/[.;]\s/)
        .pop()
        ?.trim() ?? "";
    out.push({
      term,
      definition,
      defined_at: {
        section_id: base.section_id,
        paragraph_id: base.paragraph_id,
        start: base.start + m.index,
        end: base.start + m.index + m[0].length,
      },
      used_at: [],
      form: "parenthetical",
    });
  }
  return out;
}

function registerDefinition(map: Map<string, DefinitionEntry>, entry: DefinitionEntry): void {
  const key = entry.term.toLowerCase();
  const existing = map.get(key);
  if (existing && existing.definition) return; // first definition wins
  map.set(key, entry);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
