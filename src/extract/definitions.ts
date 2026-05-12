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

const DEFINITION_INLINE = /["“”']([A-Z][\w\s\-&]{1,80}?)["“”']\s+(?:shall\s+)?means?\b/g;
const DEFINITION_BARE = /^\s*([A-Z][\w\s\-&]{1,80}?)\s+(?:shall\s+)?means?\b/;

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
        const def = text.slice(bare.index + bare[0].length).trim().replace(/^[-:]+\s*/, "");
        const start = p.runs[0]?.start ?? 0;
        registerDefinition(definitions, {
          term,
          definition: def,
          defined_at: { section_id: section.id, paragraph_id: p.id, start, end: start + text.length },
          used_at: [],
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
      // Skip the paragraph where the definition lives.
      if (ctx.paragraph.id === entry.defined_at.paragraph_id) return;
      needle.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = needle.exec(ctx.text)) !== null) {
        entry.used_at.push(posInParagraph(ctx, m.index, m.index + m[0].length));
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
      const list = undefinedHits.get(phrase) ?? [];
      list.push(posInParagraph(ctx, m.index, m.index + phrase.length));
      undefinedHits.set(phrase, list);
    }
  });
  const undefined_capitalized = [...undefinedHits.entries()]
    .filter(([, positions]) => positions.length >= 2)
    .map(([term, positions]) => ({ term, positions }))
    .sort((a, b) => a.term.localeCompare(b.term));

  return {
    entries: [...definitions.values()].sort((a, b) => a.term.localeCompare(b.term)),
    unused_terms,
    undefined_capitalized,
  };
}

function scanInlineDefinitions(text: string, base: DocPosition): DefinitionEntry[] {
  const out: DefinitionEntry[] = [];
  DEFINITION_INLINE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = DEFINITION_INLINE.exec(text)) !== null) {
    const term = m[1]!.trim();
    const after = text.slice(m.index + m[0].length).trim();
    if (!after) continue;
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
