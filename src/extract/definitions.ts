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
 * The double-alias definition: `"Protected Health Information" or "PHI"
 * means …`. DEFINITION_INLINE requires `means` right after the closing
 * quote, so only the SECOND term registered and the first — the term the
 * document then uses everywhere — was reported by STRUCT-006 as never
 * defined. Both names name the same definition.
 */
const DEFINITION_ALIASED =
  /["“”']([A-Z][\w\s\-&]{1,80}?)["“”']\s+or\s+["“”']([A-Z][\w\s\-&/'’.]{1,60}?)["“”']\s+(?:shall\s+)?means?\b/gi;

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
  /\((?:\s*(?:the|this|these|each|an?|collectively|together|individually|hereinafter|referred\s+to\s+as)[,]?\s+)*["\u201C]([A-Z][\w\s\-&/'\u2019.]{1,60}?)["\u201D]\s*\)/g;

/**
 * Meaning-by-reference: a term (or a list of terms) is defined by pointing at
 * another instrument's definition rather than stating one — the dominant
 * convention in DPAs and BAAs importing a statute's vocabulary:
 *
 *   `Personal Data, Data Subject, Processing, Controller and Processor shall
 *    have the meaning given in Article 4 GDPR.`
 *   `"Business Associate" shall have the meaning given to such term in
 *    45 CFR § 160.103.`
 *
 * Recognizing only `means …` left every such term unregistered: STRUCT-004
 * reported "no defined terms", STRUCT-006 flagged the terms as
 * used-but-undefined, and the capitalization rules never saw them at all.
 * The match anchors on the verb tail; the term list is parsed back from the
 * start of the sentence, so a fallback clause ("Capitalized terms not
 * otherwise defined herein shall have the meaning given in the MSA")
 * contributes nothing — its subject is not a Title-Case term list.
 * The tail tolerates periods inside numeric citations (`45 CFR § 160.103`).
 */
const DEFINITION_MEANING_TAIL =
  /\b(?:shall\s+|will\s+)?(?:each\s+)?ha(?:ve|s)\s+the\s+(?:respective\s+)?meanings?\s+(?:given|set\s+forth|set\s+out|ascribed|assigned|specified|defined|stated)\b(?:[^.;]|\.(?=\d))*/g;

/**
 * The derivative-form convention: `"Processing" means …, and "Process" and
 * "Processed" shall be construed accordingly.` The construed terms carry a
 * sibling definition's meaning — they are defined terms, not undefined
 * capitalized phrases.
 */
const DEFINITION_CONSTRUED_TAIL =
  /\b(?:shall|will|must|is\s+to|are\s+to)\s+(?:each\s+)?be\s+construed\s+accordingly\b/g;

/** A quoted Title-Case phrase inside a term list. */
const QUOTED_TERM = /["“]([A-Z][\w\s\-&/'’.]{0,60}?)["”]/g;

/**
 * A cover-block field label: `Issue Date: May 15, 2026` / `Principal
 * Amount: $500,000`. Term sheets, notes, and order forms constitute their
 * terms this way, and the body then uses them ("from the Issue Date") —
 * STRUCT-006 called every such term used-but-undefined. Ingest joins
 * adjacent cover lines into one paragraph, so a qualifying paragraph
 * (short, opening with a label) may carry several label:value pairs; each
 * value runs to the next label. Two-to-five Title-Case words per label, so
 * a signature block's "By:"/"Date:" or a notice's "Attn:" never registers.
 */
const FIELD_LABEL = /\b([A-Z][A-Za-z]*(?:\s+[A-Z][A-Za-z]*){1,4}):\s+/g;
const FIELD_BLOCK_MAX_LENGTH = 240;

/** A definition that points at an exhibit/schedule/section rather than stating its own text. */
const DEFINITION_REFERENCE =
  /\b(?:attached\s+(?:hereto\s+)?as|set\s+forth\s+in|described\s+in|defined\s+in|as\s+set\s+out\s+in|in)\s+((?:Exhibit|Schedule|Appendix|Annex|Attachment|Section|Article)\s+[A-Z0-9][\w.()-]*)/i;

/** A scope-gating prefix that confines a definition to a section/clause. */
const DEFINITION_SCOPE =
  /\b(?:for\s+(?:the\s+)?purposes\s+of|as\s+used\s+in|solely\s+for\s+purposes\s+of)\s+(?:this\s+)?((?:Section|Article|Clause|Paragraph)\s+[\w.()-]+)[,:\s]*$/i;

const DEFINITIONS_HEADING = /\b(definitions?|defined\s+terms|glossary)\b/i;
const TITLE_CASE_PHRASE = /\b((?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4}))\b/g;

/**
 * Place names are proper nouns, never contractual defined terms. A
 * governing-law or address clause naming "New York" or "New Jersey" was
 * reported by STRUCT-006 as a Title-Case term "used but not defined" — a place
 * is not a term a contract defines. The two-word US states (New York, New
 * Jersey, New Mexico, New Hampshire, North/South Carolina/Dakota, West
 * Virginia, Rhode Island, District of Columbia) are the ones TITLE_CASE_PHRASE
 * captures as multi-word candidates; the single-word states never reach the
 * multi-word phrase list.
 */
const PLACE_NAMES = new Set([
  "New York",
  "New Jersey",
  "New Mexico",
  "New Hampshire",
  "North Carolina",
  "South Carolina",
  "North Dakota",
  "South Dakota",
  "West Virginia",
  "Rhode Island",
  "District of Columbia",
  "United States",
  "United Kingdom",
  "New York County",
  "New Castle County",
  "Los Angeles",
  "San Francisco",
  "Santa Clara",
  "Hong Kong",
  "England and Wales",
]);
const COMMON_WORDS = new Set([
  "Effective Date",
  "Agreement",
  "Section",
  "Article",
  "Exhibit",
  "Schedule",
  "Attachment",
  // Organizational units referenced by name ("report it to Human
  // Resources") — proper nouns, never document-defined terms.
  "Human Resources",
  "Legal Department",
  "Information Technology",
]);

/**
 * Proper-noun statute titles are the law's name, not a term the document
 * defines — bylaws cite "the General Corporation Law of the State of
 * Delaware" the way a contract cites "New York", and STRUCT-006 reported
 * the statute as "used but not defined". Same reasoning as PLACE_NAMES.
 */
const STATUTE_NAMES = new Set([
  "General Corporation Law",
  "Securities Act",
  "Securities Exchange Act",
  "Internal Revenue Code",
  "Uniform Commercial Code",
  "Code of Civil Procedure",
  "Fair Labor Standards Act",
  "National Labor Relations Act",
]);

/**
 * Corporate-office titles are designations, not defined terms: bylaws that
 * empower "the Chief Executive Officer" to call a special meeting have not
 * left a defined term undefined — the office is constituted by the officers
 * article, and every governance document capitalizes titles this way. Any
 * phrase ENDING in "Officer" is an office ("Compliance Officer", "Privacy
 * Officer", "Data Protection Officer") — offices are constituted by
 * appointment, not by a definitions section.
 */
const OFFICER_TITLES =
  /^(?:[A-Z][\w\s]*\sOfficer|Vice\s+President|Executive\s+Vice\s+President|General\s+Counsel|Chair(?:person|man|woman)(?:\s+of\s+the\s+Board)?|Board\s+of\s+Directors|Managing\s+Member|Managing\s+Director)$/;

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
    if (ctx.text.trim().length <= FIELD_BLOCK_MAX_LENGTH) {
      FIELD_LABEL.lastIndex = 0;
      const labels: { term: string; start: number; valueStart: number }[] = [];
      let f: RegExpExecArray | null;
      while ((f = FIELD_LABEL.exec(ctx.text)) !== null) {
        labels.push({ term: f[1]!.trim(), start: f.index, valueStart: f.index + f[0].length });
      }
      // Only a paragraph that OPENS with a label is a cover block — a
      // sentence that happens to contain "Wire Instructions: …" mid-flow
      // is prose, not a field sheet.
      if (labels.length > 0 && /^\s*$/.test(ctx.text.slice(0, labels[0]!.start))) {
        for (let i = 0; i < labels.length; i++) {
          const value = ctx.text
            .slice(labels[i]!.valueStart, labels[i + 1]?.start ?? ctx.text.length)
            .trim();
          if (!value) continue;
          registerDefinition(definitions, {
            term: labels[i]!.term,
            definition: value,
            defined_at: {
              section_id: ctx.section.id,
              paragraph_id: ctx.paragraph.id,
              start: ctx.start,
              end: ctx.end,
            },
            used_at: [],
            form: "field-label",
          });
        }
      }
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
      const inDefiningParagraph =
        entry.form !== "parenthetical" && ctx.paragraph.id === entry.defined_at.paragraph_id;
      needle.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = needle.exec(ctx.text)) !== null) {
        const pos = posInParagraph(ctx, m.index, m.index + m[0].length);
        if (pos.start >= entry.defined_at.start && pos.end <= entry.defined_at.end) continue;
        // Inside the defining paragraph, only text BEFORE the definition
        // marker is operative use — an embedded definition ('… consummates a
        // Change of Control … "Change of Control" means a merger …') is used
        // by the clause that precedes it, while a repetition AFTER the marker
        // is the definition body talking about itself ("… but Confidential
        // Information does not include …").
        if (inDefiningParagraph && pos.end > entry.defined_at.start) continue;
        entry.used_at.push(pos);
      }
    });
  }

  // A field-label term is a fact-sheet entry — "Effective Date: January 1,
  // 2026" states its fact whether or not the body ever repeats the label, so
  // its non-reuse is not the template-leftover signal unused_terms exists to
  // report.
  const unused_terms = [...definitions.values()]
    .filter((e) => e.used_at.length === 0 && e.form !== "field-label")
    .map((e) => e.term)
    .sort();

  // Pass 4: undefined Title-Case phrases.
  const definedNames = new Set([...definitions.keys()]);
  const undefinedHits = new Map<string, DocPosition[]>();
  const caption = captionText(tree);
  // Names of natural persons who sign or appear before a notary — collected
  // from conformed-signature lines ("/s/ Nora Castellanos") and notarial
  // recitals ("personally appeared Nora Castellanos") — are people, not
  // defined terms, wherever else they appear.
  const personNames = new Set<string>();
  forEachParagraph(tree, (ctx) => {
    for (const re of [
      /\/s\/\s+([A-Z][\w'’-]+(?:\s+[A-Z][\w'’-]+){0,3})/g,
      /\b(?:personally\s+appeared|I,)\s+([A-Z][\w'’-]+(?:\s+[A-Z][\w'’-]+){0,3})/g,
    ]) {
      re.lastIndex = 0;
      let pm: RegExpExecArray | null;
      while ((pm = re.exec(ctx.text)) !== null) personNames.add(pm[1]!.toLowerCase());
    }
  });
  forEachParagraph(tree, (ctx) => {
    // A run-in heading ("4. Mutual Release by Meridian. Upon receipt …")
    // capitalizes its words as heading STYLE, not defined-term usage;
    // occurrences inside the heading segment are not uses of a term.
    const headingEnd = runInHeadingEnd(ctx.text);
    TITLE_CASE_PHRASE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = TITLE_CASE_PHRASE.exec(ctx.text)) !== null) {
      const phrase = m[1]!;
      if (m.index < headingEnd) continue;
      // The document's caption is its NAME; a phrase inside the caption line
      // or inside an echo of it ("This Confidential Settlement Agreement and
      // Mutual Release (this 'Agreement') …") is title vocabulary.
      if (caption && insideOccurrenceOf(ctx.text, caption, m.index, phrase.length)) continue;
      // A phrase soon followed by a defining parenthetical is the SUBJECT
      // that parenthetical names — "This Employee Handbook (this
      // 'Handbook') …" defined the whole phrase as "Handbook"; its words are
      // not a separate undefined term.
      if (
        /^[^().;]{0,40}\(\s*(?:the|this|each|an?|collectively|together|individually|hereinafter|referred\s+to\s+as)?[,]?\s*["“]/.test(
          ctx.text.slice(m.index + phrase.length, m.index + phrase.length + 60),
        )
      ) {
        continue;
      }
      // A candidate whose first word is immediately preceded by a hyphen is the
      // tail of a hyphenated compound, not a standalone term: "Software-as-a-
      // Service Terms of Service" yielded the phantom term "Service Terms".
      if (ctx.text[m.index - 1] === "-") continue;
      const phraseLower = phrase.toLowerCase();
      if (definedNames.has(phraseLower)) continue;
      // TITLE_CASE_PHRASE cannot cross an all-caps word, so a candidate is
      // often a truncation of a longer defined term — "Contractor Background"
      // cut from the defined "Contractor Background IP". A word-boundary
      // prefix of a defined term is that term's use, not a new undefined one.
      let prefixOfDefined = false;
      for (const name of definedNames) {
        if (name.startsWith(`${phraseLower} `)) {
          prefixOfDefined = true;
          break;
        }
      }
      if (prefixOfDefined) continue;
      // A phrase composed entirely of defined terms is a compound USE of
      // those terms, not a new undefined one: "Process Personal Data" where
      // "Process" and "Personal Data" are both defined (GDPR vocabulary
      // imported by reference) is the two defined terms in sequence.
      if (isCompoundOfDefined(phraseLower, definedNames)) continue;
      if (COMMON_WORDS.has(phrase)) continue;
      if (PLACE_NAMES.has(phrase)) continue;
      if (STATUTE_NAMES.has(phrase)) continue;
      // A Title-Case phrase ending in "Act" or "Code" is a statute's title
      // ("Bank Secrecy Act", "USA PATRIOT Act", "Utah Code") — the law's
      // name, not a term the document defines. Same reasoning as
      // STATUTE_NAMES, generalized on the unambiguous suffix.
      if (/\s(?:Act|Code)$/.test(phrase)) continue;
      if (OFFICER_TITLES.test(phrase)) continue;
      // A phrase immediately followed by a corporate suffix (", Inc.",
      // " LLC") is an entity NAME, not a defined term — same reasoning as
      // the street-address guard, keyed on the unambiguous suffix.
      if (
        /^,?\s*(?:Inc|LLC|L\.L\.C|Ltd|Corp|Co|N\.A|P\.C|GmbH|S\.A)\b/.test(
          ctx.text.slice(m.index + phrase.length, m.index + phrase.length + 12),
        )
      )
        continue;
      // A street address ("88 Dockside Avenue") is a proper noun, never a
      // contractual defined term — same reasoning as PLACE_NAMES, keyed on
      // the unambiguous street-suffix last word. Likewise a named county or
      // parish ("Pierce County") in a legal description or venue recital.
      if (
        /\s(?:Avenue|Street|Road|Boulevard|Drive|Lane|Parkway|Highway|County|Parish|Borough)$/.test(
          phrase,
        )
      )
        continue;
      // An ordinal instrument name ("First Amendment", "Second Addendum") is
      // the TITLE of a companion document, not a term this one defines.
      if (
        /^(?:First|Second|Third|Fourth|Fifth|Sixth|Seventh|Eighth|Ninth|Tenth)\s+(?:Amendment|Addendum|Modification|Restatement|Supplement)$/.test(
          phrase,
        )
      )
        continue;
      // A numbered-instrument fragment: "Change Order No. 3" captures as
      // "Change Order No" (the abbreviation's word survives, its period and
      // number don't). The fragment is part of a document NUMBER, not a term.
      if (/\sNo$/.test(phrase) && /^\.\s*\d/.test(ctx.text.slice(m.index + phrase.length)))
        continue;
      if (personNames.has(phraseLower)) continue;
      // A phrase introduced with a residence or origin ("Diego Castellanos,
      // residing at 9 Elm Row", "Lucia Ferrante, of Burlington") is a natural
      // person, not a defined term.
      if (
        /^,\s+(?:residing|of\s+[A-Z]|whose\s+address)/.test(
          ctx.text.slice(m.index + phrase.length, m.index + phrase.length + 24),
        )
      )
        continue;
      if (TITLE_CASE_LEADING_STOPWORDS.has(phrase)) continue;
      // Only strip sentence-initial-stopword patterns from the candidate
      // list when the phrase is short (2 words). Longer phrases like
      // "The Special Reserve Fund" or "The Annual Operating Plan" are
      // ordinary capitalized noun phrases worth flagging when undefined.
      const words = phrase.split(/\s+/);
      if (words.length === 2 && TITLE_CASE_LEADING_STOPWORDS.has(words[0]!)) continue;
      // A sentence-initial article fused onto a DEFINED term is that term's
      // use: "The Escrow Agent shall release …" is the defined "Escrow
      // Agent", not an undefined "The Escrow Agent". A stopword-led phrase
      // whose remainder is NOT defined ("The Special Reserve Fund") still
      // flags.
      if (
        TITLE_CASE_LEADING_STOPWORDS.has(words[0]!) &&
        definedNames.has(words.slice(1).join(" ").toLowerCase())
      ) {
        continue;
      }
      // Normalize a sentence-initial article off the candidate: "The
      // Contract Sum will be increased …" and "increased the Contract Sum"
      // are occurrences of ONE term, and reporting "Contract Sum" and "The
      // Contract Sum" side by side is the same term twice.
      let canonical = phrase;
      let start = m.index;
      if (TITLE_CASE_LEADING_STOPWORDS.has(words[0]!) && words.length > 2) {
        canonical = words.slice(1).join(" ");
        start = m.index + phrase.length - canonical.length;
      }
      const list = undefinedHits.get(canonical) ?? [];
      list.push(posInParagraph(ctx, start, start + canonical.length));
      undefinedHits.set(canonical, list);
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
  DEFINITION_ALIASED.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = DEFINITION_ALIASED.exec(text)) !== null) {
    const definition = text.slice(m.index + m[0].length).trim();
    if (!definition) continue;
    for (const term of [m[1]!.trim(), m[2]!.trim()]) {
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
      });
    }
  }
  DEFINITION_INLINE.lastIndex = 0;
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
  for (const conv of [
    { tail: DEFINITION_MEANING_TAIL, form: "meaning-reference" as const },
    { tail: DEFINITION_CONSTRUED_TAIL, form: "construed" as const },
  ]) {
    conv.tail.lastIndex = 0;
    while ((m = conv.tail.exec(text)) !== null) {
      const listStart = sentenceStartBefore(text, m.index);
      const terms = parseTermList(text.slice(listStart, m.index));
      if (terms.length === 0) continue;
      const definition = m[0].trim();
      const reference = cleanRef(DEFINITION_REFERENCE.exec(definition)?.[1]);
      for (const term of terms) {
        out.push({
          term,
          definition,
          defined_at: {
            section_id: base.section_id,
            paragraph_id: base.paragraph_id,
            start: base.start + listStart,
            end: base.start + m.index + m[0].length,
          },
          used_at: [],
          ...(reference ? { reference } : {}),
          form: conv.form,
        });
      }
    }
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

/**
 * The offset just after the last sentence boundary (`.`, `;`, `:`) before
 * `index`. A period followed by a digit is a numeric citation
 * (`45 CFR § 160.103`), not a boundary.
 */
function sentenceStartBefore(text: string, index: number): number {
  for (let i = index - 1; i >= 0; i--) {
    const ch = text[i]!;
    if ((ch === "." || ch === ";" || ch === ":") && !/\d/.test(text[i + 1] ?? "")) return i + 1;
  }
  return 0;
}

/**
 * Parse the subject of a meaning-tail sentence into defined-term candidates.
 * Quoted phrases win when present (they survive interior "and"s); otherwise
 * the bare list is split on commas and "and". A subject that is ordinary
 * prose ("Capitalized terms used but not defined herein") yields nothing.
 */
function parseTermList(listText: string): string[] {
  const out: string[] = [];
  QUOTED_TERM.lastIndex = 0;
  let sawQuote = false;
  let q: RegExpExecArray | null;
  while ((q = QUOTED_TERM.exec(listText)) !== null) {
    sawQuote = true;
    const term = q[1]!.trim();
    if (isPlausibleTerm(term)) out.push(term);
  }
  if (sawQuote) return out;
  for (const raw of listText.split(/,|\band\b/)) {
    const term = raw
      .trim()
      .replace(/^(?:the\s+)?(?:terms?\s+)?/i, "")
      .trim();
    if (isPlausibleTerm(term)) out.push(term);
  }
  return out;
}

/**
 * A term-list candidate must read as a defined term: every word capitalized
 * (up to two camelCase lead letters — "ePHI") or a lowercase connector, no
 * more than six words, and a lone word must not be a sentence-flow stopword
 * or boilerplate noun ("It", "Agreement").
 */
function isPlausibleTerm(term: string): boolean {
  if (term.length < 2 || term.length > 60) return false;
  const words = term.split(/\s+/);
  if (words.length > 6) return false;
  for (const w of words) {
    if (/^[a-z]{0,2}[A-Z][\w\-&/'’.]*$/.test(w)) continue;
    if (/^(?:of|and|or|for|to|in|the|a|an)$/.test(w)) continue;
    return false;
  }
  if (words.length === 1 && (TITLE_CASE_LEADING_STOPWORDS.has(term) || COMMON_WORDS.has(term))) {
    return false;
  }
  if (words.length === 2 && TITLE_CASE_LEADING_STOPWORDS.has(words[0]!)) return false;
  return /^[a-z]{0,2}[A-Z]/.test(term);
}

/** Lowercase words a Title-Case heading or caption legitimately leaves lowercase. */
const HEADING_CONNECTORS = /^(?:of|and|or|by|to|in|for|the|a|an|with|under|on|at|from)$/;

/** Every word capitalized (or a heading connector) — heading/caption style. */
function isTitleCaseSegment(segment: string): boolean {
  const words = segment.trim().split(/\s+/);
  if (words.length === 0) return false;
  for (const w of words) {
    if (/^[A-Z0-9(&]/.test(w)) continue;
    if (HEADING_CONNECTORS.test(w)) continue;
    // Title punctuation: "Employee Handbook — Halcyon Grid Systems, Inc."
    if (/^[—–-]$/.test(w)) continue;
    return false;
  }
  return true;
}

/**
 * The document's caption line — the first paragraph, when it reads as a
 * title (Title-Case throughout, short, no terminal sentence punctuation)
 * rather than as prose. Plain-text ingest keeps the caption as an ordinary
 * paragraph, so without this Pass 4 read the document's own name as a
 * defined-term candidate ("Mutual Release" from "Confidential Settlement
 * Agreement and Mutual Release").
 */
function captionText(tree: DocumentTree): string | undefined {
  const first = tree.sections[0]?.paragraphs[0];
  if (!first) return undefined;
  const text = first.runs
    .map((r) => r.text)
    .join("")
    .trim();
  if (text.length < 8 || text.length > 90) return undefined;
  // A trailing period only disqualifies a caption when it is sentence
  // punctuation — "Amended and Restated Bylaws of Beacon Instruments, Inc."
  // ends with the entity suffix's abbreviation point, and rejecting it left
  // every phrase in the caption a defined-term candidate.
  if (/[.;:!?]$/.test(text) && !/\b(?:Inc|LLC|L\.L\.C|Ltd|Corp|Co|N\.A|P\.C|S\.A)\.$/.test(text)) {
    return undefined;
  }
  if (text.split(/\s+/).length < 2) return undefined;
  return isTitleCaseSegment(text) ? text : undefined;
}

/**
 * The end offset of a run-in heading segment — a numbered or lettered list
 * marker followed by a short Title-Case phrase and a sentence break
 * ("4. Mutual Release by Meridian. Upon receipt …"). Returns 0 when the
 * paragraph does not open with one (a numbered SENTENCE — "4. Client shall
 * pay Vendor." — fails the Title-Case check and is not a heading).
 */
function runInHeadingEnd(text: string): number {
  const m = /^\s*(?:\d+(?:\.\d+)*|[A-Z])[.)]\s+([A-Z][^.;:]{0,80}?)[.;:]\s/.exec(text);
  if (!m) return 0;
  return isTitleCaseSegment(m[1]!) ? m[0].length : 0;
}

/** True when [index, index+length) lies inside an occurrence of `container` in `text`. */
function insideOccurrenceOf(
  text: string,
  container: string,
  index: number,
  length: number,
): boolean {
  let at = text.indexOf(container);
  while (at !== -1) {
    if (index >= at && index + length <= at + container.length) return true;
    at = text.indexOf(container, at + 1);
  }
  return false;
}

/**
 * True when the phrase's words segment fully into defined term names.
 * A segment matches its defined term through a trailing plural — "Your
 * Contributions" is the defined "Your" + "Contribution", and demanding the
 * exact singular reported the compound as a new undefined term.
 */
function isCompoundOfDefined(phraseLower: string, definedNames: Set<string>): boolean {
  const words = phraseLower.split(/\s+/);
  const matches = (seg: string): boolean =>
    definedNames.has(seg) ||
    (seg.endsWith("es") && definedNames.has(seg.slice(0, -2))) ||
    (seg.endsWith("s") && definedNames.has(seg.slice(0, -1)));
  const reachable: boolean[] = new Array(words.length + 1).fill(false);
  reachable[0] = true;
  for (let i = 1; i <= words.length; i++) {
    for (let j = 0; j < i; j++) {
      if (reachable[j] && matches(words.slice(j, i).join(" "))) {
        reachable[i] = true;
        break;
      }
    }
  }
  return reachable[words.length]!;
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
