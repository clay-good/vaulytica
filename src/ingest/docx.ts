import type { DocumentTree, IngestResult, Paragraph, Run, Section } from "./types.js";
import { countWords, noTextWarning, normalize } from "./normalize.js";
import { sha256Hex } from "./hash.js";
import { assertDocumentBytes } from "./limits.js";
import { countRevisions, docxNotices } from "./docx-notices.js";
import { languageFields } from "./language.js";

/**
 * Ingest a DOCX file using mammoth.js. DOCX preserves real heading styles
 * (Heading 1..6 → h1..h6 in mammoth's default style map), so the resulting
 * tree has accurate heading levels — much better than the heuristic
 * extraction we have to do for PDFs.
 *
 * We use mammoth's `convertToHtml` rather than `extractRawText` so we keep
 * heading structure and basic formatting (bold/italic). We then parse the
 * HTML ourselves with a DOM parser (browser-native; the test environment
 * must provide one — happy-dom does).
 *
 * The implementation is split into:
 *
 * - {@link ingestDocx} — high-level entry point taking a `File` (browser).
 * - {@link ingestDocxBuffer} — variant taking an `ArrayBuffer` directly, so
 *   tests can drive it from Node without a `File` polyfill.
 * - {@link parseDocxHtml} — pure HTML → DocumentTree, exported for testing.
 */

type MammothLike = {
  convertToHtml: (input: { arrayBuffer: ArrayBuffer; buffer?: Uint8Array }) => Promise<{
    value: string;
    messages: Array<{ type: string; message: string }>;
  }>;
};

async function loadMammoth(): Promise<MammothLike> {
  // Dynamic import keeps the dependency out of the main bundle until we
  // actually need it, and lets tests stub the module.
  const mod = (await import("mammoth")) as unknown as { default?: MammothLike } & MammothLike;
  return (mod.default ?? mod) as MammothLike;
}

export async function ingestDocx(file: File): Promise<IngestResult> {
  const buf = await file.arrayBuffer();
  return ingestDocxBuffer(buf);
}

export async function ingestDocxBuffer(buf: ArrayBuffer): Promise<IngestResult> {
  assertDocumentBytes(buf.byteLength); // spec-v8 §7 — reject before parsing
  const warnings: string[] = [];
  const mammoth = await loadMammoth();
  // mammoth resolves to two builds: the browser build's `openZip` reads
  // `arrayBuffer`, but the Node build (lib/unzip.js, used by the headless
  // `vaulytica analyze` CLI) reads only `path`/`buffer`/`file` and rejects a
  // bare `arrayBuffer` with "Could not find file in options". Supply a Node
  // `Buffer` when the runtime has one (it shares memory with `buf`, no copy);
  // the browser build has no `Buffer` and reads `arrayBuffer` as before.
  const input: { arrayBuffer: ArrayBuffer; buffer?: Uint8Array } = { arrayBuffer: buf };
  if (typeof Buffer !== "undefined") input.buffer = Buffer.from(buf);
  const result = await mammoth.convertToHtml(input);
  // mammoth returns the ALL-CHANGES-ACCEPTED text of a redline, and emits
  // Word's hidden text as ordinary text, both silently. Say so.
  warnings.push(...docxNotices(countRevisions(buf)));
  for (const m of result.messages) {
    if (m.type === "warning" || m.type === "error") {
      warnings.push(`mammoth: ${m.message}`);
    }
  }

  const tree = parseDocxHtml(result.value);
  const normalized = normalize(tree);

  const language = languageFields(normalized, warnings);
  const word_count = countWords(normalized);
  warnings.push(...noTextWarning(word_count));

  return {
    tree: normalized,
    source: "docx",
    word_count,
    ...language,
    sha256: await sha256Hex(buf),
    warnings,
  };
}

/**
 * Parse the HTML produced by mammoth into a DocumentTree. Mammoth's default
 * output is a flat list of `<h1>..<h6>`, `<p>`, `<ul>`, `<ol>`, `<table>`,
 * and inline `<strong>` / `<em>` / `<u>`. We handle the common cases and
 * fall back to treating unknown elements as paragraphs.
 *
 * Pure function: same HTML in ⇒ same DocumentTree out.
 */
export function parseDocxHtml(html: string): DocumentTree {
  const doc = parseHtmlDocument(html);
  const root: Section = { id: "", heading: "", level: 1, paragraphs: [], children: [] };
  const sections: Section[] = [root];
  const stack: Section[] = [root];

  let promoted = false;

  const pushSection = (heading: string, level: number): void => {
    while (stack.length > 1 && stack[stack.length - 1]!.level >= level) {
      stack.pop();
    }
    // Once the first heading has REPLACED the synthetic root, the bottom of the
    // stack is a real section, and the loop above never pops it: every later
    // heading of the same level became its child. A DOCX that opens on a
    // Heading-1 title collapsed into one top-level section.
    if (promoted && stack.length === 1 && stack[0] !== root && stack[0]!.level >= level) {
      const section: Section = { id: "", heading, level, paragraphs: [], children: [] };
      sections.push(section);
      stack[0] = section;
      return;
    }
    const parent = stack[stack.length - 1]!;
    const section: Section = { id: "", heading, level, paragraphs: [], children: [] };
    if (!promoted && parent === root && parent.paragraphs.length === 0) {
      // First heading replaces the synthetic root.
      sections.length = 0;
      sections.push(section);
      stack.length = 0;
      stack.push(section);
      promoted = true;
    } else if (parent === root) {
      sections.push(section);
      stack.push(section);
    } else {
      parent.children.push(section);
      stack.push(section);
    }
  };

  const styledLevelByDepth = new Map<number, number>();

  /**
   * WORD'S AUTOMATIC NUMBERING. A clause numbered by a list style carries no
   * "1." in its text, and mammoth gives the list as `<ol>` — a NEW `<ol>`
   * after every paragraph that interrupts it. Numbered by position within
   * each `<ol>`, a contract whose clauses each have body text below them read
   * "1. Definitions", "1. Services", "1. Fees", "2. Term", and every
   * "Section 3" pointed at the wrong clause. Word continues a list across an
   * interruption unless told to restart, so the top-level count does too,
   * restarting only at an exhibit or schedule.
   *
   * A sub-clause is a list nested in its parent's item, and it was flattened
   * into the parent with neither a number nor a space: "1. Services.Provider
   * shall perform … Section 4.Provider shall meet …". Each nested item is its
   * own paragraph, numbered under its parent ("2.1", "2.2").
   */
  //
  // An interrupted SUB-clause list comes back from mammoth wrapped in an empty
  // bullet — `<ul><li><ol><li>…</li></ol></li></ul>` — so depth, not the tag
  // of the outer list, says which level a number belongs to, and the count at
  // each level carries across the document.
  let counters: number[] = [];
  const emitList = (list: Element, depth: number): void => {
    const ordered = list.tagName.toLowerCase() === "ol";
    for (const li of Array.from(list.children)) {
      if (li.tagName.toLowerCase() !== "li") continue;
      let prefix = "• ";
      if (ordered) {
        counters[depth] = (counters[depth] ?? 0) + 1;
        counters.length = depth + 1;
        for (let k = 0; k < depth; k++) counters[k] ??= 1;
        prefix = depth === 0 ? `${counters[0]}. ` : `${counters.join(".")} `;
      }
      const own = collectInlineRuns(li, "", true);
      if (
        own
          .map((r) => r.text)
          .join("")
          .trim()
      )
        appendParagraph(collectInlineRuns(li, prefix, true));
      for (const nested of Array.from(li.children)) {
        const t = nested.tagName.toLowerCase();
        if (t === "ol" || t === "ul") emitList(nested, depth + 1);
      }
    }
  };

  const appendParagraph = (runs: Run[]): void => {
    if (runs.length === 0) return;
    const paragraph: Paragraph = { id: "", runs };
    stack[stack.length - 1]!.paragraphs.push(paragraph);
  };

  const body = doc.body ?? doc;
  // Pre-scan, so the first numbered heading — often typed plain, before any
  // styled sibling — already knows its siblings' level.
  for (const node of Array.from(body.childNodes)) {
    if (node.nodeType !== 1) continue;
    const m = /^h([1-6])$/.exec((node as Element).tagName.toLowerCase());
    if (!m) continue;
    const depth = /^(\d+(?:\.\d+){0,3})\.?\s/
      .exec(((node as Element).textContent ?? "").trim())?.[1]
      ?.split(".").length;
    if (depth !== undefined && !styledLevelByDepth.has(depth)) {
      styledLevelByDepth.set(depth, Number(m[1]));
    }
  }
  for (const node of Array.from(body.childNodes)) {
    if (node.nodeType !== 1) continue; // skip text/comment at body level
    const el = node as Element;
    const tag = el.tagName.toLowerCase();
    const headingMatch = /^h([1-6])$/.exec(tag);
    if (headingMatch) {
      const text = (el.textContent ?? "").trim();
      const level = Number(headingMatch[1]);
      // Remember the level a STYLED numbered heading of each depth uses, so a
      // sibling typed as a plain paragraph ("7. Hours of Work; Timekeeping."
      // between Heading-1 "6." and "8.") is inferred at the same level rather
      // than nested under its neighbour.
      const depth = /^(\d+(?:\.\d+){0,3})\.?\s/.exec(text)?.[1]?.split(".").length;
      if (depth !== undefined) styledLevelByDepth.set(depth, level);
      if (/^(?:EXHIBIT|Exhibit|SCHEDULE|Schedule|APPENDIX|Appendix|ANNEX|Annex)\b/.test(text)) {
        counters = [];
      }
      pushSection(text, level);
      continue;
    }
    if (tag === "ul" || tag === "ol") {
      emitList(el, 0);
      continue;
    }
    if (tag === "table") {
      // Flatten each row to one paragraph; cells separated by " | ".
      for (const row of Array.from(el.querySelectorAll("tr"))) {
        const cells = Array.from(row.children).map((c) => (c.textContent ?? "").trim());
        const text = cells.join(" | ");
        if (text) appendParagraph([makeTextRun(text)]);
      }
      continue;
    }
    // Default: paragraph-like.
    const runs = collectInlineRuns(el, "");
    // Heuristic: a paragraph whose entire text starts with a numbered
    // prefix like `3.2 Title` (dotted-decimal, single dot or more,
    // followed by a Title-Cased phrase) and consists of just that
    // heading-shaped line is almost certainly a section heading that
    // the drafter typed by hand instead of applying a Heading style.
    // Mammoth emits those as `<p>` not `<hN>`, so the cross-ref
    // resolver and signature-block scanner never see the structure.
    // Promote them based on dot depth: `3` → level 2, `3.2` → level 3,
    // `3.2.1` → level 4, with `Article N` and `ARTICLE N` mapped to
    // level 1.
    const paragraphText = runs
      .map((r) => r.text)
      .join("")
      .trim();
    const numbered = detectNumberedHeading(paragraphText);
    if (numbered) {
      const depth = /^(\d+(?:\.\d+){0,3})\.?\s/.exec(paragraphText)?.[1]?.split(".").length;
      pushSection(
        paragraphText,
        (depth !== undefined && styledLevelByDepth.get(depth)) || numbered.level,
      );
      continue;
    }
    appendParagraph(runs);
  }

  // Drop the synthetic root ONLY when it is genuinely empty (the paste-path
  // guard, fix-ingest-preamble-integrity). The old `!promoted` condition
  // fired precisely when the root held real content — the contract preamble
  // (title, parties, recitals, effective date) typed before the first
  // heading — and silently deleted it from every scan.
  if (sections.length > 1 && sections[0] === root && root.paragraphs.length === 0) {
    sections.shift();
  }
  return { type: "document", sections };
}

function collectInlineRuns(el: Element, prefix: string, skipLists = false): Run[] {
  const runs: Run[] = [];
  if (prefix) runs.push(makeTextRun(prefix));
  const walk = (node: Node, bold: boolean, italic: boolean, underline: boolean): void => {
    if (node.nodeType === 3) {
      const text = (node as Text).data;
      if (!text) return;
      runs.push({
        id: "",
        text,
        start: 0,
        end: 0,
        formatting: bold || italic || underline ? { bold, italic, underline } : undefined,
      });
      return;
    }
    if (node.nodeType !== 1) return;
    const child = node as Element;
    const tag = child.tagName.toLowerCase();
    // A nested list is emitted as paragraphs of its own (see emitList).
    if (skipLists && (tag === "ol" || tag === "ul")) return;
    const nextBold = bold || tag === "strong" || tag === "b";
    const nextItalic = italic || tag === "em" || tag === "i";
    const nextUnderline = underline || tag === "u";
    for (const c of Array.from(child.childNodes)) walk(c, nextBold, nextItalic, nextUnderline);
  };
  for (const c of Array.from(el.childNodes)) walk(c, false, false, false);
  return runs;
}

function makeTextRun(text: string): Run {
  return { id: "", text, start: 0, end: 0 };
}

/**
 * Parse an HTML fragment into a Document. Uses `DOMParser` if available
 * (browsers, happy-dom, jsdom) — otherwise throws a typed error directing
 * the caller to configure a DOM environment.
 */
/**
 * Detect numbered-heading-shaped paragraphs (`3.2 Invoicing and
 * Payment`, `ARTICLE III. Services`, `Section 14.2 — Jurisdiction`).
 * Returns the inferred section level when the paragraph looks like a
 * heading, or `null` to leave it as ordinary body text.
 *
 * Heuristic constraints (kept conservative to avoid false promotions):
 *   - Length ≤ 120 characters (real headings are short)
 *   - No sentence-ending period followed by lower-case text
 *   - The numeric prefix is followed by at least one Title-Case
 *     word, OR is wrapped in ALL CAPS (`ARTICLE III. SERVICES`)
 */
const ADDRESS_LINE =
  /\b\d{5}(?:-\d{4})?\b|\b(?:Street|St\.|Avenue|Ave\.|Road|Rd\.|Drive|Dr\.|Boulevard|Blvd\.?|Suite|Ste\.|Floor|Parkway|Pkwy|Lane|Ln\.|Highway|Hwy|P\.?\s?O\.?\s+Box)\b/i;

/**
 * A street name that ENDS an address line: "88 Foundry Row", "88 Elm Court".
 * Kept to the line's end and to an undotted number, because "Close", "Way"
 * and "Place" open real headings ("4. Close of Escrow").
 */
const STREET_TAIL =
  /^\d+\s+[A-Z][\w'’ -]{0,60}\b(?:Row|Court|Ct\.?|Place|Pl\.?|Way|Square|Circle|Terrace|Plaza|Trail|Alley|Crescent|Mews|Wharf|Quay)\s*$/;

export function detectNumberedHeading(text: string): { level: number } | null {
  if (!text || text.length > 120) return null;
  if (/\.\s+[a-z]/.test(text)) return null; // sentence-shaped
  // A run-in clause is a heading AND its sentence: "Section 3.1. General
  // Powers. The affairs of the corporation are managed by its Board of
  // Directors." The sentence opens on a capital, so the test above passed it,
  // and six bylaw sections became headings that swallowed their own text —
  // the outline then reported Article III's sections 2 and 4–8 missing.
  const afterNumber = text.replace(
    /^\s*(?:(?:article|section|clause)\s+)?(?:\d+(?:\.\d+)*|[IVXLCDM]+)\.?\s*/i,
    "",
  );
  if (/[.;:]\s+[A-Z][a-z'’]*\s+[a-z]/.test(afterNumber)) return null;
  // Dotted-decimal: 1, 1.2, 1.2.3, optional trailing dot or em-dash.
  // Commas belong in a heading: "1. INVENTORY, PLACEMENTS, AND IMPRESSIONS".
  // Without them every comma-bearing numbered heading stayed body text, and
  // the outline reported sections 1, 2 and 5 of an insertion order missing.
  const dotted = /^(\d+(?:\.\d+){0,3})\.?\s+[—–-]?\s*[A-Z][A-Za-z0-9'’&/ (),-]{1,100}$/.exec(text);
  // An ADDRESS line is number-and-capitalized-words too: "1400 Preston Road,
  // Suite 620", "440 North Wells Street" were promoted to sections 1400 and
  // 440, and the outline reported 1,399 sections missing. Below 100 the
  // street name decides: "88 Foundry Row" became section 88 of an engagement
  // letter, which "skipped 1..87".
  if (
    dotted &&
    (ADDRESS_LINE.test(text) ||
      STREET_TAIL.test(text) ||
      (!/^\d+\./.test(text) && Number(dotted[1]) >= 100))
  ) {
    return null;
  }
  if (dotted) {
    const dots = (dotted[1]!.match(/\./g) ?? []).length;
    return { level: Math.min(2 + dots, 6) };
  }
  // Article / Section / § N
  const articleRoman = /^(?:ARTICLE|Article)\s+([IVXLCDM]+|\d+)\b/.exec(text);
  if (articleRoman) return { level: 1 };
  const sectionPrefix = /^(?:Section|SECTION|§)\s+(\d+(?:\.\d+){0,3})\b/.exec(text);
  if (sectionPrefix) {
    const dots = (sectionPrefix[1]!.match(/\./g) ?? []).length;
    return { level: Math.min(2 + dots, 6) };
  }
  return null;
}

function parseHtmlDocument(html: string): Document {
  if (typeof DOMParser === "undefined") {
    throw new Error(
      "ingest/docx: DOMParser is not available. In the browser this is built-in; in tests, set the Vitest environment to 'happy-dom' or 'jsdom'.",
    );
  }
  return new DOMParser().parseFromString(
    `<!doctype html><html><body>${html}</body></html>`,
    "text/html",
  );
}
