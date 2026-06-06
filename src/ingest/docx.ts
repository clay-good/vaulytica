import type { DocumentTree, IngestResult, Paragraph, Run, Section } from "./types.js";
import { countWords, normalize } from "./normalize.js";
import { sha256Hex } from "./hash.js";
import { assertDocumentBytes } from "./limits.js";

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
  convertToHtml: (input: { arrayBuffer: ArrayBuffer }) => Promise<{
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
  const result = await mammoth.convertToHtml({ arrayBuffer: buf });
  for (const m of result.messages) {
    if (m.type === "warning" || m.type === "error") {
      warnings.push(`mammoth: ${m.message}`);
    }
  }

  const tree = parseDocxHtml(result.value);
  const normalized = normalize(tree);

  return {
    tree: normalized,
    source: "docx",
    word_count: countWords(normalized),
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

  const appendParagraph = (runs: Run[]): void => {
    if (runs.length === 0) return;
    const paragraph: Paragraph = { id: "", runs };
    stack[stack.length - 1]!.paragraphs.push(paragraph);
  };

  const body = doc.body ?? doc;
  for (const node of Array.from(body.childNodes)) {
    if (node.nodeType !== 1) continue; // skip text/comment at body level
    const el = node as Element;
    const tag = el.tagName.toLowerCase();
    const headingMatch = /^h([1-6])$/.exec(tag);
    if (headingMatch) {
      pushSection((el.textContent ?? "").trim(), Number(headingMatch[1]));
      continue;
    }
    if (tag === "ul" || tag === "ol") {
      for (const li of Array.from(el.children)) {
        const prefix = tag === "ul" ? "• " : `${Array.from(el.children).indexOf(li) + 1}. `;
        const runs = collectInlineRuns(li, prefix);
        appendParagraph(runs);
      }
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
    const paragraphText = runs.map((r) => r.text).join("").trim();
    const numbered = detectNumberedHeading(paragraphText);
    if (numbered) {
      pushSection(paragraphText, numbered.level);
      continue;
    }
    appendParagraph(runs);
  }

  if (!promoted && sections.length > 1) sections.shift();
  return { type: "document", sections };
}

function collectInlineRuns(el: Element, prefix: string): Run[] {
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
export function detectNumberedHeading(text: string): { level: number } | null {
  if (!text || text.length > 120) return null;
  if (/\.\s+[a-z]/.test(text)) return null; // sentence-shaped
  // Dotted-decimal: 1, 1.2, 1.2.3, optional trailing dot or em-dash.
  const dotted = /^(\d+(?:\.\d+){0,3})\.?\s+[—–-]?\s*[A-Z][A-Za-z0-9'’&/ ()-]{1,100}$/.exec(text);
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
  return new DOMParser().parseFromString(`<!doctype html><html><body>${html}</body></html>`, "text/html");
}
