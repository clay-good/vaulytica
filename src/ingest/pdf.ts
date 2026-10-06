import type { DocumentTree, IngestResult, Paragraph, Run, Section } from "./types.js";
import { countWords, noTextWarning, normalize } from "./normalize.js";
import { sha256Hex } from "./hash.js";
import { assertDocumentBytes, MAX_OCR_PAGES } from "./limits.js";
import { languageFields } from "./language.js";
import { documentVocabulary, joinWrappedLines } from "./hyphenation.js";

/**
 * Ingest a PDF using PDF.js. PDFs have no native heading metadata, so we
 * detect headings via two signals:
 *
 * 1. Font-size jumps. A run whose font size is materially larger than the
 *    median body-text size on its page is treated as a heading. The exact
 *    level is assigned in document order: largest-on-page → h1, next → h2,
 *    and so on, capped at 6.
 * 2. Bold detection. A run that is bold *and* on its own paragraph (no
 *    body-size text below it on the same line) is treated as a heading at
 *    the next available level if no font-size signal fired.
 *
 * The heuristics are intentionally conservative. When in doubt, we emit
 * body text rather than guessing a heading.
 *
 * Per the build plan, PDF ingest must also handle the OCR fallback: if the
 * text layer is empty or near-empty (< 100 alphabetic characters across all
 * pages of a multi-page document), the caller can opt in to OCR via
 * `ingestPdf(file, { allowOcr: true, onProgress })`. The actual OCR
 * implementation lives in `./ocr.ts` and is dynamically imported so the
 * 8 MB tesseract.js bundle stays out of the main chunk.
 */

export type IngestPdfOptions = {
  /** Allow OCR fallback when the text layer is empty. Default `false`. */
  allowOcr?: boolean;
  /** Called periodically during analysis with values in [0, 1]. */
  onProgress?: (progress: number, stage: "text" | "ocr") => void;
};

type PdfJsLike = {
  getDocument: (params: { data: ArrayBuffer; useSystemFonts?: boolean }) => {
    promise: Promise<PdfDocument>;
  };
  GlobalWorkerOptions?: { workerSrc?: string };
};

type PdfDocument = {
  numPages: number;
  getPage: (n: number) => Promise<PdfPage>;
  destroy?: () => Promise<void>;
};

type PdfPage = {
  pageNumber: number;
  getTextContent: () => Promise<{ items: PdfTextItem[] }>;
  /**
   * Optional because the OCR path bridges through a structurally-typed
   * `PdfDocument` of its own and older stubs in the tests do not define it.
   */
  getAnnotations?: () => Promise<Array<{ subtype?: string }>>;
  getViewport: (params: { scale: number }) => { width: number; height: number };
  render?: (params: { canvasContext: unknown; viewport: unknown }) => { promise: Promise<void> };
};

type PdfTextItem = {
  str: string;
  /** transform[0] is the horizontal font size after page transform. */
  transform: number[];
  /** Width of the run; 0 indicates a sentinel item (e.g. end-of-line). */
  width: number;
  /** Y position; line breaks are detected by Y delta. */
  fontName?: string;
  hasEOL?: boolean;
};

async function loadPdfJs(): Promise<PdfJsLike> {
  const mod = (await import("pdfjs-dist/legacy/build/pdf.mjs")) as unknown as PdfJsLike & {
    default?: PdfJsLike;
  };
  const pdfjs = (mod.default ?? mod) as PdfJsLike;
  // Same-origin worker pin (fix-privacy-claim-accuracy). Without an explicit
  // `workerSrc` the browser build throws ('No "GlobalWorkerOptions.workerSrc"
  // specified') before parsing a single byte — real-browser PDF analysis was
  // fully broken while the happy-dom suite exercised Node's fake-worker path.
  // The app serves the exact matching worker build from /pdf-worker/ (dev
  // middleware + dist copy in vite.config.ts), so PDF analysis works and
  // never resolves an asset off-origin. Node (CLI, vitest) keeps the fake
  // worker: same output, no Worker global needed.
  const isNode =
    typeof process !== "undefined" &&
    !!(process as { versions?: { node?: string } }).versions?.node;
  if (!isNode && pdfjs.GlobalWorkerOptions && !pdfjs.GlobalWorkerOptions.workerSrc) {
    pdfjs.GlobalWorkerOptions.workerSrc = "/pdf-worker/pdf.worker.min.mjs";
  }
  return pdfjs;
}

export async function ingestPdf(file: File, options: IngestPdfOptions = {}): Promise<IngestResult> {
  const buf = await file.arrayBuffer();
  return ingestPdfBuffer(buf, options);
}

export async function ingestPdfBuffer(
  buf: ArrayBuffer,
  options: IngestPdfOptions = {},
): Promise<IngestResult> {
  assertDocumentBytes(buf.byteLength); // spec-v8 §7 — reject before parsing
  const warnings: string[] = [];
  // Hash the source bytes *before* handing the buffer to pdfjs. `getDocument`
  // takes ownership of the ArrayBuffer and may detach it (it does under pdfjs's
  // Node fake-worker; the browser's copying worker happens to leave it intact),
  // so computing the hash afterward would read a detached buffer. Same bytes,
  // same hash — just ordered so the path is robust in any environment.
  const sha256 = await sha256Hex(buf);
  const pdfjs = await loadPdfJs();
  const pdfDoc = await pdfjs.getDocument({ data: buf, useSystemFonts: true }).promise;

  const pages: PageContent[] = [];
  let markupAnnotations = 0;
  for (let n = 1; n <= pdfDoc.numPages; n += 1) {
    const page = await pdfDoc.getPage(n);
    const content = await page.getTextContent();
    pages.push(extractPageContent(content.items, n));
    // A PDF's reviewer markup lives in ANNOTATIONS, not in the text layer, so
    // `getTextContent` never sees it: a sticky note reading "we cannot agree to
    // this" is neither analyzed nor mentioned. The DOCX side of this is
    // `docx-notices.ts`; this is the same silence in the other format.
    // Counted here rather than by the delivery pack's byte-regex, which is
    // honest that it only reads UNCOMPRESSED regions — pdfjs has already
    // parsed the object streams, so this sees the annotations a modern PDF
    // actually stores.
    markupAnnotations += await countMarkupAnnotations(page);
    options.onProgress?.(n / pdfDoc.numPages, "text");
  }
  const annotationNotice = markupAnnotationNotice(markupAnnotations);

  const perPageAlpha = pages.map((p) =>
    p.items.reduce((acc, it) => acc + (it.str.match(/[A-Za-z]/g)?.length ?? 0), 0),
  );
  const layer = assessTextLayer(perPageAlpha);
  const needsOcr = layer.needsOcr;

  if (needsOcr) {
    if (options.allowOcr) {
      const { runOcr } = await import("./ocr.js");
      // Both `pdf.ts` and `ocr.ts` declare local structural `PdfDocument`
      // types; they're identical in shape but TS treats them as
      // unrelated nominal aliases. Cast through `unknown` to bridge.
      const ocrText = await runOcr(
        pdfDoc as unknown as Parameters<typeof runOcr>[0],
        options.onProgress,
      );
      const tree = buildTreeFromOcrText(ocrText);
      const normalized = normalize(tree);
      warnings.push(`${layer.reason}; OCR fallback was used. Some structure may be lost.`);
      if (pdfDoc.numPages > MAX_OCR_PAGES) {
        warnings.push(
          `Document has ${pdfDoc.numPages} pages; OCR was bounded to the first ${MAX_OCR_PAGES}. The remaining ${pdfDoc.numPages - MAX_OCR_PAGES} page(s) were not OCR'd.`,
        );
      }
      if (annotationNotice) warnings.push(annotationNotice);
      const uncertain = (ocrText.match(/\[uncertain\]/g) ?? []).length;
      if (uncertain > 0) {
        warnings.push(
          `OCR flagged ${uncertain} low-confidence word${uncertain === 1 ? "" : "s"} (marked "[uncertain]" in the text). Verify any party name, amount, or date near an [uncertain] marker before relying on a finding.`,
        );
      }
      const ocrWordCount = countWords(normalized);
      warnings.push(...noTextWarning(ocrWordCount));
      return {
        tree: normalized,
        source: "pdf",
        word_count: ocrWordCount,
        page_count: pdfDoc.numPages,
        ...languageFields(normalized, warnings),
        sha256,
        warnings,
      };
    }
    warnings.push(
      `${layer.reason}. This looks like a scanned PDF without a text layer; OCR is not available in the browser build (its models would have to load from a third-party CDN, which the privacy posture blocks), so analysis covers only the extractable text. Supply a digitally-generated PDF for full coverage.`,
    );
  }

  if (annotationNotice) warnings.push(annotationNotice);

  const tree = buildTreeFromPages(pages);
  const normalized = normalize(tree);
  const word_count = countWords(normalized);
  warnings.push(...noTextWarning(word_count));

  return {
    tree: normalized,
    source: "pdf",
    word_count,
    page_count: pdfDoc.numPages,
    ...languageFields(normalized, warnings),
    sha256,
    warnings,
  };
}

/**
 * Reviewer markup subtypes — the ones a person leaves for another person to
 * read. Deliberately NOT every annotation: a `Link` is navigation and a
 * `Widget` is a form field, and warning about those would train the reader to
 * ignore the notice.
 */
const MARKUP_SUBTYPES = new Set([
  "Text",
  "FreeText",
  "Highlight",
  "Underline",
  "StrikeOut",
  "Squiggly",
  "Caret",
  "Ink",
]);

/** Markup annotations on one page, or 0 when the build cannot report them. */
async function countMarkupAnnotations(page: PdfPage): Promise<number> {
  if (!page.getAnnotations) return 0;
  try {
    const annots = await page.getAnnotations();
    // `Popup` is deliberately absent from the set above: it is the open window
    // BELONGING to another annotation, so counting it would report every
    // sticky note twice.
    return annots.filter((a) => MARKUP_SUBTYPES.has(a.subtype ?? "")).length;
  } catch {
    // Annotation parsing is not worth failing an ingest over.
    return 0;
  }
}

/** The notice a marked-up PDF earns, or null. */
export function markupAnnotationNotice(count: number): string | null {
  if (count <= 0) return null;
  const one = count === 1;
  return (
    `This PDF has ${count} reviewer ${one ? "annotation" : "annotations"} (sticky notes, ` +
    `highlights, or strike-throughs). ${one ? "It was" : "They were"} NOT analyzed — a note can ` +
    `carry the position behind a clause, and none of that reached this report. ` +
    `Open the PDF to read ${one ? "it" : "them"}.`
  );
}

// ───────────────────────────────────────────────────────────────────────────
// Text-layer assessment (OCR trigger)
// ───────────────────────────────────────────────────────────────────────────

/** A page with fewer alphabetic characters than this is treated as image-only. */
export const PER_PAGE_ALPHA_FLOOR = 50;

/**
 * Decide whether a PDF needs OCR from its per-page alphabetic-character
 * counts. Two triggers, both requiring more than one page:
 *
 * 1. Whole-document near-empty (< 100 alpha chars total) — a fully
 *    scanned PDF (the original, conservative trigger).
 * 2. Mixed text layer — most pages are image-only (< {@link
 *    PER_PAGE_ALPHA_FLOOR} alpha chars) even though a searchable header
 *    or cover inflates the total above 100. A digitally-searchable
 *    header over an image-only body would otherwise be misread as
 *    text-sufficient and the body silently lost.
 *
 * Conservative on trigger 2: it requires at least two image-only pages
 * and a clear majority (≥ 60%) of pages image-only, so a single sparse
 * divider or signature page does not force OCR on an otherwise-text PDF.
 * Pure and deterministic.
 */
export function assessTextLayer(perPageAlpha: number[]): {
  needsOcr: boolean;
  imageOnlyPages: number[];
  reason: string;
} {
  const numPages = perPageAlpha.length;
  const totalAlpha = perPageAlpha.reduce((a, b) => a + b, 0);
  const imageOnlyPages = perPageAlpha
    .map((a, i) => ({ a, page: i + 1 }))
    .filter((x) => x.a < PER_PAGE_ALPHA_FLOOR)
    .map((x) => x.page);
  if (numPages <= 1) {
    return { needsOcr: false, imageOnlyPages, reason: "" };
  }
  if (totalAlpha < 100) {
    return {
      needsOcr: true,
      imageOnlyPages,
      reason: `Text layer is effectively empty (${totalAlpha} alphabetic chars across ${numPages} pages)`,
    };
  }
  if (imageOnlyPages.length >= 2 && imageOnlyPages.length / numPages >= 0.6) {
    return {
      needsOcr: true,
      imageOnlyPages,
      reason: `Text layer is mixed: ${imageOnlyPages.length} of ${numPages} pages are image-only (a searchable header over a scanned body)`,
    };
  }
  return { needsOcr: false, imageOnlyPages, reason: "" };
}

// ───────────────────────────────────────────────────────────────────────────
// Internal helpers
// ───────────────────────────────────────────────────────────────────────────

type PageContent = {
  pageNumber: number;
  items: PdfTextItem[];
  medianFontSize: number;
};

function extractPageContent(items: PdfTextItem[], pageNumber: number): PageContent {
  const sizes = items.filter((i) => i.str.trim()).map((i) => Math.round(i.transform[0] ?? 0));
  const medianFontSize = median(sizes) || 11;
  return { pageNumber, items, medianFontSize };
}

function median(nums: number[]): number {
  if (nums.length === 0) return 0;
  const sorted = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1]! + sorted[mid]!) / 2 : sorted[mid]!;
}

function buildTreeFromPages(pages: PageContent[]): DocumentTree {
  // Document-wide, so a word hyphenated on page 3 can be recognized from the
  // way page 11 spells it.
  const vocabulary = documentVocabulary(
    pages.flatMap((p) => p.items.map((it) => it.str)).join(" "),
  );
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

  // The last body paragraph placed, and whether the page has placed anything
  // yet: a paragraph the page break cut mid-sentence continues on the next
  // page's first line.
  let lastParagraph: Paragraph | null = null;
  const pageLines = pages.map((page) => groupItemsIntoLines(page.items));
  const spacing = ordinaryLineStep(pageLines);
  for (const [k, page] of pages.entries()) {
    const paragraphLines = groupLinesIntoParagraphs(pageLines[k]!, spacing);
    let firstOnPage = true;
    for (const paraLines of paragraphLines) {
      // Each grouped LINE is joined into a word-sequence first, so an
      // end-of-line hyphen is still visible when the lines are joined. The old
      // flat `.join(" ")` put a space after it — "confiden- tial" — which is
      // worse than the paste path's join and unreadable to every rule.
      const allText = joinWrappedLines(
        paraLines.map((line) =>
          line
            .map((it) => it.str)
            .join(" ")
            .replace(/\s+/g, " ")
            .trim(),
        ),
        vocabulary,
      ).replace(/\s+/g, " ");
      if (!allText) continue;
      const maxSize = Math.max(...paraLines.flat().map((it) => Math.round(it.transform[0] ?? 0)));
      const isLikelyHeading =
        maxSize >= page.medianFontSize + 2 && allText.length < 120 && paraLines.length === 1;
      if (isLikelyHeading) {
        const level = Math.max(1, Math.min(6, page.medianFontSize + 6 - maxSize + 1));
        pushSection(allText, level);
        firstOnPage = false;
        lastParagraph = null;
        continue;
      }
      // A PAGE BREAK IS NOT A PARAGRAPH BREAK when it falls mid-sentence:
      // "… governed by the laws of the State of" at the foot of one page and
      // "Delaware" at the head of the next read as two paragraphs, and the
      // governing law was "State of". Joined when the page's first paragraph
      // continues a sentence the last page left open and opens no clause.
      const continues =
        firstOnPage &&
        lastParagraph !== null &&
        // A closing parenthesis or quote ends a sentence only after its
        // punctuation: "within forty-five (45)" at a page foot is mid-sentence.
        !/[.!?:;]["”’')]?\s*$/.test(lastParagraph.runs[0]!.text) &&
        // …and ends the way a broken sentence does, not the way a heading line
        // does: "ARTICLE IV. OFFICERS" at the foot of a page carries no period
        // either, and joined its first section on the next.
        (/(?:[a-z,\-–—]|\(\d+\))\s*$/.test(lastParagraph.runs[0]!.text) ||
          lastParagraph.runs[0]!.text.length > 80) &&
        !(PDF_CLAUSE_OPENER.test(allText) && ENDS_CLAUSE.test(lastParagraph.runs[0]!.text));
      firstOnPage = false;
      if (continues) {
        const run = lastParagraph!.runs[0]!;
        run.text = joinWrappedLines([run.text, allText], vocabulary);
        continue;
      }
      const runs: Run[] = [{ id: "", text: allText, start: 0, end: 0 }];
      lastParagraph = { id: "", runs };
      stack[stack.length - 1]!.paragraphs.push(lastParagraph);
    }
  }

  // Drop the synthetic root ONLY when it is genuinely empty (the paste-path
  // guard, fix-ingest-preamble-integrity) — never the pre-heading preamble.
  if (sections.length > 1 && sections[0] === root && root.paragraphs.length === 0) {
    sections.shift();
  }
  return { type: "document", sections };
}

function groupItemsIntoLines(items: PdfTextItem[]): PdfTextItem[][] {
  const lines: PdfTextItem[][] = [];
  let current: PdfTextItem[] = [];
  for (const it of items) {
    if (it.hasEOL) {
      if (it.str) current.push(it);
      lines.push(current);
      current = [];
    } else {
      current.push(it);
    }
  }
  if (current.length) lines.push(current);
  return lines.filter((l) => l.some((it) => it.str.trim().length > 0));
}

/**
 * Where a clause can end, so the next line may open one. A wrapped line that
 * begins "(30) days of receipt" continues "within thirty" — the numeral is the
 * drafter's, not a list marker — and splitting there cut a payment term in
 * half. A list item follows a sentence end, a lead-in colon, a semicolon, or
 * the "and" / "or" before a list's last item.
 */
const ENDS_CLAUSE = /(?:[.!?:;]["”')]?|\b(?:and|or))\s*$/;

/** A line that opens a numbered clause starts a paragraph however it is spaced. */
// "15." / "15)" / "6.3" — a bare "15 " is a number in a sentence ("Sections
// 13, 14, and / 15 survive"), not a clause.
const PDF_CLAUSE_OPENER =
  /^(?:\d+(?:\.\d+)+\.?\s|\d+[.)]\s|\([a-z0-9]{1,4}\)\s|(?:ARTICLE|SECTION|EXHIBIT|SCHEDULE|ANNEX|APPENDIX)\s+[0-9IVXLC])/;

/**
 * A PDF has lines, not paragraphs: every wrapped line of a clause arrives as a
 * line of its own. Read as one paragraph each, a sentence split across two
 * lines was two "paragraphs" — every paragraph-scoped rule saw half a clause,
 * and a four-line securities legend pushed a warrant's title past the title
 * reader, so the warrant fell to generic-fallback.
 *
 * Lines join into a paragraph unless something on the page separates them: a
 * vertical gap wider than the page's ordinary line spacing (a blank line), a
 * change of font size (a heading or a footnote), a line that opens a numbered
 * clause, or a step back UP the page (a new column).
 */
const lineY = (l: PdfTextItem[]): number => l[0]?.transform[5] ?? 0;
const lineSize = (l: PdfTextItem[]): number =>
  Math.round(Math.max(...l.map((it) => it.transform[0] ?? 0)));

/**
 * The ordinary step from one line to the next, read across the whole
 * document: a page that holds two lines has one step, and a gap measured
 * against itself is never a gap. Taken from the low end of the distribution:
 * on a page of short paragraphs the gaps between them outnumber the steps
 * within them, and the median was the gap itself — a bylaws' "ARTICLE IV.
 * OFFICERS" ran into its first section.
 */
function ordinaryLineStep(pages: PdfTextItem[][][]): number {
  const steps: number[] = [];
  for (const lines of pages)
    for (let i = 1; i < lines.length; i++) {
      const d = lineY(lines[i - 1]!) - lineY(lines[i]!);
      if (d > 0 && lineSize(lines[i]!) === lineSize(lines[i - 1]!)) steps.push(d);
    }
  const sorted = steps.sort((a, b) => a - b);
  return sorted.length > 0 ? sorted[Math.floor(sorted.length * 0.2)]! : 0;
}

function groupLinesIntoParagraphs(lines: PdfTextItem[][], spacing: number): PdfTextItem[][][] {
  if (lines.length === 0) return [];
  const y = lineY;
  const size = lineSize;
  const text = (l: PdfTextItem[]): string =>
    l
      .map((it) => it.str)
      .join(" ")
      .trim();
  const out: PdfTextItem[][][] = [[lines[0]!]];
  for (let i = 1; i < lines.length; i++) {
    const prev = lines[i - 1]!;
    const cur = lines[i]!;
    const d = y(prev) - y(cur);
    const separate =
      spacing === 0 ||
      d <= 0 ||
      d > spacing * 1.35 ||
      size(cur) !== size(prev) ||
      (PDF_CLAUSE_OPENER.test(text(cur)) && ENDS_CLAUSE.test(text(prev)));
    if (separate) out.push([cur]);
    else out[out.length - 1]!.push(cur);
  }
  return out;
}

function buildTreeFromOcrText(text: string): DocumentTree {
  const paragraphs = text
    .split(/\n{2,}/)
    .map((p) => p.replace(/\s+/g, " ").trim())
    .filter(Boolean);
  const root: Section = {
    id: "",
    heading: "",
    level: 1,
    paragraphs: paragraphs.map<Paragraph>((t) => ({
      id: "",
      runs: [{ id: "", text: t, start: 0, end: 0 }],
    })),
    children: [],
  };
  return { type: "document", sections: [root] };
}
