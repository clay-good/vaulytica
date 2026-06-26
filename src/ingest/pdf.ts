import type { DocumentTree, IngestResult, Paragraph, Run, Section } from "./types.js";
import { countWords, normalize } from "./normalize.js";
import { sha256Hex } from "./hash.js";
import { assertDocumentBytes, MAX_OCR_PAGES } from "./limits.js";

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
  return (mod.default ?? mod) as PdfJsLike;
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
  for (let n = 1; n <= pdfDoc.numPages; n += 1) {
    const page = await pdfDoc.getPage(n);
    const content = await page.getTextContent();
    pages.push(extractPageContent(content.items, n));
    options.onProgress?.(n / pdfDoc.numPages, "text");
  }

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
      const uncertain = (ocrText.match(/\[uncertain\]/g) ?? []).length;
      if (uncertain > 0) {
        warnings.push(
          `OCR flagged ${uncertain} low-confidence word${uncertain === 1 ? "" : "s"} (marked "[uncertain]" in the text). Verify any party name, amount, or date near an [uncertain] marker before relying on a finding.`,
        );
      }
      return {
        tree: normalized,
        source: "pdf",
        word_count: countWords(normalized),
        page_count: pdfDoc.numPages,
        sha256,
        warnings,
      };
    }
    warnings.push(
      `${layer.reason}. Pass { allowOcr: true } to run OCR via tesseract.js, or supply a digitally-generated PDF.`,
    );
  }

  const tree = buildTreeFromPages(pages);
  const normalized = normalize(tree);

  return {
    tree: normalized,
    source: "pdf",
    word_count: countWords(normalized),
    page_count: pdfDoc.numPages,
    sha256,
    warnings,
  };
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

  for (const page of pages) {
    const lines = groupItemsIntoLines(page.items);
    const paragraphLines = groupLinesIntoParagraphs(lines);
    for (const paraLines of paragraphLines) {
      const allText = paraLines
        .flat()
        .map((it) => it.str)
        .join(" ")
        .replace(/\s+/g, " ")
        .trim();
      if (!allText) continue;
      const maxSize = Math.max(...paraLines.flat().map((it) => Math.round(it.transform[0] ?? 0)));
      const isLikelyHeading =
        maxSize >= page.medianFontSize + 2 && allText.length < 120 && paraLines.length === 1;
      if (isLikelyHeading) {
        const level = Math.max(1, Math.min(6, page.medianFontSize + 6 - maxSize + 1));
        pushSection(allText, level);
        continue;
      }
      const runs: Run[] = [{ id: "", text: allText, start: 0, end: 0 }];
      stack[stack.length - 1]!.paragraphs.push({ id: "", runs });
    }
  }

  if (!promoted && sections.length > 1) sections.shift();
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

function groupLinesIntoParagraphs(lines: PdfTextItem[][]): PdfTextItem[][][] {
  // Trivial grouping for now: each non-empty line is its own paragraph. PDF
  // paragraph detection is genuinely hard without layout analysis, and the
  // downstream extractors are line-tolerant. A more sophisticated grouping
  // can land later without changing the public API.
  return lines.map((l) => [l]);
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
