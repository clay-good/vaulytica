/**
 * OCR fallback for scanned PDFs. Lazy-loaded by {@link ingestPdf} only when
 * the text layer is empty, so tesseract.js (~8 MB compressed) never enters
 * the main bundle.
 *
 * Language is hardcoded to `eng` at launch per spec §28. Additional
 * languages can be added by callers passing through to {@link ocrCanvas}.
 *
 * The implementation renders each PDF page to an offscreen `<canvas>` at
 * 200 DPI (scale ≈ 200 / 72 ≈ 2.78), then hands the canvas to tesseract.js.
 * tesseract.js exposes a worker pool; we use a single worker per
 * {@link runOcr} call and terminate it at the end so memory is reclaimed
 * immediately and the same call is reproducible.
 */

type PdfDocument = {
  numPages: number;
  getPage: (n: number) => Promise<PdfPage>;
};

type PdfPage = {
  getViewport: (params: { scale: number }) => { width: number; height: number };
  render: (params: { canvasContext: CanvasRenderingContext2D; viewport: unknown }) => {
    promise: Promise<void>;
  };
};

type TesseractLike = {
  createWorker: (lang?: string) => Promise<{
    recognize: (img: HTMLCanvasElement | string) => Promise<{ data: { text: string } }>;
    terminate: () => Promise<void>;
  }>;
};

const OCR_SCALE = 200 / 72;

export type OcrProgress = (progress: number, stage: "text" | "ocr") => void;

/**
 * Run OCR over every page of a PDF.js document. Returns the concatenated
 * text with two newlines between pages so paragraph detection downstream
 * has a stable boundary signal.
 */
export async function runOcr(pdfDoc: PdfDocument, onProgress?: OcrProgress): Promise<string> {
  const tesseract = await loadTesseract();
  const worker = await tesseract.createWorker("eng");
  try {
    const chunks: string[] = [];
    for (let n = 1; n <= pdfDoc.numPages; n += 1) {
      const page = await pdfDoc.getPage(n);
      const viewport = page.getViewport({ scale: OCR_SCALE });
      const canvas = makeCanvas(viewport.width, viewport.height);
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("ingest/ocr: failed to acquire 2D canvas context");
      await page.render({ canvasContext: ctx, viewport }).promise;
      const result = await worker.recognize(canvas);
      chunks.push(result.data.text);
      onProgress?.(n / pdfDoc.numPages, "ocr");
    }
    return chunks.join("\n\n");
  } finally {
    await worker.terminate();
  }
}

/**
 * OCR a single canvas. Exported so callers (e.g., a future "OCR this image"
 * feature) can use the lazy-loaded engine without going through a PDF.
 */
export async function ocrCanvas(canvas: HTMLCanvasElement, lang = "eng"): Promise<string> {
  const tesseract = await loadTesseract();
  const worker = await tesseract.createWorker(lang);
  try {
    const result = await worker.recognize(canvas);
    return result.data.text;
  } finally {
    await worker.terminate();
  }
}

async function loadTesseract(): Promise<TesseractLike> {
  const mod = (await import("tesseract.js")) as unknown as { default?: TesseractLike } & TesseractLike;
  return (mod.default ?? mod) as TesseractLike;
}

function makeCanvas(width: number, height: number): HTMLCanvasElement {
  if (typeof OffscreenCanvas !== "undefined") {
    // Tesseract.js accepts OffscreenCanvas via duck-typing; we still return
    // an HTMLCanvasElement-shaped value because the worker only reads
    // `.width`, `.height`, and `getContext("2d")`.
    return new OffscreenCanvas(width, height) as unknown as HTMLCanvasElement;
  }
  if (typeof document === "undefined") {
    throw new Error(
      "ingest/ocr: no document or OffscreenCanvas available. OCR requires a browser environment.",
    );
  }
  const c = document.createElement("canvas");
  c.width = width;
  c.height = height;
  return c;
}
