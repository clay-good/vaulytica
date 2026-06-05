import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Orchestration coverage for the OCR fallback (`runOcr` / `ocrCanvas`). The
 * real OCR engine (tesseract.js: WASM + a downloaded language model) and real
 * canvas rendering cannot run headless, so they are mocked here. This does NOT
 * verify OCR *accuracy* — that needs a real device with a scanned PDF — but it
 * does pin the logic we wrote: the per-page loop, the `\n\n` page-separator
 * contract that downstream paragraph detection relies on, the progress
 * callback, and (critically) that the worker is always `terminate()`d, even
 * when recognition throws, so the engine doesn't leak.
 */

const recognize =
  vi.fn<
    (img: unknown) => Promise<{ data: { text: string; words?: { text: string; confidence: number }[] } }>
  >();
const terminate = vi.fn(async () => {});
const createWorker = vi.fn(async (_lang?: string) => ({ recognize, terminate }));

// Intercept the dynamic `import("tesseract.js")` in loadTesseract().
vi.mock("tesseract.js", () => ({ default: { createWorker } }));

// makeCanvas() prefers OffscreenCanvas; happy-dom's canvas getContext can be
// null, which would throw before the mocked render runs. A tiny fake whose
// getContext returns a truthy stub lets the orchestration proceed without a
// real rasterizer (we never read pixels — recognize is mocked).
class FakeOffscreenCanvas {
  width: number;
  height: number;
  constructor(width: number, height: number) {
    this.width = width;
    this.height = height;
  }
  getContext(): CanvasRenderingContext2D {
    return {} as CanvasRenderingContext2D;
  }
}

import { ocrCanvas, runOcr, markLowConfidence } from "./ocr.js";

beforeEach(() => {
  vi.stubGlobal("OffscreenCanvas", FakeOffscreenCanvas);
});

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

function fakePage() {
  return {
    getViewport: (p: { scale: number }) => ({ width: 100 * p.scale, height: 100 * p.scale }),
    render: () => ({ promise: Promise.resolve() }),
  };
}

describe("ocrCanvas", () => {
  it("creates an eng worker, recognizes the canvas, returns text, terminates", async () => {
    recognize.mockResolvedValue({ data: { text: "scanned text" } });
    const canvas = {} as HTMLCanvasElement;
    const text = await ocrCanvas(canvas, "eng");
    expect(text).toBe("scanned text");
    expect(createWorker).toHaveBeenCalledWith("eng");
    expect(recognize).toHaveBeenCalledWith(canvas);
    expect(terminate).toHaveBeenCalledTimes(1);
  });

  it("defaults the language to eng", async () => {
    recognize.mockResolvedValue({ data: { text: "x" } });
    await ocrCanvas({} as HTMLCanvasElement);
    expect(createWorker).toHaveBeenCalledWith("eng");
  });

  it("terminates the worker even when recognition throws (no engine leak)", async () => {
    recognize.mockRejectedValue(new Error("recognize failed"));
    await expect(ocrCanvas({} as HTMLCanvasElement)).rejects.toThrow("recognize failed");
    expect(terminate).toHaveBeenCalledTimes(1);
  });
});

describe("markLowConfidence", () => {
  it("marks only words below the confidence threshold", () => {
    const out = markLowConfidence([
      { text: "Acme", confidence: 95 },
      { text: "Corp", confidence: 40 },
      { text: "shall", confidence: 88 },
      { text: "pay", confidence: 12 },
    ]);
    expect(out).toBe("Acme Corp [uncertain] shall pay [uncertain]");
  });

  it("leaves a high-confidence line unmarked", () => {
    const out = markLowConfidence([
      { text: "All", confidence: 90 },
      { text: "clear", confidence: 91 },
    ]);
    expect(out).toBe("All clear");
  });
});

describe("runOcr applies per-word confidence marking when words are present", () => {
  it("flags low-confidence words inline", async () => {
    recognize.mockResolvedValue({
      data: {
        text: "ignored",
        words: [
          { text: "Provider", confidence: 95 },
          { text: "pays", confidence: 30 },
        ],
      },
    });
    const text = await runOcr({ numPages: 1, getPage: async () => fakePage() });
    expect(text).toBe("Provider pays [uncertain]");
  });
});

describe("runOcr", () => {
  it("OCRs every page and joins them with a blank-line separator", async () => {
    recognize
      .mockResolvedValueOnce({ data: { text: "page one" } })
      .mockResolvedValueOnce({ data: { text: "page two" } });
    const getPage = vi.fn(async () => fakePage());
    const text = await runOcr({ numPages: 2, getPage }, undefined);
    // The `\n\n` boundary is the contract downstream paragraph detection reads.
    expect(text).toBe("page one\n\npage two");
    expect(getPage).toHaveBeenCalledTimes(2);
    expect(getPage).toHaveBeenNthCalledWith(1, 1);
    expect(getPage).toHaveBeenNthCalledWith(2, 2);
    expect(terminate).toHaveBeenCalledTimes(1);
  });

  it("reports progress once per page as a fraction in (0, 1]", async () => {
    recognize.mockResolvedValue({ data: { text: "t" } });
    const onProgress = vi.fn();
    await runOcr({ numPages: 4, getPage: async () => fakePage() }, onProgress);
    expect(onProgress).toHaveBeenCalledTimes(4);
    expect(onProgress).toHaveBeenNthCalledWith(1, 0.25, "ocr");
    expect(onProgress).toHaveBeenLastCalledWith(1, "ocr");
  });

  it("terminates the worker even when a page fails (no engine leak)", async () => {
    recognize.mockRejectedValue(new Error("page boom"));
    await expect(runOcr({ numPages: 1, getPage: async () => fakePage() })).rejects.toThrow(
      "page boom",
    );
    expect(terminate).toHaveBeenCalledTimes(1);
  });
});
