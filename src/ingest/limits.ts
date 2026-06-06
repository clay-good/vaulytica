/**
 * Input-boundary guards (spec-v8 Thrust A, Part II).
 *
 * Every public ingest entry point must degrade gracefully — never crash,
 * hang, or exhaust memory — on hostile or malformed input. These caps are the
 * deterministic, posture-legal way to do that: each is a pure function of the
 * input (so the determinism contract holds — §6 "bounds, never timeouts"), and
 * each is set one order of magnitude above the largest legitimate real-world
 * input, so no real user ever hits one. A 50 MB contract is already enormous.
 */

/**
 * Single-document byte ceiling for the direct ingest entry points
 * (`ingestDocxBuffer`, `ingestPdfBuffer`). The bundle planner already caps the
 * multi-document path; this is its single-document analog, so a direct drop or
 * a direct API caller cannot bypass every limit. Matches the per-file bundle
 * cap (50 MB).
 */
export const MAX_DOCUMENT_BYTES = 50 * 1024 * 1024;

/**
 * Pasted-text character ceiling for `ingestPaste`. ~20M characters is a
 * multi-thousand-page document; past it the paste is a mistake, not a use case.
 */
export const MAX_PASTE_CHARS = 20 * 1024 * 1024;

/**
 * Maximum section nesting depth. Real legal outlines are a handful of levels
 * deep; 64 is far past any genuine document. Beyond it, descendant sections are
 * flattened into the deepest kept ancestor (their paragraphs preserved) rather
 * than recursed into, so a pathologically nested DOCX/HTML cannot overflow the
 * stack in `normalize`/`walk`/the extractors.
 */
export const MAX_SECTION_DEPTH = 64;

/**
 * Maximum number of PDF pages OCR'd in one run. A 500-page scan is already
 * enormous; beyond it the first N are OCR'd and the remainder reported as
 * skipped (an honest partial, never a silent hang).
 */
export const MAX_OCR_PAGES = 500;

/** Typed, catchable rejection for an input that exceeds a hard byte/char cap. */
export class InputTooLargeError extends Error {
  readonly cap: number;
  readonly observed: number;
  constructor(what: string, observed: number, cap: number) {
    super(
      `${what} (${observed.toLocaleString()}) exceeds the ${cap.toLocaleString()} limit. ` +
        `Split the document or supply a smaller file.`,
    );
    this.name = "InputTooLargeError";
    this.cap = cap;
    this.observed = observed;
  }
}

/** Reject a direct-entry document whose byte length exceeds {@link MAX_DOCUMENT_BYTES}. */
export function assertDocumentBytes(byteLength: number): void {
  if (byteLength > MAX_DOCUMENT_BYTES) {
    throw new InputTooLargeError("Document size in bytes", byteLength, MAX_DOCUMENT_BYTES);
  }
}

/** Reject a paste whose character length exceeds {@link MAX_PASTE_CHARS}. */
export function assertPasteChars(charLength: number): void {
  if (charLength > MAX_PASTE_CHARS) {
    throw new InputTooLargeError("Pasted text length", charLength, MAX_PASTE_CHARS);
  }
}
