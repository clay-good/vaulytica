import type { IngestResult } from "./types.js";

/**
 * A code beside each ingest warning (spec-v52 §1).
 *
 * `IngestResult.warnings` is a list of sentences written for a person. A
 * folder page has to SORT on them — "was this file read at all?" is a tier —
 * and it cannot sort on prose. Nor on "has a warning": every plain-text file
 * carries one. So each sentence gets a code, in the same order.
 *
 * The sentences do not change, and neither they nor the codes are inside
 * `run`, so no `result_hash` moves.
 *
 * Codes are read from the sentence's own opening words, which each producer
 * owns in one place (`paste.ts`, `normalize.ts`, `language.ts`,
 * `docx-notices.ts`, `pdf.ts`). `warning-codes.test.ts` drives every one of
 * those producers and fails if a sentence stops being recognized — an
 * unrecognized warning is `other`, which sorts as "read, with a caveat" and so
 * can never hide a file that was not read.
 */
export type IngestWarningCode =
  /** A PDF with no selectable text, read without OCR: nothing was analyzed. */
  | "no-text-layer"
  /** No words at all in a file that is not a PDF. */
  | "empty"
  /** A scan that was read through OCR; the text may be wrong. */
  | "ocr"
  /** Tracked changes, analyzed as if every change were accepted. */
  | "tracked-changes"
  /** Not English: the rules did not read most of it. */
  | "not-english"
  /** Read as plain text. Carried by every .txt and .md; not a caveat on its own. */
  | "plain-text"
  /** Any other notice (hidden text, PDF annotations, a parser message). */
  | "other";

function codeOf(message: string, source: IngestResult["source"]): IngestWarningCode {
  if (message.startsWith("No readable text was found")) {
    return source === "pdf" ? "no-text-layer" : "empty";
  }
  if (message.startsWith("Read as plain text.")) return "plain-text";
  if (message.startsWith("This document has tracked changes")) return "tracked-changes";
  if (message.startsWith("This document does not read as English")) return "not-english";
  if (/\bOCR\b/.test(message)) return "ocr";
  return "other";
}

/** One code per entry of `ingest.warnings`, in the same order. */
export function ingestWarningCodes(
  ingest: Pick<IngestResult, "warnings" | "source">,
): IngestWarningCode[] {
  return ingest.warnings.map((w) => codeOf(w, ingest.source));
}

/** Codes that mean the file's words never reached the rules. */
export const NOT_READ_CODES: ReadonlySet<IngestWarningCode> = new Set(["no-text-layer", "empty"]);

/** Codes that mean it was read, and the findings may be incomplete or wrong. */
export const CAVEAT_CODES: ReadonlySet<IngestWarningCode> = new Set([
  "ocr",
  "tracked-changes",
  "not-english",
  "other",
]);
