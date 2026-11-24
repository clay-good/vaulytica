/**
 * Is a file's extracted text INCOMPLETE, and why?
 *
 * Distinct from "uncertain". A document read through OCR may be wrong word by
 * word; a scan whose text layer covers four pages of twelve yields nothing at
 * all from the other eight. Either way a comparison against it cannot reach a
 * verdict, which is what `checkConformity` needs to know.
 *
 * Derived from the ingest's own warning CODES rather than its prose, so this
 * does not break when a sentence is reworded.
 */
import type { IngestResult } from "../ingest/types.js";
import { ingestWarningCodes } from "../ingest/warning-codes.js";

export function incompleteTextReason(
  ingest: Pick<IngestResult, "warnings" | "source">,
): string | undefined {
  const codes = ingestWarningCodes(ingest);
  if (codes.includes("no-text-layer") || codes.includes("empty")) {
    return "no text could be extracted from it at all";
  }
  if (codes.includes("partial-text-layer")) {
    return "it is a scan whose text layer covers only some of its pages, and OCR did not run";
  }
  if (codes.includes("ocr")) {
    return "its words came from OCR, which may have misread them";
  }
  return undefined;
}
