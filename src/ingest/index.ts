/**
 * Ingest layer barrel. Each ingest entry point produces a normalized
 * {@link IngestResult} from a source representation (File, ArrayBuffer, or
 * pasted text). The output {@link DocumentTree} is the contract the
 * extractor layer consumes.
 */
export type {
  DocumentTree,
  IngestResult,
  IngestSource,
  Paragraph,
  Run,
  Section,
  FormattingHint,
} from "./types.js";
export { flattenText } from "./types.js";
export { ingestDocx, ingestDocxBuffer, parseDocxHtml } from "./docx.js";
export { ingestPdf, ingestPdfBuffer } from "./pdf.js";
export type { IngestPdfOptions } from "./pdf.js";
export { ingestPaste } from "./paste.js";
export { normalize, countWords } from "./normalize.js";
export { sha256Hex } from "./hash.js";
// OCR is intentionally not re-exported by default — it is lazy-loaded by
// `ingestPdf` when needed. Direct callers can `import("@/ingest/ocr")`.
export type { OcrProgress } from "./ocr.js";

// Multi-document ingest (spec-v4 §8). Callers that need just the v1
// single-file path can keep importing the v1 entries above; the v4
// surface lives in its own module.
export {
  MAX_FILE_BYTES,
  MAX_BUNDLE_BYTES,
  MAX_BUNDLE_FILES,
  BUNDLE_CAP_MESSAGE,
  classifyExtension,
  rejectionForFilename,
  planBundle,
  filesToCandidates,
  enumerateFolderEntry,
  extractZipEntries,
  looksLikeZip,
  ingestEntries,
  ingestBundle,
} from "./multi.js";

export type {
  AcceptedKind,
  MultiIngestEntry,
  MultiIngestPlan,
  IngestedDocument,
  MultiIngestResult,
} from "./multi.js";
