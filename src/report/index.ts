/**
 * Report layer barrel. Consumers import the DOCX builder, the JSON
 * builder, the citation formatter, and the bibliography deduper from
 * a single place.
 */

export { buildDocxReport } from "./docx.js";
export { buildJsonReport, type JsonReport } from "./json.js";
export { formatCitation, formatBibliographyEntry } from "./citations.js";
export {
  buildBibliography,
  citationIndex,
  type BibliographyEntry,
} from "./bibliography.js";

// v3 report extensions (spec-v3.md §§54–59). Each renderer is conditional;
// the v2 builder accepts an optional `v3?: V3ReportInputs` and inserts the
// new sections only when the corresponding input is present.
export type {
  ComplianceMatrix,
  ComplianceMatrixRow,
  MatrixCell,
  MatrixStatus,
  V3ReportInputs,
} from "./v3/index.js";

export {
  renderComplianceMatrix,
  renderTransfersSummary,
  renderSubprocessorPage,
  renderInsurancePage,
  renderConsistencyAppendix,
  renderCitationIndex,
  buildV3Footer,
} from "./v3/index.js";

// v4 §11 — consolidated bundle report (Step 44).
export {
  buildBundleDocxReport,
  buildBundleJson,
  buildBundleJsonBlob,
  buildBundleZip,
  bundleFingerprint,
  BUNDLE_TOP_N,
} from "./bundle.js";

export type {
  BundleDocument,
  BundleReportInput,
  BundleZipInput,
  BundleZipArtifact,
  BundleJson,
} from "./bundle.js";
