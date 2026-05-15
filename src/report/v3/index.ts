/**
 * v3 report extensions barrel (spec-v3.md §§54–59).
 *
 * Consumers import the section renderers, the matrix types, and the
 * footer builder. The v2 DOCX builder in `src/report/docx.ts` consumes
 * this module via an optional `v3` input.
 */

export type {
  ComplianceMatrix,
  ComplianceMatrixRow,
  MatrixCell,
  MatrixStatus,
  V3ReportInputs,
} from "./types.js";

export { renderComplianceMatrix } from "./matrix.js";
export { renderTransfersSummary } from "./transfers.js";
export { renderSubprocessorPage } from "./subprocessor.js";
export { renderInsurancePage } from "./insurance.js";
export { renderConsistencyAppendix } from "./consistency.js";
export { renderCitationIndex } from "./citation-index.js";
export { buildV3Footer, type FooterFields } from "./footer.js";
