/**
 * Report layer barrel. Consumers import the DOCX builder, the JSON
 * builder, the citation formatter, and the bibliography deduper from
 * a single place.
 */

export { buildDocxReport } from "./docx.js";
export { buildJsonReport, type JsonReport, type ReportSecondaryFamily } from "./json.js";

// v6 Part III — findings-to-action exports (Steps 87–88).
export {
  buildFixListMarkdown,
  buildFixListCsv,
  buildObligationsCsv,
  buildDeadlinesIcs,
  collectDeadlines,
  fixListMarkdownBlob,
  fixListCsvBlob,
  obligationsCsvBlob,
  deadlinesIcsBlob,
  type DeadlineEvent,
  type UnresolvedDate,
  type DeadlinesResult,
} from "./exports.js";
// v6 Part I — version comparison (Steps 89–90).
export {
  compareRuns,
  comparabilityOf,
  ComparisonRefusedError,
  buildComparisonJson,
  buildComparisonJsonObject,
  type Comparison,
  type Comparability,
  type ComparisonDelta,
  type ComparisonJson,
  type RunSummary,
  type SeverityCounts,
  type UnchangedPair,
} from "./compare.js";
export { buildComparisonDocx, comparisonDocxBlob } from "./compare-docx.js";

export {
  formatCitation,
  formatBibliographyEntry,
  freshnessSignal,
  citationFamily,
  breakLongTokens,
  type CitationFamily,
} from "./citations.js";

// spec-v8 Thrust C — SARIF 2.1.0 export (Step 141) + standalone HTML report (Step 142).
export { buildSarif, buildSarifJson, sarifBlob, type SarifLog } from "./sarif.js";
export { buildHtmlReport, htmlReportBlob } from "./html.js";
// spec-v8 §25 — clause-evidence coverage surface (Step 146).
export {
  buildClauseEvidence,
  type ClauseEvidenceSummary,
  type FindingEvidence,
} from "./clause-evidence.js";
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

// v6 Part V — portfolio risk matrix (Step 97).
export {
  buildPortfolioMatrix,
  portfolioFingerprint,
  PORTFOLIO_CHECKS,
  PORTFOLIO_MATRIX_MAX_ROWS,
} from "./portfolio.js";
export type {
  PortfolioMatrix,
  PortfolioRow,
  PortfolioRollup,
  PortfolioStatus,
  PortfolioCellEval,
} from "./portfolio.js";

// v6 Part IV — model-clause references (Steps 95–96).
export {
  MODEL_CLAUSES,
  MODEL_CLAUSE_COVERAGE,
  modelClauseForRule,
  type ModelClauseReference,
} from "../dkb/model-clauses.js";

// v6 Part VI §21 — jurisdiction overlays (Step 101).
export {
  STATE_OVERLAYS,
  STATE_OVERLAY_COVERAGE,
  selectStateOverlays,
  overlayFamilyForPlaybook,
  type StateOverlay,
  type StateOverlayResult,
  type OverlayFamily,
} from "../dkb/state-overlays.js";
