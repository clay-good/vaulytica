/**
 * v3 report-section types (spec-v3.md §§54–59).
 *
 * Each section is conditional: the DOCX builder includes a section only
 * when the corresponding input is present. The matrix is the only
 * top-tier addition; the rest are optional pages.
 */

import type {
  V3ExtractedData,
  TransferMechanismReference,
  SubprocessorInventory,
  InsuranceSchedule,
} from "../../extract/v3/types.js";
import type { ConsistencyRun } from "../../engine/consistency/types.js";

/** A cell in the compliance matrix. */
export type MatrixStatus = "pass" | "partial" | "fail" | "na";

export type MatrixCell = {
  status: MatrixStatus;
  /** Optional rule ids contributing to the cell (used for click-through). */
  contributing_rule_ids?: string[];
  /** Optional human note rendered in the cell on top of the status. */
  note?: string;
};

export type ComplianceMatrixRow = {
  /** Regulator label (e.g., "HIPAA", "GDPR", "CCPA"). */
  regulator: string;
  /** Stable URL for the regulator's authoritative source. */
  authority_url?: string;
  /** One entry per column, in column order. */
  cells: MatrixCell[];
};

export type ComplianceMatrix = {
  /** Column headers — typically the playbook's `compliance_matrix_columns`. */
  columns: string[];
  /** One row per applicable regulator. */
  rows: ComplianceMatrixRow[];
  /** ISO 8601 of the DKB build date that grounded the matrix. */
  dkb_build_date?: string;
};

/** Aggregate of every v3 report extension passed to {@link buildDocxReport}. */
export type V3ReportInputs = {
  /** Spec §54. Rendered after the executive summary. */
  matrix?: ComplianceMatrix;
  /** Spec §56. Rendered when transfer language is detected. */
  transfers?: TransferMechanismReference[];
  /** Spec §57. Rendered when a subprocessor list is referenced. */
  subprocessor?: SubprocessorInventory | null;
  /** Spec §58. Rendered for COI playbooks or when an insurance schedule is present. */
  insurance?: InsuranceSchedule;
  /** Spec §59. Rendered when two or more documents were loaded. */
  consistency?: ConsistencyRun;
  /** Spec §55. ISO 8601 build date for the citation-as-of line. */
  dkb_build_date?: string;
  /** Whole v3 extracted data (convenience pass-through). */
  extracted_v3?: V3ExtractedData;
};
