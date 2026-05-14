/**
 * v3 extractor barrel (spec-v3.md §17).
 */

import type { DocumentTree } from "../../ingest/types.js";
import type { Party } from "../types.js";
import type { V3ExtractedData } from "./types.js";

import { classifyRoles } from "./role-classifier.js";
import { extractDataCategories } from "./pii-category.js";
import { extractTransferMechanisms } from "./transfer-mechanism.js";
import { extractSecurityMeasures } from "./security-measures.js";
import { extractBreachTimings } from "./breach-timing.js";
import { extractAuditRights } from "./audit-rights.js";
import { extractSubprocessorInventory } from "./subprocessor.js";
import { extractInsuranceSchedule } from "./insurance.js";
import { extractDtsaNotice } from "./dtsa-notice.js";

export { classifyRoles } from "./role-classifier.js";
export { extractDataCategories, CATEGORY_CATALOG } from "./pii-category.js";
export { extractTransferMechanisms } from "./transfer-mechanism.js";
export { extractSecurityMeasures } from "./security-measures.js";
export { extractBreachTimings } from "./breach-timing.js";
export { extractAuditRights } from "./audit-rights.js";
export { extractSubprocessorInventory } from "./subprocessor.js";
export { extractInsuranceSchedule } from "./insurance.js";
export { extractDtsaNotice } from "./dtsa-notice.js";

export type {
  Role,
  RoleEvidence,
  RoleAssignment,
  DataCategoryGroup,
  DataCategory,
  TransferMechanismKind,
  TransferMechanismLocation,
  TransferMechanismReference,
  SecurityMeasureSlug,
  SecurityMeasureCadence,
  SecurityMeasureScope,
  SecurityMeasure,
  BreachTrigger,
  BreachAddressee,
  BreachChannel,
  BreachTiming,
  AuditMethod,
  AuditCostAllocation,
  AuditRights,
  SubprocessorConsentForm,
  SubprocessorListLocation,
  SubprocessorObjectionConsequence,
  SubprocessorInventory,
  InsuranceLine,
  InsuranceAmount,
  InsuranceEndorsement,
  InsuranceSchedule,
  DtsaNotice,
  V3ExtractedData,
} from "./types.js";

/** Run every v3 extractor in dependency order. Deterministic. */
export function extractAllV3(
  tree: DocumentTree,
  options: { parties?: Party[] } = {},
): V3ExtractedData {
  const parties = options.parties ?? [];
  return {
    roles: classifyRoles(tree, parties),
    data_categories: extractDataCategories(tree),
    transfer_mechanisms: extractTransferMechanisms(tree),
    security_measures: extractSecurityMeasures(tree),
    breach_timings: extractBreachTimings(tree),
    audit_rights: extractAuditRights(tree),
    subprocessor: extractSubprocessorInventory(tree),
    insurance: extractInsuranceSchedule(tree),
    dtsa_notice: extractDtsaNotice(tree),
  };
}
