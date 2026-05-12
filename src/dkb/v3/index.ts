/**
 * v3 DKB surface — node types and schemas for regulated-agreement
 * families. The classic v2 DKB surface lives at `../index.ts`; v3 nodes
 * are loaded separately by `dkb/build/v3/` and consumed by rules under
 * `src/engine/rules/v3/`.
 */
export type {
  ConsistencyCheck,
  InsuranceNorm,
  PinnedCitation,
  RegulatorModelForm,
  StatutoryClauseRequirement,
  SubprocessorRequirement,
  TransferMechanism,
  TransferMechanismKind,
  V3DkbNode,
  V3NodeType,
} from "./types.js";

export {
  ConsistencyCheckSchema,
  InsuranceNormSchema,
  PinnedCitationSchema,
  RegulatorModelFormSchema,
  StatutoryClauseRequirementSchema,
  SubprocessorRequirementSchema,
  TransferMechanismSchema,
  V3DkbNodeListSchema,
  V3DkbNodeSchema,
  parseV3Node,
} from "./schema.js";
