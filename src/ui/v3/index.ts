/**
 * v3 UI extensions barrel (spec-v3.md §§60–63).
 */

export {
  detectV3Family,
  type V3Family,
  type V3Detection,
  type DetectionSignal,
} from "./auto-detect.js";

export {
  defaultFramesForPlaybook,
  toggleFrame,
  ALL_FRAMES,
  type ComplianceFrame,
  type FrameDefaults,
} from "./compliance-frame.js";

export {
  EMPTY_MULTI_DOC_STATE,
  MAX_DOCUMENTS,
  addDocument,
  removeDocument,
  markAnalyzing,
  markComplete,
  markError,
  setConsistencyEnabled,
  setConsistencyFindingsCount,
  isReadyForConsistency,
  hasUsableConsistencyBundle,
  type AddDocumentResult,
  type DocumentCard,
  type MultiDocState,
} from "./multi-doc.js";

export {
  EMPTY_STATE_COPY,
  V3_ERROR_COPY,
  v3ErrorMessage,
  type V3ErrorCode,
  type V3ErrorMessage,
} from "./copy.js";
