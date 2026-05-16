/**
 * Consistency rule registry barrel (spec-v3.md §27).
 */

export {
  CONSISTENCY_RULES,
  CC_001_BAA_PURPOSE,
  CC_002_DPA_PURPOSE,
  CC_003_DPA_CATEGORIES,
  CC_004_BAA_TERM,
  CC_005_GOVERNING_LAW,
  CC_006_NOTICE,
  CC_007_ORDER_OF_PRECEDENCE,
} from "./rules.js";

export {
  V4_CROSS_RULES,
  CROSS_PARTY_001,
  CROSS_JURIS_001,
  CROSS_DEFTERM_001,
  CROSS_DATE_001,
  CROSS_AMOUNT_001,
  CROSS_MISSING_001,
  CROSS_PRECEDENCE_001,
} from "./v4/index.js";

import { CONSISTENCY_RULES as V3_CC } from "./rules.js";
import { V4_CROSS_RULES as V4_CROSS } from "./v4/index.js";
import type { ConsistencyRule } from "../types.js";

/**
 * Aggregate of every consistency rule shipping today: v3 CC-NNN + v4
 * CROSS-NNN. The runner sorts by id, so the CC- and CROSS- groups
 * cluster naturally at execution time.
 */
export const ALL_CONSISTENCY_RULES: readonly ConsistencyRule[] = [...V3_CC, ...V4_CROSS];
