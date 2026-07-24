/**
 * Launch rule registry. Adding a new rule means:
 *
 *   1. Create `src/engine/rules/<category>/<RULE-ID>.ts` that exports
 *      `export const rule: Rule = {...}`.
 *   2. Add the import + reference to `LAUNCH_RULES` below.
 *   3. Cite at least one DKB entry by id in the rule's `dkb_citations`.
 *   4. Author positive + negative tests.
 *
 * The runner sorts rules lexicographically by id, so the order of this
 * array is purely a maintenance convenience.
 */

import type { Rule } from "../finding.js";

// Structural
import { rule as STRUCT_001 } from "./structural/STRUCT-001.js";
import { rule as STRUCT_002 } from "./structural/STRUCT-002.js";
import { rule as STRUCT_003 } from "./structural/STRUCT-003.js";
import { rule as STRUCT_004 } from "./structural/STRUCT-004.js";
import { rule as STRUCT_005 } from "./structural/STRUCT-005.js";
import { rule as STRUCT_006 } from "./structural/STRUCT-006.js";
import { rule as STRUCT_007 } from "./structural/STRUCT-007.js";
import { rule as STRUCT_008 } from "./structural/STRUCT-008.js";
import { rule as STRUCT_009 } from "./structural/STRUCT-009.js";
import { rule as STRUCT_010 } from "./structural/STRUCT-010.js";
import { rule as STRUCT_011 } from "./structural/STRUCT-011.js";
import { rule as STRUCT_012 } from "./structural/STRUCT-012.js";
import { rule as STRUCT_013 } from "./structural/STRUCT-013.js";
import { rule as STRUCT_014 } from "./structural/STRUCT-014.js";
import { rule as STRUCT_015 } from "./structural/STRUCT-015.js";
import { rule as STRUCT_016 } from "./structural/STRUCT-016.js";
import { rule as STRUCT_017 } from "./structural/STRUCT-017.js";
import { rule as STRUCT_018 } from "./structural/STRUCT-018.js";
import { rule as STRUCT_019 } from "./structural/STRUCT-019.js";

// Financial
import { rule as FIN_001 } from "./financial/FIN-001.js";
import { rule as FIN_002 } from "./financial/FIN-002.js";
import { rule as FIN_003 } from "./financial/FIN-003.js";
import { rule as FIN_004 } from "./financial/FIN-004.js";
import { rule as FIN_005 } from "./financial/FIN-005.js";
import { rule as FIN_006 } from "./financial/FIN-006.js";
import { rule as FIN_007 } from "./financial/FIN-007.js";
import { rule as FIN_008 } from "./financial/FIN-008.js";
import { rule as FIN_009 } from "./financial/FIN-009.js";

// Temporal
import { rule as TEMP_001 } from "./temporal/TEMP-001.js";
import { rule as TEMP_002 } from "./temporal/TEMP-002.js";
import { rule as TEMP_003 } from "./temporal/TEMP-003.js";
import { rule as TEMP_004 } from "./temporal/TEMP-004.js";
import { rule as TEMP_005 } from "./temporal/TEMP-005.js";
import { rule as TEMP_006 } from "./temporal/TEMP-006.js";
import { rule as TEMP_007 } from "./temporal/TEMP-007.js";
import { rule as TEMP_008 } from "./temporal/TEMP-008.js";
import { rule as TEMP_009 } from "./temporal/TEMP-009.js";
import { rule as TEMP_010 } from "./temporal/TEMP-010.js";
import { rule as TEMP_011 } from "./temporal/TEMP-011.js";
import { rule as TEMP_012 } from "./temporal/TEMP-012.js";

// Obligations
import { rule as OBLI_001 } from "./obligations/OBLI-001.js";
import { rule as OBLI_002 } from "./obligations/OBLI-002.js";
import { rule as OBLI_003 } from "./obligations/OBLI-003.js";
import { rule as OBLI_004 } from "./obligations/OBLI-004.js";
import { rule as OBLI_005 } from "./obligations/OBLI-005.js";
import { rule as OBLI_006 } from "./obligations/OBLI-006.js";
import { rule as OBLI_007 } from "./obligations/OBLI-007.js";
import { rule as OBLI_008 } from "./obligations/OBLI-008.js";
import { rule as OBLI_009 } from "./obligations/OBLI-009.js";

// Risk allocation
import { rule as RISK_001 } from "./risk-allocation/RISK-001.js";
import { rule as RISK_002 } from "./risk-allocation/RISK-002.js";
import { rule as RISK_003 } from "./risk-allocation/RISK-003.js";
import { rule as RISK_004 } from "./risk-allocation/RISK-004.js";
import { rule as RISK_005 } from "./risk-allocation/RISK-005.js";
import { rule as RISK_006 } from "./risk-allocation/RISK-006.js";
import { rule as RISK_007 } from "./risk-allocation/RISK-007.js";
import { rule as RISK_008 } from "./risk-allocation/RISK-008.js";
import { rule as RISK_009 } from "./risk-allocation/RISK-009.js";
import { rule as RISK_010 } from "./risk-allocation/RISK-010.js";
import { rule as RISK_011 } from "./risk-allocation/RISK-011.js";
import { rule as RISK_012 } from "./risk-allocation/RISK-012.js";
import { rule as RISK_013 } from "./risk-allocation/RISK-013.js";
import { rule as RISK_014 } from "./risk-allocation/RISK-014.js";
import { rule as RISK_015 } from "./risk-allocation/RISK-015.js";
import { rule as RISK_016 } from "./risk-allocation/RISK-016.js";
import { rule as RISK_017 } from "./risk-allocation/RISK-017.js";

// Choice & venue
import { rule as CHOICE_001 } from "./choice-and-venue/CHOICE-001.js";
import { rule as CHOICE_002 } from "./choice-and-venue/CHOICE-002.js";
import { rule as CHOICE_003 } from "./choice-and-venue/CHOICE-003.js";
import { rule as CHOICE_004 } from "./choice-and-venue/CHOICE-004.js";
import { rule as CHOICE_005 } from "./choice-and-venue/CHOICE-005.js";
import { rule as CHOICE_006 } from "./choice-and-venue/CHOICE-006.js";
import { rule as CHOICE_007 } from "./choice-and-venue/CHOICE-007.js";
import { rule as CHOICE_008 } from "./choice-and-venue/CHOICE-008.js";
import { rule as CHOICE_009 } from "./choice-and-venue/CHOICE-009.js";
import { rule as CHOICE_010 } from "./choice-and-venue/CHOICE-010.js";
import { rule as CHOICE_011 } from "./choice-and-venue/CHOICE-011.js";
import { rule as CHOICE_012 } from "./choice-and-venue/CHOICE-012.js";

// Termination
import { rule as TERM_001 } from "./termination/TERM-001.js";
import { rule as TERM_002 } from "./termination/TERM-002.js";
import { rule as TERM_003 } from "./termination/TERM-003.js";
import { rule as TERM_004 } from "./termination/TERM-004.js";
import { rule as TERM_005 } from "./termination/TERM-005.js";
import { rule as TERM_006 } from "./termination/TERM-006.js";
import { rule as TERM_007 } from "./termination/TERM-007.js";
import { rule as TERM_008 } from "./termination/TERM-008.js";
import { rule as TERM_009 } from "./termination/TERM-009.js";

// IP & data
import { rule as IPDATA_001 } from "./ip-and-data/IPDATA-001.js";
import { rule as IPDATA_002 } from "./ip-and-data/IPDATA-002.js";
import { rule as IPDATA_003 } from "./ip-and-data/IPDATA-003.js";
import { rule as IPDATA_004 } from "./ip-and-data/IPDATA-004.js";
import { rule as IPDATA_005 } from "./ip-and-data/IPDATA-005.js";
import { rule as IPDATA_006 } from "./ip-and-data/IPDATA-006.js";
import { rule as IPDATA_007 } from "./ip-and-data/IPDATA-007.js";
import { rule as IPDATA_008 } from "./ip-and-data/IPDATA-008.js";
import { rule as IPDATA_009 } from "./ip-and-data/IPDATA-009.js";
import { rule as IPDATA_010 } from "./ip-and-data/IPDATA-010.js";

// Personnel
import { rule as PERS_001 } from "./personnel/PERS-001.js";
import { rule as PERS_002 } from "./personnel/PERS-002.js";
import { rule as PERS_003 } from "./personnel/PERS-003.js";
import { rule as PERS_004 } from "./personnel/PERS-004.js";
import { rule as PERS_005 } from "./personnel/PERS-005.js";
import { rule as PERS_006 } from "./personnel/PERS-006.js";
import { rule as PERS_007 } from "./personnel/PERS-007.js";
import { rule as PERS_008 } from "./personnel/PERS-008.js";
import { rule as PERS_009 } from "./personnel/PERS-009.js";

// Dark patterns
import { rule as DARK_001 } from "./dark-patterns/DARK-001.js";
import { rule as DARK_002 } from "./dark-patterns/DARK-002.js";
import { rule as DARK_003 } from "./dark-patterns/DARK-003.js";
import { rule as DARK_004 } from "./dark-patterns/DARK-004.js";
import { rule as DARK_005 } from "./dark-patterns/DARK-005.js";
import { rule as DARK_006 } from "./dark-patterns/DARK-006.js";
import { rule as DARK_007 } from "./dark-patterns/DARK-007.js";
import { rule as DARK_008 } from "./dark-patterns/DARK-008.js";
import { rule as DARK_009 } from "./dark-patterns/DARK-009.js";
import { rule as DARK_010 } from "./dark-patterns/DARK-010.js";
import { rule as DARK_011 } from "./dark-patterns/DARK-011.js";
import { rule as DARK_012 } from "./dark-patterns/DARK-012.js";
import { rule as DARK_013 } from "./dark-patterns/DARK-013.js";

export const LAUNCH_RULES: readonly Rule[] = [
  // Structural — 19
  STRUCT_001,
  STRUCT_002,
  STRUCT_003,
  STRUCT_004,
  STRUCT_005,
  STRUCT_006,
  STRUCT_007,
  STRUCT_008,
  STRUCT_009,
  STRUCT_010,
  STRUCT_011,
  STRUCT_012,
  STRUCT_013,
  STRUCT_014,
  STRUCT_015,
  STRUCT_016,
  STRUCT_017,
  STRUCT_018,
  STRUCT_019,
  // Financial — 9
  FIN_001,
  FIN_002,
  FIN_003,
  FIN_004,
  FIN_005,
  FIN_006,
  FIN_007,
  FIN_008,
  FIN_009,
  // Temporal — 12
  TEMP_001,
  TEMP_002,
  TEMP_003,
  TEMP_004,
  TEMP_005,
  TEMP_006,
  TEMP_007,
  TEMP_008,
  TEMP_009,
  TEMP_010,
  TEMP_011,
  TEMP_012,
  // Obligations — 9
  OBLI_001,
  OBLI_002,
  OBLI_003,
  OBLI_004,
  OBLI_005,
  OBLI_006,
  OBLI_007,
  OBLI_008,
  OBLI_009,
  // Risk allocation — 17
  RISK_001,
  RISK_002,
  RISK_003,
  RISK_004,
  RISK_005,
  RISK_006,
  RISK_007,
  RISK_008,
  RISK_009,
  RISK_010,
  RISK_011,
  RISK_012,
  RISK_013,
  RISK_014,
  RISK_015,
  RISK_016,
  RISK_017,
  // Choice & venue — 12
  CHOICE_001,
  CHOICE_002,
  CHOICE_003,
  CHOICE_004,
  CHOICE_005,
  CHOICE_006,
  CHOICE_007,
  CHOICE_008,
  CHOICE_009,
  CHOICE_010,
  CHOICE_011,
  CHOICE_012,
  // Termination — 9
  TERM_001,
  TERM_002,
  TERM_003,
  TERM_004,
  TERM_005,
  TERM_006,
  TERM_007,
  TERM_008,
  TERM_009,
  // IP & data — 10
  IPDATA_001,
  IPDATA_002,
  IPDATA_003,
  IPDATA_004,
  IPDATA_005,
  IPDATA_006,
  IPDATA_007,
  IPDATA_008,
  IPDATA_009,
  IPDATA_010,
  // Personnel — 9
  PERS_001,
  PERS_002,
  PERS_003,
  PERS_004,
  PERS_005,
  PERS_006,
  PERS_007,
  PERS_008,
  PERS_009,
  // Dark patterns — 9
  DARK_001,
  DARK_002,
  DARK_003,
  DARK_004,
  DARK_005,
  DARK_006,
  DARK_007,
  DARK_008,
  DARK_009,
  DARK_010,
  DARK_011,
  DARK_012,
  DARK_013,
];
