/**
 * Filing-format-lint pack barrel (add-filing-format-lint). Unlike v3/v4 packs,
 * `FILING_RULES` is NOT spread into the always-on catalog: the pipeline appends
 * it only when a court profile is selected, so a document analyzed without
 * `--court` sees exactly the pre-existing rule set and its hash is unchanged.
 */
export { FILING_RULES, FILING_PLAYBOOK_IDS } from "./rules.js";
export { CITE_RULES } from "./cite-rules.js";
