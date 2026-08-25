/**
 * v6 ruleset aggregate — the law-practice packs (spec-v46.md).
 *
 * Every wave through v5 reviews a document the lawyer's *client* is a
 * party to. v6 turns the same engine on the documents the practice itself
 * produces: the engagement letter, the discovery request, the pleading.
 * That is a different legal use case, not a wider contract catalog, and it
 * is the first time Vaulytica reads a document the lawyer signs.
 *
 * Three packs, three reserved namespaces:
 *
 *   A. Law-practice engagement documents → `engagement.ts`  (`ENG`)
 *   B. Discovery instruments             → `discovery.ts`   (`DISC`)
 *   C. Pleadings                         → `pleadings.ts`   (`PLDG`)
 *
 * The honesty posture is stricter here than anywhere else in the catalog,
 * for two reasons spec-v46 §3 sets out: the ABA Model Rules are not law in
 * any jurisdiction, and local rules and standing orders routinely displace
 * the federal rule these checks read. Every citation says so, and no
 * finding asserts that a lawyer has breached a duty — only that a term the
 * rule contemplates was not found.
 *
 * Additivity is the same contract every pack honors: each rule is gated to
 * exactly one v6 playbook, so no document that matched an earlier family
 * changes its `result_hash`.
 */

import type { Rule } from "../../finding.js";
import { ENGAGEMENT_RULES } from "./engagement.js";
import { DISCOVERY_RULES } from "./discovery.js";
import { PLEADING_RULES } from "./pleadings.js";

/** The v6 ruleset aggregate. Appended after `V5_RULES` in the pipeline. */
export const V6_RULES: readonly Rule[] = [
  ...ENGAGEMENT_RULES,
  ...DISCOVERY_RULES,
  ...PLEADING_RULES,
];

export { ENGAGEMENT_RULES, DISCOVERY_RULES, PLEADING_RULES };
