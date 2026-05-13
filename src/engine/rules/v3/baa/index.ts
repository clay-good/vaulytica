/**
 * BAA ruleset — spec-v3.md §28 / Step 23.
 *
 * 45 rules covering 45 C.F.R. § 164.504(e), § 164.314(a) flow-down,
 * § 164.410 breach notification, plus HHS-guidance posture rules.
 * Every rule is scoped to BAA playbooks via `applies_to_playbooks` so
 * the v2 launch suite is untouched when no BAA is active.
 */
export { BAA_RULES } from "./rules.js";
export { BAA_PLAYBOOK_IDS } from "./_helpers.js";
