/**
 * NDA-deep ruleset — spec-v3.md §32 / Step 27.
 *
 * 25 rules covering the DTSA whistleblower-immunity notice
 * (18 U.S.C. § 1833(b)), Confidential-Information definition
 * completeness, term separation, return / attestation, injunctive
 * relief, permitted-use scope, governing law, residuals flagging, and
 * mutual / unilateral symmetry checks. Every rule scopes to the
 * NDA-deep playbooks via `applies_to_playbooks` so v2 NDA behavior
 * remains unchanged.
 */
export { NDA_DEEP_RULES } from "./rules.js";
export {
  NDA_PLAYBOOK_IDS,
  NDA_MUTUAL_PLAYBOOK_IDS,
  NDA_UNILATERAL_PLAYBOOK_IDS,
} from "./_helpers.js";
