/**
 * Addenda ruleset (vendor security, AI addendum, EULA, ToS, privacy-policy, COI) — placeholder.
 *
 * Spec: spec-v3.md §34.
 *
 * Will implement ~20 rules covering:
 *
 * Vendor security addendum: specific measures listed; cadence stated; right-to-audit
 * or SOC 2 substitution; incident-response notification; vulnerability-disclosure;
 * secure-development-lifecycle; data-classification mapping; encryption standards
 * (FIPS 140-3 / AES-256); pen-test cadence.
 *
 * Subprocessor schedule: maintained URL or attached list; notice period; objection rights;
 * flow-down stated.
 *
 * AI addendum: definitions (Generative AI, Foundation Model, Output, Training Data);
 * prohibited uses (training on customer data without opt-in, etc.); transparency;
 * IP ownership of outputs; disclaimers for AI outputs (hallucination risk, human-review
 * obligation); data residency; subprocessor disclosure for AI providers;
 * deletion-of-fine-tuning-data on termination.
 *
 * Citations for AI addendum rules are to NIST AI RMF, EU AI Act high-risk categories,
 * and FTC enforcement actions — cited as "consensus practice, not statute" where applicable.
 *
 * Implementation lands in spec-v3.md Step 29.
 */
export const RULES: never[] = [];
