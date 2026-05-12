/**
 * NDA deep ruleset — placeholder.
 *
 * Spec: spec-v3.md §32.
 *
 * Will implement ~25 rules for deep NDA analysis, including:
 *   - DTSA notice present and complete (§26 extractor).
 *   - Confidentiality term reasonable (definite term or perpetual-on-trade-secrets).
 *   - Definition of Confidential Information with all four standard exclusions.
 *   - Residuals clause present/absent — flagged for awareness.
 *   - Permitted-use scope narrow enough ("to evaluate the Purpose," not "any business purpose").
 *   - Return-or-destruction with attestation requirement.
 *   - Injunctive-relief clause (waiver of bond, irreparable-harm acknowledgment).
 *   - Governing law from a list of viable jurisdictions.
 *   - Most-favored-nation / no-precedent clause.
 *   - Non-solicitation carve-outs with general-solicitation carve-out.
 *   - Symmetry check for mutual NDAs.
 *   - Receiver-only obligation check for unilateral NDAs.
 *
 * Implementation lands in spec-v3.md Step 27.
 */
export const RULES: never[] = [];
