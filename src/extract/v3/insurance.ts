/**
 * v3 insurance amount, AM-Best rating, and endorsement extractor — placeholder.
 *
 * Spec: spec-v3.md §25.
 *
 * For contract insurance schedules, will extract:
 *   - per-line-of-coverage amounts
 *   - per-occurrence vs. aggregate
 *   - required endorsements by ISO form number (CG 20 10, CG 20 37, CG 20 26, etc.)
 *   - required carrier rating (AM Best)
 *   - required notice of cancellation
 *
 * For COIs (ACORD 25 layout), will additionally extract:
 *   - actual policy number
 *   - policy period
 *   - named insured
 *   - additional-insured language
 *   - certificate-holder block
 *   - producer block
 *
 * Implementation lands in spec-v3.md Step 30.
 */
export {};
