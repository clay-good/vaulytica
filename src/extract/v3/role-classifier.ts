/**
 * v3 role classifier — placeholder.
 *
 * Spec: spec-v3.md §18.
 *
 * Will classify each party into one or more of {covered entity, business associate,
 * subcontractor, controller, processor, sub-processor, joint controller, third party,
 * service provider (CCPA), contractor (CCPA), service recipient, service supplier}.
 *
 * Detection strategy (in priority order):
 *   1. Explicit definitional sentences ("'Processor' means…").
 *   2. Role-establishing recitals ("Controller wishes to engage Processor to…").
 *   3. Clause-level role usage ("As a Service Provider under the CCPA, Recipient shall…").
 *   4. Small CUAD-derived classifier as fallback, with `low_confidence: true` on the finding.
 *
 * When two roles conflict, both are recorded; the report's compliance matrix shows
 * compliance against each applicable regime. Implementation lands in spec-v3.md Step 30.
 */
export {};
