/**
 * MSA deep ruleset — placeholder.
 *
 * Spec: spec-v3.md §33.
 *
 * Will implement ~30 rules for deep MSA analysis, including:
 *   - Indemnification: scope, procedure, carve-outs from cap.
 *   - Limitation of liability: per-claim and aggregate caps; carve-outs; supercap structure;
 *     consequential-damages waiver; California § 1668 problem flagging.
 *   - IP: background/foreground IP allocation, feedback license, residual-knowledge.
 *   - Warranties: workmanlike, conformance, no-malicious-code, compliance, non-infringement;
 *     disclaimer of implied warranties (consistent with UCC and state law).
 *   - SLA: exists, attached or linked, has remedies, sole-and-exclusive-or-not.
 *   - Term and termination: cause, convenience, bankruptcy, effects, wind-down.
 *   - Data return / portability on termination.
 *   - Force majeure: balanced (cuts both ways).
 *   - Assignment: change-of-control, affiliates carve-out.
 *   - Governing law and venue alignment.
 *   - Order-of-precedence: explicit and internally consistent.
 *   - State-law-overlay rules via DKB node state-commercial-overlays.json.
 *
 * Implementation lands in spec-v3.md Step 28.
 */
export const RULES: never[] = [];
