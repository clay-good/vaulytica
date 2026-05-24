/**
 * Compliance-frame rule filter (spec-v3.md §61, LAUNCH row v3-o follow-up).
 *
 * The compliance-frame chip row lets the user toggle which regulator
 * frameworks apply to a run. When a frame is OFF, rules tagged with
 * that frame (and no other active frame) are excluded from the engine
 * run. Rules that aren't tagged with any frame are always kept —
 * they're playbook-bound (e.g. NDA-D-*, MSA-*, STRUCT-*) rather than
 * frame-bound, and disabling HIPAA shouldn't silence the missing-
 * party-name check.
 *
 * Frame ↔ rule-id mapping is by id-prefix. This is brittle in theory
 * but stable in practice: every rule family lives in its own
 * `src/engine/rules/v3/<family>/rules.ts` directory and the prefix is
 * established when the family is created. A new family adding rules
 * with a new prefix needs a matching entry here.
 *
 * The pure functions are exported separately from the wire-up so the
 * mapping can be unit-tested without spinning up the engine.
 */

import type { Rule } from "../engine/index.js";
import type { ComplianceFrame } from "./v3/index.js";

/**
 * Rule-id prefix → set of compliance frames the prefix is gated by.
 * A rule is keepable if at least one of its prefix's frames is
 * currently active. A prefix with an empty frame array is treated as
 * "frame-bound to nothing" and ALWAYS kept regardless of toggle state.
 *
 * Spec mapping (spec-v3 §61):
 *
 *   - BAA-*       → HIPAA
 *   - DPA-*       → GDPR (EU controller↔processor)
 *   - USDPA-*     → US state privacy statutes (CCPA + 7 sister laws)
 *   - TRANSFER-*  → GDPR + UK-GDPR (SCC, UK IDTA)
 *   - ADDENDA-001..009 (vendor security)        → no frame (playbook-bound)
 *   - ADDENDA-010..016 (AI Addendum)            → NIST-AI-RMF + EU-AI-Act
 *   - ADDENDA-017..018 (EULA)                   → no frame
 *   - ADDENDA-019 (FTC Click-to-Cancel)         → FTC-ROSCA
 *   - ADDENDA-020 (privacy policy)              → GDPR + CCPA (the typical
 *     audience for a privacy policy is one of these two regimes)
 *
 * V1 launch rule prefixes (STRUCT, FIN, TEMP, OBLIG, RISK, CHOICE,
 * TERM, IPDATA, PERS, DARK) and V3 deep-rule prefixes (NDA-D, MSA)
 * are intentionally not in this table — they're playbook-bound and
 * always kept.
 */
type FrameMapEntry = {
  prefix: string;
  /** True when the prefix takes a numeric suffix sub-range. */
  range?: { from: number; to: number };
  frames: ComplianceFrame[];
};

const FRAME_TABLE: FrameMapEntry[] = [
  { prefix: "BAA-", frames: ["HIPAA"] },
  // DPA- but NOT USDPA-. The prefix-match function below resolves
  // longer prefixes first so USDPA- wins for USDPA-* ids.
  { prefix: "DPA-", frames: ["GDPR"] },
  {
    prefix: "USDPA-",
    frames: ["CCPA", "VCDPA", "CPA", "CTDPA", "UCPA", "TDPSA", "OCPA", "DPDPA"],
  },
  { prefix: "TRANSFER-", frames: ["GDPR", "UK-GDPR"] },
  // ADDENDA sub-ranges.
  { prefix: "ADDENDA-", range: { from: 1, to: 9 }, frames: [] }, // vendor security
  { prefix: "ADDENDA-", range: { from: 10, to: 16 }, frames: ["NIST-AI-RMF", "EU-AI-Act"] },
  { prefix: "ADDENDA-", range: { from: 17, to: 18 }, frames: [] }, // EULA
  { prefix: "ADDENDA-", range: { from: 19, to: 19 }, frames: ["FTC-ROSCA"] },
  { prefix: "ADDENDA-", range: { from: 20, to: 20 }, frames: ["GDPR", "CCPA"] }, // privacy policy
];

/**
 * Return the compliance frames a rule is gated by. Empty array means
 * the rule is playbook-bound and never filtered by frame toggles.
 */
export function framesForRule(ruleId: string): ComplianceFrame[] {
  // Sort table entries so the longest prefix wins (USDPA- vs DPA-).
  // Sorting at every call is overkill; pre-sort once at module load.
  const entry = SORTED_TABLE.find((e) => {
    if (!ruleId.startsWith(e.prefix)) return false;
    if (!e.range) return true;
    const suffix = ruleId.slice(e.prefix.length);
    const n = Number(suffix);
    if (!Number.isFinite(n)) return false;
    return n >= e.range.from && n <= e.range.to;
  });
  if (!entry) return [];
  return [...entry.frames];
}

const SORTED_TABLE: FrameMapEntry[] = [...FRAME_TABLE].sort(
  (a, b) => b.prefix.length - a.prefix.length,
);

/**
 * Filter a rule set against the currently-active compliance frames.
 * Rules whose frames are entirely disjoint from `activeFrames` are
 * dropped. Rules with no frame tag at all are always kept.
 *
 * When `activeFrames` is omitted, every rule is kept (the default,
 * preserving existing behavior for callers that don't pass the option).
 */
export function filterRulesByFrames(
  rules: ReadonlyArray<Rule>,
  activeFrames: ReadonlyArray<ComplianceFrame> | undefined,
): Rule[] {
  if (!activeFrames) return [...rules];
  const active = new Set(activeFrames);
  return rules.filter((r) => keepRule(r.id, active));
}

/** Internal: decide whether a single rule survives the frame filter. */
function keepRule(ruleId: string, active: ReadonlySet<ComplianceFrame>): boolean {
  const frames = framesForRule(ruleId);
  if (frames.length === 0) return true;
  for (const f of frames) {
    if (active.has(f)) return true;
  }
  return false;
}
