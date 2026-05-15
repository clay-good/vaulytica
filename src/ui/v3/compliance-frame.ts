/**
 * Compliance-frame chip-row defaults (spec-v3.md §61).
 *
 * The compliance frame is a row of toggle chips next to the playbook
 * selector. Each chip names a regulator (HIPAA / GDPR / UK GDPR / CCPA /
 * state-X / sectoral-X). Toggling a chip adds or removes that regulator's
 * rule set from the run. The defaults are inferred from the playbook but
 * are always user-overridable.
 *
 * Defaults per spec:
 *
 *   - DPA → GDPR + CCPA on (most US DPAs cover both)
 *   - BAA → HIPAA on
 *   - MSA → all off (an MSA is rarely the privacy document; the UI hint
 *     "looking for GDPR coverage? add a DPA" is rendered separately)
 *   - SCC → GDPR + UK-GDPR on
 *   - UK IDTA → UK-GDPR on
 *   - COI → no compliance frames; insurance is its own dimension
 *   - vendor security, AI, EULA, ToS, privacy policy → context-dependent
 *
 * Pure module. No IO. No DOM coupling. The UI consumes the output to
 * render the chip row; the engine consumes the output to filter
 * `applies_to_playbooks` further if the user disables a frame.
 */

export type ComplianceFrame =
  | "HIPAA"
  | "GDPR"
  | "UK-GDPR"
  | "CCPA"
  | "VCDPA"
  | "CPA"
  | "CTDPA"
  | "UCPA"
  | "TDPSA"
  | "OCPA"
  | "DPDPA"
  | "GLBA"
  | "FERPA"
  | "PIPEDA"
  | "LGPD"
  | "APPI"
  | "PIPL"
  | "NIST-AI-RMF"
  | "EU-AI-Act"
  | "FTC-ROSCA";

export type FrameDefaults = {
  /** Frames toggled on by default for this playbook. */
  on: ComplianceFrame[];
  /** Frames offered in the chip row but not toggled on. */
  available: ComplianceFrame[];
  /**
   * One-line UI hint shown next to the chip row when the playbook does
   * not enable any frames by default (e.g. MSA).
   */
  hint?: string;
};

/** All frames the v3 UI ever shows. Order is the display order in the chip row. */
export const ALL_FRAMES: ComplianceFrame[] = [
  "HIPAA",
  "GDPR",
  "UK-GDPR",
  "CCPA",
  "VCDPA",
  "CPA",
  "CTDPA",
  "UCPA",
  "TDPSA",
  "OCPA",
  "DPDPA",
  "GLBA",
  "FERPA",
  "PIPEDA",
  "LGPD",
  "APPI",
  "PIPL",
  "NIST-AI-RMF",
  "EU-AI-Act",
  "FTC-ROSCA",
];

const US_STATE_PRIVACY: ComplianceFrame[] = [
  "CCPA",
  "VCDPA",
  "CPA",
  "CTDPA",
  "UCPA",
  "TDPSA",
  "OCPA",
  "DPDPA",
];

export function defaultFramesForPlaybook(playbookId: string): FrameDefaults {
  const id = playbookId.toLowerCase();

  // BAA family
  if (id === "baa" || id.startsWith("baa-")) {
    return { on: ["HIPAA"], available: ALL_FRAMES };
  }

  // DPA family — EU GDPR + CCPA on by default (most US-anchored DPAs cover both).
  if (id === "dpa" || id === "dpa-controller-processor" || id === "dpa-processor-subprocessor") {
    return { on: ["GDPR", "CCPA"], available: ALL_FRAMES };
  }
  if (id === "dpa-ccpa-service-provider") {
    return { on: ["CCPA", ...US_STATE_PRIVACY.filter((f) => f !== "CCPA")], available: ALL_FRAMES };
  }
  if (id === "dpa-multi-state-us") {
    return { on: US_STATE_PRIVACY, available: ALL_FRAMES };
  }

  // SCC family
  if (id.startsWith("scc-")) {
    return { on: ["GDPR", "UK-GDPR"], available: ALL_FRAMES };
  }

  // UK IDTA
  if (id === "uk-idta-addendum") {
    return { on: ["UK-GDPR"], available: ALL_FRAMES };
  }

  // MSA family — all off, with a hint.
  if (id.startsWith("msa-") || id === "msa-general") {
    return {
      on: [],
      available: ALL_FRAMES,
      hint: "Looking for GDPR or HIPAA coverage? Add a companion DPA or BAA.",
    };
  }

  // Vendor security addendum
  if (id === "vendor-security-addendum") {
    return { on: [], available: ALL_FRAMES, hint: "Pair with a DPA or BAA for regulator coverage." };
  }

  // AI addendum
  if (id === "ai-addendum") {
    return { on: ["NIST-AI-RMF", "EU-AI-Act"], available: ALL_FRAMES };
  }

  // EULA / ToS / privacy-policy / COI — context-dependent.
  if (id === "saas-tos") {
    return { on: ["FTC-ROSCA"], available: ALL_FRAMES };
  }
  if (id === "privacy-policy-lint") {
    return { on: ["GDPR", "CCPA"], available: ALL_FRAMES };
  }
  if (id === "eula" || id === "coi") {
    return { on: [], available: ALL_FRAMES };
  }

  // NDA family — no compliance frames apply.
  if (id.includes("nda")) {
    return { on: [], available: ALL_FRAMES };
  }

  // Generic / unknown playbook — start with everything off.
  return { on: [], available: ALL_FRAMES };
}

/**
 * Toggle one frame in a current state. Returns a new array; never mutates.
 * Used by the UI chip-row click handler.
 */
export function toggleFrame(
  current: readonly ComplianceFrame[],
  frame: ComplianceFrame,
): ComplianceFrame[] {
  if (current.includes(frame)) return current.filter((f) => f !== frame);
  return [...current, frame];
}
