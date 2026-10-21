/**
 * Wire an asserted readability standard into a run (add-readability-measure).
 * No assertion, no change: the run, its rules and its hash are what they were.
 */
import type { Rule } from "../engine/finding.js";
import { READABILITY_RULES } from "./rules.js";
import { readabilityStandard, type ReadabilityStandard } from "./standards.js";

export type ReadabilityWiring = {
  rules: readonly Rule[];
  options?: { readability_standard: ReadabilityStandard };
  asserted_readability?: string;
};

export function activateReadability(
  asserted: string | undefined,
  baseRules: readonly Rule[],
): ReadabilityWiring {
  const std = asserted ? readabilityStandard(asserted) : undefined;
  if (!std) return { rules: baseRules };
  return {
    rules: [...baseRules, ...READABILITY_RULES],
    options: { readability_standard: std },
    asserted_readability: std.id,
  };
}
