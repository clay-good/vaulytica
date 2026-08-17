import { describe, expect, it } from "vitest";

import { MSA_DEEP_RULES } from "./msa-deep/rules.js";
import { DPA_GDPR_RULES } from "./dpa-gdpr/rules.js";
import { TRANSFER_RULES } from "./transfer/rules.js";
import { buildContext } from "../../_test-fixtures.js";
import type { Rule } from "../../finding.js";

const ALL: Rule[] = [...MSA_DEEP_RULES, ...DPA_GDPR_RULES, ...TRANSFER_RULES];
const byId = (id: string): Rule => {
  const r = ALL.find((x) => x.id === id);
  if (!r) throw new Error(`no ${id}`);
  return r;
};

// [id, shouldFire, text]
const CASES: [string, boolean, string][] = [
  // MSA-017 — SLA credit sole-and-exclusive remedy
  [
    "MSA-017",
    false,
    "Service credits shall never be Customer's sole and exclusive remedy for any downtime.",
  ],
  [
    "MSA-017",
    false,
    "Under no circumstances shall the service credit be deemed Customer's sole and exclusive remedy.",
  ],
  [
    "MSA-017",
    false,
    "Service credits shall not be Customer's sole and exclusive remedy for any downtime.",
  ],
  [
    "MSA-017",
    true,
    "The service credit shall be Customer's sole and exclusive remedy for any downtime.",
  ],
  // MSA-024 — governing law / venue mismatch
  [
    "MSA-024",
    false,
    "This Agreement is governed by the laws of the State of New York, and venue shall never be in the State of Delaware.",
  ],
  [
    "MSA-024",
    false,
    "This Agreement is governed by the laws of the State of New York, and venue shall not be in the State of Delaware.",
  ],
  // DPA-036 — audit substitution
  [
    "DPA-036",
    false,
    "The SOC 2 report shall never be provided in lieu of any audit right, but rather as a supplement.",
  ],
  [
    "DPA-036",
    false,
    "Under no circumstances shall the SOC 2 report be in lieu of any audit; Processor shall permit an on-site audit on reasonable cause.",
  ],
  ["DPA-036", true, "The SOC 2 report shall be provided in lieu of any audit right."],
  // TRANSFER-003 — SCC materially modified
  [
    "TRANSFER-003",
    false,
    "The Standard Contractual Clauses may never be amended, modified, or varied by the parties.",
  ],
  ["TRANSFER-003", false, "Under no circumstances shall the SCCs be amended by the parties."],
  [
    "TRANSFER-003",
    true,
    "The Standard Contractual Clauses are hereby amended to reflect the parties' agreed liability cap.",
  ],
];

/**
 * "The rule accuses the compliant clause."
 *
 * A language rule's `exclude_if` guard is meant to suppress the DISCLAIMED
 * form. These four guards were written assuming the negation sits on a literal
 * "not" adjacent to the verb, so the compliant drafting each rule's own
 * recommendation asks for — phrased with "never", or with a fronted "under no
 * circumstances" — slipped past the guard, tripped a `bad_pattern`, and was
 * reported as the violation it forbids.
 *
 * Same root cause as the v4 sweep. Each case below is paired with the
 * genuinely bad clause, which must still fire.
 */
describe("v3 language rules — the compliant clause is not accused", () => {
  it.each(CASES.filter(([, want]) => !want).map(([id, , text]) => [id, text]))(
    "%s stays silent on the compliant drafting: %s",
    (id, text) => {
      expect(byId(id).check(buildContext(["Agreement", text])), id).toBeNull();
    },
  );

  it.each(CASES.filter(([, want]) => want).map(([id, , text]) => [id, text]))(
    "%s still fires on the genuinely bad clause: %s",
    (id, text) => {
      expect(byId(id).check(buildContext(["Agreement", text])), id).not.toBeNull();
    },
  );
});
