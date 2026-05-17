/**
 * Per-fail-fixture sanity guards for the v3 corpus.
 *
 * Each entry pins down the rule IDs that MUST fire for a given
 * `*-fail.txt` fixture. The golden test catches byte-level drift; this
 * test catches *semantic* drift — e.g. a regex tweak that silently
 * stops a critical rule from firing on the intended failure mode.
 *
 * Pass-fixtures live alongside but carry no sanity entries — the
 * golden test already locks them down structurally.
 */

import { describe, expect, it } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { runV3Fixture } from "./_pipeline.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "fixtures");

const EXPECTED_RULE_IDS: Record<string, string[]> = {
  // BAA missing the §164.504(e)(2)(ii)(D) subcontractor flow-down clause.
  // BAA-018 is the Security Rule subcontractor-flow-down detector and
  // is the load-bearing critical for this fail-fixture.
  "baa-missing-subcontractor-flow-down-fail.txt": ["BAA-018"],

  // Mutual NDA with the DTSA whistleblower-immunity notice removed —
  // 18 U.S.C. § 1833(b) requires the notice in any agreement governing
  // trade secrets. NDA-D-001 is the presence check, NDA-D-002 the
  // completeness check.
  "mutual-nda-deep-missing-dtsa-fail.txt": ["NDA-D-001", "NDA-D-002"],

  // Article 28(3)(a) GDPR DPA with the documented-instructions clause
  // removed. DPA-007 is the load-bearing critical; the controller-side
  // duty in DPA-006 also fires because removing §4 also lost the
  // "Controller shall provide Processor with documented instructions"
  // sentence.
  "dpa-controller-processor-missing-documented-instructions-fail.txt": [
    "DPA-007",
    "DPA-006",
  ],

  // AI Addendum that explicitly permits training on Customer Data on
  // an opt-out basis. ADDENDA-011 fires (critical) per FTC enforcement
  // posture on AI-training disclosures; IPDATA-009 also fires because
  // the broader v2 AI / model-training detector matches the same text.
  "ai-addendum-training-without-optin-fail.txt": [
    "ADDENDA-011",
    "IPDATA-009",
  ],
};

describe("v3 fixture sanity", () => {
  for (const [fixture, expectedIds] of Object.entries(EXPECTED_RULE_IDS)) {
    it(`${fixture} fires the expected rules`, async () => {
      const { run } = await runV3Fixture(join(FIXTURES, fixture));
      const firedIds = new Set(run.findings.map((f) => f.rule_id));
      const missing = expectedIds.filter((id) => !firedIds.has(id));
      expect(missing, `expected rules did not fire: ${missing.join(", ")}`).toEqual([]);
    });
  }
});
