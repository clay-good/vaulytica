/**
 * Per-fail-fixture sanity guards for the v4 corpus.
 *
 * Each entry pins down the rule IDs that MUST fire for a given
 * `*-fail.txt` fixture. The golden test catches byte-level drift;
 * this test catches *semantic* drift — e.g. a regex tweak that
 * silently stops a critical rule from firing on the intended failure
 * mode.
 *
 * Pass-fixtures live alongside but carry no sanity entries — the
 * golden test already locks them down structurally.
 */

import { describe, expect, it } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { runV4Fixture } from "./_pipeline.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "fixtures");

const EXPECTED_RULE_IDS: Record<string, string[]> = {
  // Bylaws with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // quorum provision, relying instead on the residual DGCL § 216
  // default rule. No "quorum" anchor appears anywhere in the
  // document. GOV-005 (critical) fires — its present_pattern
  // `/quorum/i` is no longer matched anywhere in the document.
  // DGCL § 216 supplies a majority-default if the bylaws are
  // silent, but the bylaws themselves should restate the threshold
  // explicitly; otherwise stockholders and proxy solicitors have
  // no four-corners answer to what the quorum requirement is.
  "governance-bylaws-missing-quorum-fail.txt": ["GOV-005"],

  // Executive Employment Agreement with the preamble extended by a
  // sentence that affirmatively elects not to include a separately
  // captioned severance-schedule provision, relying instead on the
  // employer's general termination-pay practices and any equity-
  // plan documents. No "severance", "salary continuation", or
  // "COBRA / continuation coverage" anchor appears anywhere in the
  // document. EMP-006 fires — its present_patterns `/severance/i`,
  // `/salary\s+continuation/i`, and `/(cobra|continuation\s+coverage)/i`
  // are no longer matched anywhere in the document. Severance terms
  // are the central economic feature of an executive agreement; a
  // generic at-will-with-no-severance contract leaves the executive
  // with no contractual hook for post-termination compensation.
  "employment-executive-missing-severance-fail.txt": ["EMP-006"],

  // Cookie Notice with the preamble extended by a sentence that
  // affirmatively elects not to include a separately captioned
  // categories-of-cookies section, relying instead on a published
  // cookie inventory and the consent-management tool. No
  // "strictly necessary / essential" / "functional / preferences" /
  // "analytics / performance / targeting / advertising" anchor
  // appears anywhere in the document. PRV-001 fires — its three
  // present_patterns
  //   `/(strictly\s+necessary|essential)/i`
  //   `/(functional|preferences?)/i`
  //   `/(analytics|performance|targeting|advertising)/i`
  // are no longer matched anywhere in the document. ePrivacy
  // Directive Art. 5(3) requires informed consent for non-strictly-
  // necessary cookies; without a categorized inventory the user
  // cannot give the granular consent the directive contemplates.
  "privacy-cookie-notice-missing-categories-fail.txt": ["PRV-001"],
};

describe("v4 fixture sanity", () => {
  for (const [fixture, expectedIds] of Object.entries(EXPECTED_RULE_IDS)) {
    it(`${fixture} fires the expected rules`, async () => {
      const { run } = await runV4Fixture(join(FIXTURES, fixture));
      const firedIds = new Set(run.findings.map((f) => f.rule_id));
      const missing = expectedIds.filter((id) => !firedIds.has(id));
      expect(missing, `expected rules did not fire: ${missing.join(", ")}`).toEqual([]);
    });
  }
});
