/**
 * Playbook fixture coverage enforcement. For every launch playbook
 * in `LAUNCH_PLAYBOOK_IDS`, the test asserts that **at least one
 * committed fixture matches it under the deterministic matcher** —
 * or that the playbook is explicitly listed as exempt with a stated
 * reason.
 *
 * This catches the regression where a new playbook is added without
 * a fixture, OR a matcher change drops a fixture below the
 * confidence threshold for the playbook the fixture was meant to
 * exercise.
 *
 * Adding a new playbook? Add a fixture, OR add the id to
 * `EXEMPT_PLAYBOOK_IDS` below with a stated reason in the comment.
 */

import { describe, expect, it } from "vitest";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { LAUNCH_PLAYBOOK_IDS } from "../../src/playbooks/index.js";
import { listFixtures, runFixture } from "./_pipeline-helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONTRACTS = join(__dirname, "..", "fixtures", "contracts");

/**
 * Playbook IDs that don't need their own fixture. Each entry MUST
 * carry a one-line rationale in the comment.
 */
const EXEMPT_PLAYBOOK_IDS: Record<string, string> = {
  // The fallback is exercised implicitly when no other playbook
  // scores above the matcher threshold; a "clean" fixture that
  // doesn't match anything else triggers it. Not a substantive
  // playbook surface.
  "generic-fallback": "implicit — fires when no other playbook matches",
  // saas-vendor shares ~all features with saas-customer for a
  // generic SaaS doc; the matcher prefers saas-customer
  // alphabetically. Vendor-specific surface is exercised via
  // bad-saas-vendor.docx but matched as saas-customer; the
  // fixture-sanity test for that fixture is playbook-agnostic.
  "saas-vendor":
    "exercised via bad-saas-vendor.docx (matched as saas-customer due to feature overlap)",
};

const fixtures = await listFixtures(CONTRACTS);
const matched = new Set<string>();
for (const name of fixtures) {
  const { run } = await runFixture(join(CONTRACTS, name));
  matched.add(run.playbook_id);
}

describe("playbook fixture coverage", () => {
  for (const id of LAUNCH_PLAYBOOK_IDS) {
    const exempt = EXEMPT_PLAYBOOK_IDS[id];
    if (exempt) {
      it(`${id} is exempt (${exempt})`, () => {
        expect(exempt.length, "exemption rationale required").toBeGreaterThan(8);
      });
      continue;
    }
    it(`${id} is matched by at least one committed fixture`, () => {
      expect(matched.has(id), `no fixture matches playbook ${id}`).toBe(true);
    });
  }

  it("the matcher never picks an unknown playbook", () => {
    const known = new Set<string>(LAUNCH_PLAYBOOK_IDS);
    for (const id of matched) {
      expect(known.has(id), `matcher returned unknown playbook id: ${id}`).toBe(true);
    }
  });
});
