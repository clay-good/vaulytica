/**
 * A v3/v4 presence check must be able to fire on its own family's document.
 *
 * A presence rule whose pattern is a word from its family's TITLE can never
 * report the clause missing, because the title is always there. The check is
 * not merely weak — it is INVISIBLE: it reports nothing on a document that
 * contains nothing, which is indistinguishable from a document that is
 * clean.
 *
 * The v5/v6 packs have had this guard since the title-vacuity sweep, which
 * found 27 real instances. The 991 v3/v4 rules never had one, and the sweep
 * below finds 51 more. The SNDA trio is fixed (see
 * `real-estate/snda-title-vacuity.test.ts`) — its playbook is named
 * "SNDA (Subordination, Non-Disturbance, Attornment)" and its three checks
 * were spelled /subordinat/i, /non.disturbance/i, and /attorn/i, the latter
 * also matching every "attorney" in the document.
 *
 * A check that cannot fire is not a check. This sweep is what keeps the
 * next one from shipping.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildContext } from "../../src/engine/_test-fixtures.js";
import { V3_RULES } from "../../src/engine/rules/v3/index.js";
import { V4_RULES } from "../../src/engine/rules/v4/index.js";
import {
  V4_PRESENCE_RULE_IDS,
  V4_GATED_PRESENCE_RULE_IDS,
} from "../../src/engine/rules/v4/_helpers.js";

const familyName = new Map<string, string>();
for (const wave of ["v3", "v4", "v5", "v6"]) {
  let files: string[] = [];
  try {
    files = readdirSync(join(process.cwd(), "src", "playbooks", wave));
  } catch {
    continue;
  }
  for (const file of files) {
    if (!file.endsWith(".json")) continue;
    const pb = JSON.parse(
      readFileSync(join(process.cwd(), "src", "playbooks", wave, file), "utf8"),
    ) as { id: string; name: string };
    familyName.set(pb.id, pb.name);
  }
}

/**
 * Known-vacuous checks, each satisfied by a word in its own family's name.
 * Debt, not design. Repair pattern: replace the title word with the clause's
 * OPERATIVE shape, then add a both-directions test beside the rules file.
 * This list may only shrink.
 */
/**
 * Known-vacuous checks, each satisfied by a word in its own family's name.
 *
 * Now EMPTY. All 51 were repaired across four commits: the SNDA trio, the
 * nine compliance policies, the six securities filings, the fourteen
 * construction / insurance / estate / healthcare checks, and the nineteen
 * remaining. Every repair is paired with a compliant-direction case in
 * `v34-vacuity-repairs.test.ts` or beside its own rules file.
 *
 * Adding to this list means shipping a check that cannot fire. Don't.
 */
const KNOWN_VACUOUS = new Set<string>([]);

describe("v3/v4 presence checks can fire on their own family", () => {
  it("no ungated presence check is satisfied by its family's title alone", () => {
    const vacuous: string[] = [];
    let checked = 0;
    for (const r of [...V3_RULES, ...V4_RULES]) {
      if (!V4_PRESENCE_RULE_IDS.has(r.id)) continue;
      if (V4_GATED_PRESENCE_RULE_IDS.has(r.id)) continue;
      const title = familyName.get((r.applies_to_playbooks ?? [])[0]!);
      if (!title) continue;
      checked += 1;
      // The family title and one wholly unrelated sentence. A presence check
      // silent HERE is answered by its own name.
      const ctx = buildContext([
        title,
        "The parties met on a Tuesday and discussed the weather at some length.",
      ]);
      if (r.check(ctx) === null && !KNOWN_VACUOUS.has(r.id)) {
        vacuous.push(`${r.id}  (${title})  ${r.name}`);
      }
    }
    expect(checked, "the sweep found no presence rules — it is broken").toBeGreaterThan(500);
    expect(
      vacuous.sort(),
      `satisfied by their own family's title, so unable to fire:\n  ${vacuous.sort().join("\n  ")}`,
    ).toEqual([]);
  }, 120_000);

  it("every listed check is still vacuous, so the list cannot outlive its entries", () => {
    // A repaired rule must be REMOVED from the list, or the list silently
    // permits the defect to come back.
    const repaired: string[] = [];
    for (const r of [...V3_RULES, ...V4_RULES]) {
      if (!KNOWN_VACUOUS.has(r.id)) continue;
      const title = familyName.get((r.applies_to_playbooks ?? [])[0]!);
      if (!title) continue;
      const ctx = buildContext([
        title,
        "The parties met on a Tuesday and discussed the weather at some length.",
      ]);
      if (r.check(ctx) !== null) repaired.push(r.id);
    }
    expect(
      repaired.sort(),
      `these are fixed — remove them from KNOWN_VACUOUS: ${repaired.sort().join(", ")}`,
    ).toEqual([]);
  }, 120_000);
});
