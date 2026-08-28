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
 * The rest are listed below with the title word that satisfies them. The
 * list may only SHRINK. Adding to it means shipping a check that cannot
 * fire.
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
const KNOWN_VACUOUS = new Set([
  "COMM-008",
  "COMM-019",
  "GOV-071",
  "EQT-043",
  "EQT-066",
  "MNA-039",
  "MNA-055",
  "RE-001",
  "RE-032",
  "EMP-032",
  "SET-021",
  "SET-025",
  "IPL-021",
  "IPL-025",
  "IPL-031",
  "IPL-036",
  "PRV-016",
  "PRV-023",
  "PRV-040",
  "HC-001",
  "HC-010",
  "HC-019",
  "INS-005",
  "INS-007",
  "INS-011",
  "INS-020",
  "CON-008",
  "CON-014",
  "CON-016",
  "CON-021",
  "EST-011",
  "EST-024",
  "EST-032",
  "REG-008",
  "REG-016",
  "REG-022",
  "REG-023",
  "REG-024",
  "REG-034",
]);

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
