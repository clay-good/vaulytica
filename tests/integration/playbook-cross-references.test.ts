/**
 * A playbook's pointer at another playbook has to land on one.
 *
 * `Playbook.companion_playbooks` is the catalog's only cross-reference field —
 * "suggested two-document pairings (playbook ids)", per its own doc comment.
 * 255 of the 267 shipped playbooks declare one, 335 references in all, and
 * **no consumer anywhere reads the field**. An unread field is an unchecked
 * one: `vendor-security-questionnaire` pointed at `vendor-security-bundle`, a
 * playbook that exists nowhere in the tree, and because that was its *only*
 * companion the field was wholly empty for that family with nothing to say so.
 *
 * The field's value is entirely in the pointer resolving, so the guard is
 * referential integrity — checked against the catalog a *consumer* would
 * resolve against, which is the union the runtime actually ships: the 12
 * launch playbooks under `playbooks/` plus the v3–v6 waves bundled into
 * `playbooks/extended.json`.
 *
 * 🚨 Resolving against `src/playbooks/**` alone is the trap this test was
 * written after walking into. The 12 base families (`saas-customer`,
 * `employment-at-will-us`, `lease-commercial-multitenant`, …) live ONLY under
 * `playbooks/`, and they are the most-referenced companions in the catalog —
 * so a sweep over the source dirs reports 11 dangling references, 10 of them
 * imaginary. The catalog has two roots; a guard that walks one is worse than
 * no guard, because it invents work. Same lesson as `DOCUMENT_READING_ROOTS`
 * in `_recognizer-sources.ts`.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parsePlaybook, parsePlaybooks } from "../../src/playbooks/loader.js";
import { LAUNCH_PLAYBOOK_IDS } from "../../src/playbooks/registry.js";
import type { Playbook } from "../../src/playbooks/types.js";

/** Exactly what the deployed matcher can route to: launch playbooks + the bundled waves. */
const SHIPPED: readonly Playbook[] = [
  ...LAUNCH_PLAYBOOK_IDS.map((id) =>
    parsePlaybook(JSON.parse(readFileSync(join(process.cwd(), "playbooks", `${id}.json`), "utf8"))),
  ),
  ...parsePlaybooks(
    JSON.parse(readFileSync(join(process.cwd(), "playbooks", "extended.json"), "utf8")),
  ),
];

const IDS = new Set(SHIPPED.map((p) => p.id));

describe("the shipped catalog resolves against itself", () => {
  it("has a varied, populated companion field to check", () => {
    // Anti-vacuity. A referential-integrity test over an empty relation is
    // green for the wrong reason; these numbers say the relation has content.
    expect(IDS.size, "the shipped catalog").toBeGreaterThanOrEqual(250);
    const declaring = SHIPPED.filter((p) => (p.companion_playbooks ?? []).length > 0);
    expect(declaring.length, "playbooks declaring a companion").toBeGreaterThanOrEqual(200);
    const references = declaring.reduce((n, p) => n + p.companion_playbooks!.length, 0);
    expect(references, "companion references in total").toBeGreaterThanOrEqual(300);
  });

  it("every companion_playbooks id names a playbook that exists", () => {
    const dangling: string[] = [];
    for (const p of SHIPPED) {
      for (const c of p.companion_playbooks ?? []) {
        if (!IDS.has(c)) dangling.push(`${p.id} → ${c}`);
      }
    }
    expect(dangling, "a playbook suggests a companion document the catalog cannot open").toEqual(
      [],
    );
  });

  it("no playbook is its own companion, and no companion is listed twice", () => {
    const self: string[] = [];
    const duplicated: string[] = [];
    for (const p of SHIPPED) {
      const companions = p.companion_playbooks ?? [];
      if (companions.includes(p.id)) self.push(p.id);
      if (new Set(companions).size !== companions.length) duplicated.push(p.id);
    }
    expect(self, "a playbook pairs with itself").toEqual([]);
    expect(duplicated, "a playbook lists the same companion twice").toEqual([]);
  });

  it("a declared regulator_frame is never blank", () => {
    // The field is a label, not a reference, so there is no vocabulary to
    // check it against — 195 distinct values over 255 playbooks, by design.
    // What is checkable is that a declared frame says something.
    const blank = SHIPPED.filter(
      (p) => p.regulator_frame !== undefined && p.regulator_frame.trim() === "",
    ).map((p) => p.id);
    expect(blank, "a playbook declares an empty regulatory frame").toEqual([]);
  });
});
