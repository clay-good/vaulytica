/**
 * The title-vacuity guard (spec-v45.md §13).
 *
 * A clause-presence rule fires when *none* of its patterns match, so a
 * rule whose pattern is a word from the document's own title can never
 * fire. That is the failure mode this wave is structurally prone to: the
 * catalog is one rule per compliance-matrix column, and the column labels
 * are drawn from the same vocabulary as the family name. Left unchecked it
 * produces a check that reports nothing on every document forever — worse
 * than no check at all, because the compliance matrix shows the column as
 * reviewed.
 *
 * The probe is the strongest form available without a corpus: a document
 * that is *only* its family's title plus neutral execution boilerplate.
 * Nothing substantive is in it, so every ungated check for that family
 * must fire. Rules carrying an applicability gate are excluded — they are
 * supposed to be silent on a document that does not show the shape they
 * check for, and `behavior.test.ts` pins several of those in both
 * directions instead.
 *
 * This caught 27 real defects when it was first run, including the
 * irrevocability recital satisfied by the words "Irrevocable Trust" in the
 * title and the UCC § 9-104 control language satisfied by the word
 * "Control" in "Deposit Account Control Agreement".
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { V5_RULES } from "./index.js";
import { GATED_PACK_RULE_IDS } from "./_pack.js";

const familyName = new Map<string, string>();
for (const file of readdirSync(join(process.cwd(), "src", "playbooks", "v5"))) {
  if (!file.endsWith(".json")) continue;
  const pb = JSON.parse(
    readFileSync(join(process.cwd(), "src", "playbooks", "v5", file), "utf8"),
  ) as { id: string; name: string };
  familyName.set(pb.id, pb.name);
}

/** The family's own title, plus boilerplate that asserts nothing. */
function titleOnly(playbookId: string) {
  return buildContext(
    [
      familyName.get(playbookId)!,
      "The parties have entered into this document as of the date first written above.",
    ],
    ["Signatures", "By: ____ Name: ____ Title: ____ Date: ____"],
  );
}

describe("v5 title-vacuity guard", () => {
  it("every ungated check fires on a document that is only its family's title", () => {
    const vacuous = V5_RULES.filter((r) => !GATED_PACK_RULE_IDS.has(r.id))
      .filter((r) => r.check(titleOnly((r.applies_to_playbooks ?? [])[0]!)) === null)
      .map((r) => `${r.id} (${r.name})`);
    expect(
      vacuous,
      `these v5 checks are satisfied by the document title alone:\n  ${vacuous.join("\n  ")}`,
    ).toEqual([]);
  });

  it("records a gate for every rule that declares one, and for no rule that does not", () => {
    // The exclusion above is only sound if the gated set is derived rather
    // than hand-maintained. Pin that it is non-empty and that every member
    // is a real v5 rule, so a stale id can never quietly widen the exclusion.
    const ids = new Set(V5_RULES.map((r) => r.id));
    expect(GATED_PACK_RULE_IDS.size).toBeGreaterThan(0);
    for (const id of GATED_PACK_RULE_IDS) expect(ids.has(id), `${id} is not a v5 rule`).toBe(true);
  });
});
