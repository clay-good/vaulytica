/**
 * A conjunction must be satisfiable by a COMPLIANT clause.
 *
 * `require_all_present` (v4) and `all: true` (v5/v6) turn a pattern list into
 * PILLARS that must all be met. Getting that wrong is invisible from inside
 * the suite: the rule still fires on a bad document, and it also fires on a
 * good one, so the only way to see it is to write the clause the rule's own
 * recommendation asks for and check the rule goes quiet.
 *
 * These are the ones that did not. Every row below was a real defect — a
 * column that could not be satisfied by the drafting it exists to bless —
 * found by sweeping every conjunction in the catalog for one whose own
 * recommendation text does not satisfy it, then writing the clause by hand.
 *
 * The list is a floor, not a ceiling: add a row whenever a conjunction is
 * repaired, and the repair stays repaired.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../src/engine/_test-fixtures.js";
import { V4_RULES } from "../../src/engine/rules/v4/index.js";
import { V5_RULES } from "../../src/engine/rules/v5/index.js";
import { V6_RULES } from "../../src/engine/rules/v6/index.js";
import type { Rule } from "../../src/engine/finding.js";
import { COMPLIANT } from "./_conjunction-fixtures.js";

const ALL: Rule[] = [...V4_RULES, ...V5_RULES, ...V6_RULES];
const rule = (id: string): Rule => {
  const r = ALL.find((x) => x.id === id);
  if (!r) throw new Error(`no rule ${id}`);
  return r;
};

describe("a conjunction is satisfiable by the clause it asks for", () => {
  it.each(COMPLIANT)("%s is silent on a compliant clause", (id, heading, clause) => {
    const ctx = buildContext(
      [heading, clause],
      ["Signatures", "By: ____ Name: ____ Title: ____ Date: ____"],
    );
    const finding = rule(id).check(ctx);
    expect(finding, `${id} fired: ${finding?.title ?? ""}`).toBeNull();
  });

  it("every row names a rule that still exists", () => {
    for (const [id] of COMPLIANT) expect(() => rule(id), id).not.toThrow();
  });
});
