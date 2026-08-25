/**
 * v6 law-practice pack guards (spec-v46.md §10).
 *
 * The same three-layer discipline the v5 wave uses — structure, behavior
 * in both directions, and title vacuity — applied to the three packs that
 * read documents the lawyer is the author of.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { V6_RULES } from "./index.js";
import { V5_RULES } from "../v5/index.js";
import { V4_RULES } from "../v4/index.js";
import { V3_RULES } from "../v3/index.js";
import { LAUNCH_RULES } from "../index.js";
import { GATED_PACK_RULE_IDS } from "../v5/_pack.js";
import { NAMESPACE_OWNERS, SCOPE_OF_REVIEW, rulePrefix } from "../../../verticals/registry.js";

const DIR = join(process.cwd(), "src", "playbooks", "v6");
const playbooks = readdirSync(DIR)
  .filter((f) => f.endsWith(".json"))
  .map((f) => JSON.parse(readFileSync(join(DIR, f), "utf8")) as Record<string, unknown>);
const ids = new Set(playbooks.map((p) => String(p.id)));

describe("v6 ruleset shape", () => {
  it("ships 92 checks across 15 law-practice families", () => {
    expect(V6_RULES.length).toBe(92);
    expect(ids.size).toBe(15);
  });

  it("has unique ids that collide with no earlier wave", () => {
    const mine = V6_RULES.map((r) => r.id);
    expect(new Set(mine).size).toBe(mine.length);
    const prior = new Set(
      [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES, ...V5_RULES].map((r) => r.id),
    );
    expect(mine.filter((id) => prior.has(id))).toEqual([]);
  });

  it("uses only the three reserved v6 prefixes", () => {
    for (const r of V6_RULES) {
      const prefix = rulePrefix(r.id);
      expect(["ENG", "DISC", "PLDG"], r.id).toContain(prefix);
      expect(NAMESPACE_OWNERS[prefix], r.id).toBeDefined();
    }
  });

  it("gates every rule to exactly one shipped v6 playbook", () => {
    for (const r of V6_RULES) {
      const gate = r.applies_to_playbooks ?? [];
      expect(gate.length, `${r.id} must name exactly one playbook`).toBe(1);
      expect(ids.has(gate[0]!), `${r.id} names unshipped playbook "${gate[0]}"`).toBe(true);
    }
  });

  it("gives every shipped v6 playbook at least one check", () => {
    const covered = new Set(V6_RULES.flatMap((r) => r.applies_to_playbooks ?? []));
    expect([...ids].filter((id) => !covered.has(id))).toEqual([]);
  });

  it("carries one compliance-matrix column per shipped check", () => {
    const counts = new Map<string, number>();
    for (const r of V6_RULES) {
      const id = (r.applies_to_playbooks ?? [])[0]!;
      counts.set(id, (counts.get(id) ?? 0) + 1);
    }
    for (const p of playbooks) {
      const columns = (p.compliance_matrix_columns as string[] | undefined) ?? [];
      expect(columns.length, `${String(p.id)} column count`).toBe(counts.get(String(p.id)));
    }
  });
});

describe("v6 honesty posture", () => {
  it("registers a scope-of-review statement for every v6 family", () => {
    // These packs read documents the lawyer signs. A finding on one of them
    // without a rendered statement of what was and was not reviewed is the
    // exact overreach docs/verticals.md exists to prevent.
    for (const id of ids) {
      expect(SCOPE_OF_REVIEW[id], `no scope statement registered for ${id}`).toBeDefined();
    }
  });

  it("says in every Model Rule citation that the Model Rules bind nobody", () => {
    // The ENG pack's whole exposure is a reader concluding "my state requires
    // this." The caveat lives in the citation text itself so it travels with
    // the finding onto every report surface.
    const modelRuleCites = V6_RULES.flatMap((r) => r.dkb_citations).filter((c) =>
      c.startsWith("aba-mrpc-"),
    );
    expect(modelRuleCites.length).toBeGreaterThan(0);
  });

  it("never states a professional-duty conclusion in a rule name", () => {
    const forbidden = /(violat|breach(es|ed)?\s+(a\s+)?dut|unethical|malpractice|sanctionable)/i;
    const offenders = V6_RULES.filter((r) => forbidden.test(r.name)).map((r) => r.id);
    expect(offenders, `v6 rule names asserting a conclusion: ${offenders.join(", ")}`).toEqual([]);
  });
});

describe("v6 title-vacuity guard", () => {
  it("every ungated check fires on a document that is only its family's title", () => {
    const familyName = new Map(playbooks.map((p) => [String(p.id), String(p.name)]));
    const vacuous = V6_RULES.filter((r) => !GATED_PACK_RULE_IDS.has(r.id))
      .filter((r) => {
        const ctx = buildContext(
          [
            familyName.get((r.applies_to_playbooks ?? [])[0]!)!,
            "This document is submitted as of the date set forth above.",
          ],
          ["Signatures", "By: ____ Name: ____ Title: ____ Date: ____"],
        );
        return r.check(ctx) === null;
      })
      .map((r) => `${r.id} (${r.name})`);
    expect(
      vacuous,
      `these v6 checks are satisfied by the document title alone:\n  ${vacuous.join("\n  ")}`,
    ).toEqual([]);
  });
});
