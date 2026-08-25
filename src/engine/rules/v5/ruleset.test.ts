/**
 * v5 ruleset structural guards (spec-v45.md §13).
 *
 * The wave is large and mechanical, which is exactly the shape in which a
 * silent structural defect survives review: a duplicated id, a rule gated
 * to a playbook that does not ship, a playbook that ships with no checks
 * at all, or a rule id colliding with the v4 range it was supposed to sit
 * above. Each of those is invisible in a diff and fatal at runtime, so
 * each is pinned here.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { V5_RULES } from "./index.js";
import { V4_RULES } from "../v4/index.js";
import { V3_RULES } from "../v3/index.js";
import { LAUNCH_RULES } from "../index.js";
import { NAMESPACE_OWNERS, rulePrefix } from "../../../verticals/registry.js";

const PLAYBOOK_DIR = join(process.cwd(), "src", "playbooks", "v5");

const v5PlaybookIds = new Set(
  readdirSync(PLAYBOOK_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.replace(/\.json$/, "")),
);

describe("v5 ruleset shape", () => {
  it("ships 605 rules across 105 US document families", () => {
    expect(V5_RULES.length).toBe(605);
    expect(v5PlaybookIds.size).toBe(105);
  });

  it("has unique rule ids", () => {
    const ids = V5_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("collides with no id in the launch, v3, or v4 sets", () => {
    const prior = new Set([...LAUNCH_RULES, ...V3_RULES, ...V4_RULES].map((r) => r.id));
    const collisions = V5_RULES.filter((r) => prior.has(r.id)).map((r) => r.id);
    expect(collisions, `v5 ids already used by an earlier wave: ${collisions.join(", ")}`).toEqual(
      [],
    );
  });

  it("uses only registered namespace prefixes owned by a non-launch pack", () => {
    for (const r of V5_RULES) {
      const owner = NAMESPACE_OWNERS[rulePrefix(r.id)];
      expect(owner, `${r.id}: prefix "${rulePrefix(r.id)}" is unregistered`).toBeDefined();
      expect(owner, r.id).not.toBe("launch");
    }
  });

  it("numbers every rule at or above its wave floor", () => {
    // v4 stops at or below -080 in each sub-domain prefix, and at EST-304 for
    // the assertion-gated estate deepening. v5 therefore starts at -101, and
    // at EST-401 for trust/estate. A rule numbered below its floor would sit
    // inside a range a future v4 addition could claim.
    for (const r of V5_RULES) {
      const n = Number(r.id.slice(r.id.indexOf("-") + 1));
      const floor = r.id.startsWith("EST-") ? 401 : 101;
      expect(n, `${r.id} is numbered below the v5 floor of ${floor}`).toBeGreaterThanOrEqual(floor);
    }
  });

  it("every rule has a non-empty version, name, category, and description", () => {
    for (const r of V5_RULES) {
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.name.length, r.id).toBeGreaterThan(0);
      expect(r.category.length, r.id).toBeGreaterThan(0);
      expect(r.description.length, r.id).toBeGreaterThan(0);
    }
  });

  it("every rule cites exactly one source", () => {
    for (const r of V5_RULES) expect(r.dkb_citations.length, r.id).toBe(1);
  });
});

describe("v5 gating", () => {
  it("gates every rule to exactly one shipped v5 playbook", () => {
    for (const r of V5_RULES) {
      const gate = r.applies_to_playbooks ?? [];
      expect(gate.length, `${r.id} must name exactly one playbook`).toBe(1);
      expect(v5PlaybookIds.has(gate[0]!), `${r.id} names unshipped playbook "${gate[0]}"`).toBe(
        true,
      );
    }
  });

  it("declares no assertion gate (the whole wave is playbook-gated)", () => {
    for (const r of V5_RULES) expect(r.assertion_gate, r.id).toBeUndefined();
  });

  it("gives every shipped v5 playbook at least one check", () => {
    const covered = new Set(V5_RULES.flatMap((r) => r.applies_to_playbooks ?? []));
    const bare = [...v5PlaybookIds].filter((id) => !covered.has(id));
    expect(bare, `v5 playbooks with no rules: ${bare.join(", ")}`).toEqual([]);
  });

  it("never gates a v5 rule to a pre-v5 playbook", () => {
    // A v5 rule reaching an already-shipped family would change that
    // family's result_hash — the one thing the additivity contract forbids.
    const offenders = V5_RULES.filter((r) =>
      (r.applies_to_playbooks ?? []).some((p) => !v5PlaybookIds.has(p)),
    ).map((r) => r.id);
    expect(offenders).toEqual([]);
  });
});

describe("v5 playbooks", () => {
  const playbooks = readdirSync(PLAYBOOK_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => JSON.parse(readFileSync(join(PLAYBOOK_DIR, f), "utf8")) as Record<string, unknown>);

  it("names the US jurisdiction on every family", () => {
    for (const p of playbooks) {
      expect(p.applicable_jurisdictions, String(p.id)).toEqual(["US"]);
    }
  });

  it("carries one compliance-matrix column per shipped check", () => {
    // The catalog was designed column-first: each column is one rule. A
    // mismatch means either a column shipped without a check behind it, or
    // a check exists that the compliance matrix will not show.
    const counts = new Map<string, number>();
    for (const r of V5_RULES) {
      const id = (r.applies_to_playbooks ?? [])[0]!;
      counts.set(id, (counts.get(id) ?? 0) + 1);
    }
    for (const p of playbooks) {
      const columns = (p.compliance_matrix_columns as string[] | undefined) ?? [];
      expect(columns.length, `${String(p.id)} column count`).toBe(counts.get(String(p.id)));
    }
  });

  it("states its own rule range in its description", () => {
    // The description is the only place a reader learns which checks a
    // family selects; it ages the moment a rule is added or removed.
    const byPlaybook = new Map<string, string[]>();
    for (const r of V5_RULES) {
      const id = (r.applies_to_playbooks ?? [])[0]!;
      if (!byPlaybook.has(id)) byPlaybook.set(id, []);
      byPlaybook.get(id)!.push(r.id);
    }
    for (const p of playbooks) {
      const ids = byPlaybook.get(String(p.id))!.slice().sort();
      const range = ids.length === 1 ? ids[0]! : `${ids[0]}..${ids[ids.length - 1]!.split("-")[1]}`;
      expect(String(p.description), String(p.id)).toContain(
        `Selects the ${range} ruleset (${ids.length} checks).`,
      );
    }
  });
});
