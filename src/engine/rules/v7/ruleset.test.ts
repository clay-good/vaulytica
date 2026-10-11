/**
 * v7 pack guards (spec-v49.md §5): one check per compliance-matrix column,
 * each gated to exactly one shipped v7 playbook, under a reserved prefix.
 * Title vacuity is held for every pack-built rule by
 * `../v5/title-vacuity.test.ts`.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { V7_RULES } from "./index.js";
import { V6_RULES } from "../v6/index.js";
import { V5_RULES } from "../v5/index.js";
import { V4_RULES } from "../v4/index.js";
import { V3_RULES } from "../v3/index.js";
import { LAUNCH_RULES } from "../index.js";
import { NAMESPACE_OWNERS, rulePrefix } from "../../../verticals/registry.js";

const DIR = join(process.cwd(), "src", "playbooks", "v7");
const playbooks = readdirSync(DIR)
  .filter((f) => f.endsWith(".json"))
  .map((f) => JSON.parse(readFileSync(join(DIR, f), "utf8")) as Record<string, unknown>);
const ids = new Set(playbooks.map((p) => String(p.id)));

describe("v7 ruleset shape", () => {
  it("has unique ids that collide with no earlier wave", () => {
    const mine = V7_RULES.map((r) => r.id);
    expect(new Set(mine).size).toBe(mine.length);
    const prior = new Set(
      [...LAUNCH_RULES, ...V3_RULES, ...V4_RULES, ...V5_RULES, ...V6_RULES].map((r) => r.id),
    );
    expect(mine.filter((id) => prior.has(id))).toEqual([]);
  });

  it("gates every rule to exactly one shipped v7 playbook, under that playbook's prefix", () => {
    for (const r of V7_RULES) {
      const gate = r.applies_to_playbooks ?? [];
      expect(gate.length, `${r.id} must name exactly one playbook`).toBe(1);
      expect(ids.has(gate[0]!), `${r.id} names unshipped playbook "${gate[0]}"`).toBe(true);
      expect(NAMESPACE_OWNERS[rulePrefix(r.id)], r.id).toBe(gate[0]);
    }
  });

  it("carries one compliance-matrix column per shipped check", () => {
    // `software-license-enterprise` selects the always-on packs and has no
    // checks of its own; its columns describe what those packs read.
    const counts = new Map<string, number>();
    for (const r of V7_RULES) {
      const id = (r.applies_to_playbooks ?? [])[0]!;
      counts.set(id, (counts.get(id) ?? 0) + 1);
    }
    expect([...counts.keys()].sort()).toEqual(
      [
        "hipaa-data-use-agreement",
        "pilot-evaluation-agreement",
        "roommate-agreement",
        "service-level-agreement",
        "software-development-agreement",
      ].sort(),
    );
    for (const p of playbooks) {
      if (!counts.has(String(p.id))) continue;
      const columns = (p.compliance_matrix_columns as string[] | undefined) ?? [];
      expect(columns.length, `${String(p.id)} column count`).toBe(counts.get(String(p.id)));
    }
  });

  it("cites the three families with no controlling authority as practice, never above a warning", () => {
    // spec-v49 §3: no statute or rule lists what these three must say.
    const PRACTICE_ONLY = new Set(["SLA", "PILOT", "ROOM"]);
    const rules = V7_RULES.filter((r) => PRACTICE_ONLY.has(rulePrefix(r.id)));
    expect(rules.length).toBeGreaterThan(0);
    for (const r of rules) {
      expect(
        r.dkb_citations.every((c) => c.startsWith("practice-")),
        r.id,
      ).toBe(true);
      expect(r.default_severity, r.id).not.toBe("critical");
    }
  });

  it("cites each data-use-agreement check to its own subparagraph of § 164.514(e)(4)(ii)", () => {
    const rules = V7_RULES.filter((r) => rulePrefix(r.id) === "DUA");
    expect(rules).toHaveLength(7);
    const cites = rules.flatMap((r) => r.dkb_citations);
    expect(new Set(cites).size).toBe(7);
    for (const c of cites) expect(c).toMatch(/^cfr-45-164-514-e-4-ii-(a|b|c-[1-5])$/);
  });
});
