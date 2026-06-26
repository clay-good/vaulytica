import { describe, expect, it } from "vitest";
import { diffPlaybooks, diffPlaybooksMarkdown } from "./diff.js";
import type { CustomPlaybook, CustomRule } from "./custom-playbook.js";

const rule = (id: string, over: Partial<CustomRule> = {}): CustomRule => ({
  id,
  title: `Rule ${id}`,
  description: "desc",
  severity: "warning",
  assert: { kind: "clause_present", pattern: "indemnification" },
  ...over,
});

const base: CustomPlaybook = {
  schema_version: "1.0",
  catalog_version: "1.0.0",
  id: "team-standard",
  name: "Team Standard v1",
  description: "Our standard",
  mode: "augment",
  rule_selection: { include: ["NDA-001", "NDA-002"], exclude: [] },
  rule_overrides: { "NDA-003": { severity: "critical" } },
  thresholds: { liability_cap_multiple: 1 },
  required_clauses: [{ category: "confidentiality", severity: "critical" }],
  custom_rules: [rule("c1"), rule("c2")],
};

describe("diffPlaybooks (spec-v8 §23)", () => {
  it("reports no differences for identical playbooks", () => {
    const d = diffPlaybooks(base, structuredClone(base));
    expect(d.identical).toBe(true);
  });

  it("detects metadata, selection, override, threshold, clause, and custom-rule changes", () => {
    const next: CustomPlaybook = {
      ...structuredClone(base),
      name: "Team Standard v2",
      rule_selection: { include: ["NDA-001"], exclude: ["NDA-009"] },
      rule_overrides: { "NDA-003": { severity: "warning" }, "NDA-004": { skip: true } },
      thresholds: { liability_cap_multiple: 2 },
      required_clauses: [{ category: "confidentiality", severity: "warning" }],
      custom_rules: [rule("c1", { severity: "critical" }), rule("c3")],
    };
    const d = diffPlaybooks(base, next);
    expect(d.identical).toBe(false);
    expect(d.metadata.map((m) => m.field)).toContain("name");
    expect(d.rule_selection.include.removed).toEqual(["NDA-002"]);
    expect(d.rule_selection.exclude.added).toEqual(["NDA-009"]);
    expect(d.rule_overrides.changed[0]).toMatchObject({ rule_id: "NDA-003" });
    expect(d.rule_overrides.added[0]).toMatchObject({ rule_id: "NDA-004" });
    expect(d.thresholds.changed[0]).toMatchObject({
      key: "liability_cap_multiple",
      from: 1,
      to: 2,
    });
    expect(d.required_clauses.changed[0]).toMatchObject({ category: "confidentiality" });
    expect(d.custom_rules.added).toEqual(["c3"]);
    expect(d.custom_rules.removed).toEqual(["c2"]);
    expect(d.custom_rules.changed[0]).toMatchObject({ id: "c1", fields: ["severity"] });
  });

  it("is deterministic and symmetric in shape", () => {
    const next = { ...structuredClone(base), name: "v2" };
    expect(JSON.stringify(diffPlaybooks(base, next))).toBe(
      JSON.stringify(diffPlaybooks(base, next)),
    );
  });

  it("renders a Markdown summary; 'no differences' when identical", () => {
    expect(diffPlaybooksMarkdown(base, structuredClone(base))).toContain(
      "No structural differences",
    );
    const next = {
      ...structuredClone(base),
      name: "v2",
      custom_rules: [rule("c1"), rule("c2"), rule("c4")],
    };
    const md = diffPlaybooksMarkdown(base, next);
    expect(md).toContain("# Playbook diff:");
    expect(md).toContain("## Custom rules");
    expect(md).toContain("c4");
  });
});
