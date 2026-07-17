import { describe, expect, it } from "vitest";
import { diffPlaybooks, diffPlaybooksMarkdown } from "./diff.js";
import { CUSTOM_PLAYBOOK_FIELDS } from "./custom-playbook.js";
import type { CustomPlaybook, CustomRule, NegotiationPosition } from "./custom-playbook.js";

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

describe("negotiation-position drift (fix-playbook-diff-completeness)", () => {
  const position = (value: number): NegotiationPosition => ({
    dimension: "Liability cap",
    ideal: {
      kind: "numeric_threshold",
      metric: "liability_cap_multiple",
      comparator: "gte",
      value: 12,
    },
    acceptable: {
      kind: "numeric_threshold",
      metric: "liability_cap_multiple",
      comparator: "gte",
      value,
    },
  });

  it("a moved walk-away floor is drift, not 'no structural differences'", () => {
    // The live defect: acceptable floor 6 → 4 diffed as identical, exit 0 —
    // the gate silently passed drift in exactly the field the posture /
    // coherence family exists to police.
    const a = { ...structuredClone(base), negotiation_positions: [position(6)] };
    const b = { ...structuredClone(base), negotiation_positions: [position(4)] };
    const d = diffPlaybooks(a, b);
    expect(d.identical).toBe(false);
    expect(d.negotiation_positions.changed).toHaveLength(1);
    expect(d.negotiation_positions.changed[0]!.changes[0]).toBe(
      "acceptable floor for Liability cap moved 6 → 4",
    );
    const md = diffPlaybooksMarkdown(a, b);
    expect(md).toContain("## Negotiation positions");
    expect(md).toContain("acceptable floor for Liability cap moved 6 → 4");
  });

  it("added / removed positions and guidance changes are reported", () => {
    const a = { ...structuredClone(base), negotiation_positions: [position(6)] };
    const b = {
      ...structuredClone(base),
      negotiation_positions: [
        { ...position(6), guidance: { ideal: "Hold the line." } },
        { ...position(6), dimension: "Term" },
      ],
    };
    const d = diffPlaybooks(a, b);
    expect(d.negotiation_positions.added).toEqual(["Term"]);
    expect(d.negotiation_positions.changed[0]!.changes[0]).toContain("guidance");
    const back = diffPlaybooks(b, a);
    expect(back.negotiation_positions.removed).toEqual(["Term"]);
  });

  it("identical positions stay identical", () => {
    const a = { ...structuredClone(base), negotiation_positions: [position(6)] };
    expect(diffPlaybooks(a, structuredClone(a)).identical).toBe(true);
  });

  it("an intermediate-rung change is surfaced as drift (add-negotiation-ladder-playbooks)", () => {
    const withRung = (label: string): NegotiationPosition => ({
      ...position(6),
      rungs: [
        {
          label,
          predicate: {
            kind: "numeric_threshold",
            metric: "liability_cap_multiple",
            comparator: "gte",
            value: 9,
          },
        },
      ],
    });
    const a = { ...structuredClone(base), negotiation_positions: [withRung("9x cap")] };
    const b = { ...structuredClone(base), negotiation_positions: [withRung("nine times fees")] };
    const d = diffPlaybooks(a, b);
    expect(d.identical).toBe(false);
    expect(d.negotiation_positions.changed[0]!.changes).toContain(
      "intermediate rungs for Liability cap changed",
    );
  });
});

describe("diff completeness guard — every schema field has a comparator", () => {
  it("diffPlaybooks covers every top-level playbook field", () => {
    // Derived from the zod schema itself, so the NEXT field added to the
    // playbook format cannot ship un-diffed the way negotiation_positions
    // did (added at spec-v10, invisible to diff until this change).
    const COVERED: Record<string, "metadata" | "section" | "identity"> = {
      schema_version: "identity", // literal — cannot differ between valid playbooks
      catalog_version: "metadata",
      id: "identity", // carried in from/to headers
      name: "metadata",
      description: "metadata",
      mode: "metadata",
      rule_selection: "section",
      rule_overrides: "section",
      thresholds: "section",
      required_clauses: "section",
      custom_rules: "section",
      negotiation_positions: "section",
      party_roles: "section",
    };
    const missing = CUSTOM_PLAYBOOK_FIELDS.filter((f) => !(f in COVERED));
    expect(
      missing,
      `new playbook field(s) without a diff comparator — extend diffPlaybooks and this map`,
    ).toEqual([]);
  });
});
