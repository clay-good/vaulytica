import { describe, expect, it } from "vitest";
import { formatPlaybookDiff } from "./diff.js";

const BASE = JSON.stringify({
  schema_version: "1.0",
  catalog_version: "1.0.0",
  id: "team-standard",
  name: "Team Standard v1",
  description: "Our standard",
  custom_rules: [
    {
      id: "c1",
      title: "Indemnity present",
      description: "An indemnification clause must be present.",
      severity: "warning",
      assert: { kind: "clause_present", pattern: "indemnification" },
    },
  ],
});

const NEXT = JSON.stringify({
  schema_version: "1.0",
  catalog_version: "1.0.0",
  id: "team-standard",
  name: "Team Standard v2",
  description: "Our standard",
  custom_rules: [
    {
      id: "c1",
      title: "Indemnity present",
      description: "An indemnification clause must be present.",
      severity: "critical",
      assert: { kind: "clause_present", pattern: "indemnification" },
    },
    {
      id: "c2",
      title: "Governing law is DE or NY",
      description: "Governing law must be Delaware or New York.",
      severity: "warning",
      assert: { kind: "governing_law_in", allowed: ["us-de", "us-ny"] },
    },
  ],
});

describe("formatPlaybookDiff (spec-v8 §23 CLI surface)", () => {
  it("reports identical playbooks", () => {
    const out = formatPlaybookDiff(BASE, BASE, "markdown");
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.identical).toBe(true);
      expect(out.output).toContain("No structural differences");
    }
  });

  it("renders a Markdown diff of metadata + custom-rule changes", () => {
    const out = formatPlaybookDiff(BASE, NEXT, "markdown");
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.identical).toBe(false);
      expect(out.output).toContain("# Playbook diff:");
      expect(out.output).toContain("## Custom rules");
      expect(out.output).toContain("c2");
    }
  });

  it("renders a JSON diff when requested", () => {
    const out = formatPlaybookDiff(BASE, NEXT, "json");
    expect(out.ok).toBe(true);
    if (out.ok) {
      const parsed = JSON.parse(out.output);
      expect(parsed.identical).toBe(false);
      expect(parsed.custom_rules.added).toContain("c2");
      expect(parsed.custom_rules.changed[0]).toMatchObject({ id: "c1", fields: ["severity"] });
    }
  });

  it("surfaces schema errors with the offending side labeled, never throws", () => {
    const out = formatPlaybookDiff("{ not valid json", BASE, "markdown");
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.errors.some((e) => e.startsWith("a:"))).toBe(true);
    }
  });

  it("is deterministic", () => {
    expect(formatPlaybookDiff(BASE, NEXT, "json")).toEqual(formatPlaybookDiff(BASE, NEXT, "json"));
  });
});
