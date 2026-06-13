import { describe, expect, it } from "vitest";
import { buildClosingChecklist } from "./closing-checklist.js";
import { buildClosingChecklistMarkdown, buildClosingChecklistCsv } from "./exports.js";
import type { EngineRun, Finding } from "../engine/finding.js";

function finding(rule_id: string, title: string, section = "s1"): Finding {
  return {
    id: `${rule_id}-${section}-0`,
    rule_id,
    rule_version: "1.0.0",
    severity: "warning",
    title,
    description: title,
    excerpt: { text: "x", section_id: section, start_offset: 0, end_offset: 1 },
    explanation: "",
    source_citations: [],
    document_position: 0,
  };
}

function run(findings: Finding[]): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v0",
    playbook_id: "p",
    source_file: { name: "x.docx", sha256: "0".repeat(64), size_bytes: 1 },
    executed_at: "",
    findings,
    execution_log: [],
    result_hash: "",
  };
}

describe("buildClosingChecklist (spec-v9 §23–§24)", () => {
  it("consolidates readiness findings, in category order, ignoring unrelated rules", () => {
    const r = run([
      finding("RISK-001", "Unlimited liability"), // not a readiness rule
      finding("STRUCT-018", "Referenced attachment not present: 1", "s4"),
      finding("STRUCT-017", "Declared party with no signature line: 1", "s9"),
      finding("STRUCT-013", "Unfilled template placeholders: 2", "s2"),
    ]);
    const cl = buildClosingChecklist(r, [
      { rule_id: "HANDOFF-001", title: "Tracked changes present", count: 2 },
    ]);
    expect(cl.open_count).toBe(4);
    expect(cl.items.map((i) => i.rule_id)).toEqual([
      "STRUCT-017",
      "STRUCT-018",
      "STRUCT-013",
      "HANDOFF-001",
    ]);
    expect(cl.items.find((i) => i.rule_id === "HANDOFF-001")?.label).toMatch(/2 tracked changes/);
  });

  it("is empty (but not a certification) when no readiness item is present", () => {
    const cl = buildClosingChecklist(run([finding("RISK-001", "Unlimited liability")]));
    expect(cl.open_count).toBe(0);
    const md = buildClosingChecklistMarkdown(cl);
    expect(md).toMatch(/not a certification/i);
  });

  it("renders Markdown grouped by category and a formula-safe CSV", () => {
    const cl = buildClosingChecklist(
      run([finding("STRUCT-018", "=cmd referenced attachment", "s1")]),
    );
    const md = buildClosingChecklistMarkdown(cl);
    expect(md).toContain("# Vaulytica closing checklist");
    expect(md).toContain("## Attachments (1)");
    const csv = buildClosingChecklistCsv(cl);
    // CSV formula-injection guard prefixes a leading "=".
    expect(csv).toContain("'=cmd");
  });
});
