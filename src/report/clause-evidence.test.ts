import { describe, expect, it } from "vitest";
import { buildClauseEvidence } from "./clause-evidence.js";
import type { EngineRun, Finding } from "../engine/finding.js";

function finding(id: string, excerpt: Finding["excerpt"]): Finding {
  return {
    id,
    rule_id: "R-" + id,
    rule_version: "1.0.0",
    severity: "warning",
    title: "t",
    description: "d",
    excerpt,
    explanation: "e",
    source_citations: [],
    document_position: 0,
  };
}

function run(findings: Finding[]): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v",
    playbook_id: "p",
    source_file: { name: "f", sha256: "a".repeat(64), size_bytes: 1 },
    executed_at: "",
    findings,
    execution_log: [],
    result_hash: "b".repeat(64),
  };
}

describe("buildClauseEvidence (spec-v8 §25)", () => {
  it("classifies quoted vs bare findings and computes coverage", () => {
    const summary = buildClauseEvidence(
      run([
        finding("a", { text: "quoted clause", section_id: "s1", start_offset: 0, end_offset: 13 }),
        finding("b", { text: "", start_offset: 0, end_offset: 0 }),
        finding("c", { text: "   ", start_offset: 5, end_offset: 5 }),
      ]),
    );
    expect(summary.total).toBe(3);
    expect(summary.quoted).toBe(1);
    expect(summary.bare).toBe(2);
    expect(summary.coverage_ratio).toBe(0.3333);
    expect(summary.findings[0]!.has_quoted_excerpt).toBe(true);
    expect(summary.findings[1]!.has_quoted_excerpt).toBe(false);
  });

  it("is vacuously full coverage for zero findings", () => {
    const summary = buildClauseEvidence(run([]));
    expect(summary).toMatchObject({ total: 0, quoted: 0, bare: 0, coverage_ratio: 1 });
  });

  it("is deterministic", () => {
    const r = run([finding("a", { text: "x", start_offset: 0, end_offset: 1 })]);
    expect(JSON.stringify(buildClauseEvidence(r))).toBe(JSON.stringify(buildClauseEvidence(r)));
  });
});
