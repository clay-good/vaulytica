import { describe, expect, it } from "vitest";
import { buildClauseEvidence, clauseEvidenceSentence } from "./clause-evidence.js";
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

/**
 * The sentence, and the three shapes it has to get right.
 *
 * The per-finding table has been in the JSON since spec-v8 §25 and nowhere
 * else, so the only reader who ever learned that a third of a report's findings
 * quote no clause text was one parsing the JSON. These pin the wording rather
 * than a substring, because the wording IS the surface: a report that says
 * "some findings" instead of "3 of 9" has not told anyone anything.
 */
describe("clauseEvidenceSentence", () => {
  const quoted = (id: string): Finding =>
    ({
      id,
      rule_id: "R",
      severity: "warning",
      excerpt: { text: "the exact clause", start_offset: 0, end_offset: 16 },
    }) as unknown as Finding;
  const bare = (id: string): Finding =>
    ({
      id,
      rule_id: "R",
      severity: "warning",
      excerpt: { text: "", start_offset: 0, end_offset: 0 },
    }) as unknown as Finding;

  it("says nothing when there are no findings to characterize", () => {
    expect(clauseEvidenceSentence(buildClauseEvidence([]))).toBeUndefined();
  });

  it("states the split when the report is mixed", () => {
    const s = clauseEvidenceSentence(buildClauseEvidence([quoted("a"), quoted("b"), bare("c")]))!;
    expect(s).toContain("2 of 3 findings quote the exact clause text");
    expect(s).toContain("the remaining 1 rest on a pattern or structural match");
  });

  it("does not hedge when every finding quotes its clause", () => {
    const s = clauseEvidenceSentence(buildClauseEvidence([quoted("a"), quoted("b")]))!;
    expect(s).toBe("All 2 findings quote the exact clause text they fired on.");
    expect(s).not.toContain("remaining");
  });

  it("says so plainly when NONE of them does", () => {
    // The case a "N of M" template renders as "0 of 3 ... the remaining 3",
    // which reads like a partial result. It is not partial; it is every one.
    const s = clauseEvidenceSentence(buildClauseEvidence([bare("a"), bare("b"), bare("c")]))!;
    expect(s).toContain("None of the 3 findings quotes clause text");
    expect(s).toContain("confirm every one against the document itself");
  });
});
