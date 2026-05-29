import { describe, expect, it } from "vitest";
import { buildComparisonDocx } from "./compare-docx.js";
import { compareRuns } from "./compare.js";
import type { EngineRun, Finding, Severity } from "../engine/finding.js";

function finding(rule_id: string, severity: Severity, position: number, text = "the clause text"): Finding {
  return {
    id: `${rule_id}-s${position}-${position}`,
    rule_id,
    rule_version: "1.0.0",
    severity,
    title: `Issue with ${rule_id}`,
    description: "desc",
    excerpt: { text, section_id: `s${position}`, start_offset: position, end_offset: position + 5 },
    explanation: "Why this matters.",
    source_citations: [],
    document_position: position,
  };
}

function makeRun(name: string, result_hash: string, findings: Finding[]): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v1.0.0",
    playbook_id: "mutual-nda",
    source_file: { name, sha256: "a".repeat(64), size_bytes: 1024 },
    executed_at: "2026-05-29T00:00:00Z",
    findings,
    execution_log: findings.map((f) => ({ rule_id: f.rule_id, rule_version: "1.0.0", fired: true, elapsed_ms: 0 })),
    result_hash,
  };
}

async function bytes(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer());
}

describe("buildComparisonDocx", () => {
  it("produces a non-empty .docx blob", async () => {
    const base = makeRun("v1.pdf", "b".repeat(64), [finding("A", "critical", 1, "cap at 1x")]);
    const revised = makeRun("v2.pdf", "r".repeat(64), [finding("A", "critical", 1, "cap at 2x"), finding("B", "info", 2)]);
    const cmp = await compareRuns(base, revised);
    const blob = await buildComparisonDocx(cmp);
    const b = await bytes(blob);
    expect(b.length).toBeGreaterThan(0);
    // PK zip magic — DOCX is a zip container.
    expect(b[0]).toBe(0x50);
    expect(b[1]).toBe(0x4b);
  });

  it("renders an identical document.xml across two builds of the same comparison", async () => {
    const base = makeRun("v1.pdf", "b".repeat(64), [finding("A", "critical", 1)]);
    const revised = makeRun("v2.pdf", "r".repeat(64), [finding("A", "critical", 1), finding("B", "warning", 2)]);
    const cmp = await compareRuns(base, revised);
    const { unzipSync, strFromU8 } = await import("fflate");
    const docXml = async (blob: Blob) =>
      strFromU8(unzipSync(await bytes(blob))["word/document.xml"]!);
    expect(await docXml(await buildComparisonDocx(cmp))).toBe(
      await docXml(await buildComparisonDocx(cmp)),
    );
  });

  it("names both versions and the comparison hash in the document body", async () => {
    const base = makeRun("base-v1.pdf", "b".repeat(64), [finding("A", "critical", 1)]);
    const revised = makeRun("revised-v2.pdf", "r".repeat(64), [finding("B", "info", 2)]);
    const cmp = await compareRuns(base, revised);
    const { unzipSync, strFromU8 } = await import("fflate");
    const docXml = strFromU8(unzipSync(await bytes(await buildComparisonDocx(cmp)))["word/document.xml"]!);
    expect(docXml).toContain("base-v1.pdf");
    expect(docXml).toContain("revised-v2.pdf");
    expect(docXml).toContain(cmp.result_hash);
  });

  it("handles an empty (no-change) comparison without error", async () => {
    const findings = [finding("A", "critical", 1)];
    const base = makeRun("v1.pdf", "b".repeat(64), findings);
    const revised = makeRun("v2.pdf", "r".repeat(64), findings);
    const cmp = await compareRuns(base, revised);
    const blob = await buildComparisonDocx(cmp);
    expect((await bytes(blob)).length).toBeGreaterThan(0);
  });
});
