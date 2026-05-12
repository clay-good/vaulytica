import { describe, expect, it } from "vitest";
import { buildDocxReport } from "./docx.js";
import { buildJsonReport } from "./json.js";
import { loadStarterDkbSync } from "../engine/_test-fixtures.js";
import type { EngineRun, Finding } from "../engine/finding.js";
import type { IngestResult } from "../ingest/types.js";
import type { Playbook } from "../playbooks/types.js";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadMutualNda(): Playbook {
  const p = join(__dirname, "..", "..", "playbooks", "mutual-nda.json");
  return JSON.parse(readFileSync(p, "utf8")) as Playbook;
}

function finding(id: string, severity: Finding["severity"]): Finding {
  return {
    id,
    rule_id: "STRUCT-001",
    rule_version: "1.0.0",
    severity,
    title: `Finding ${id}`,
    description: "Description of the finding",
    excerpt: { text: "excerpt text", section_id: "s1", start_offset: 0, end_offset: 12 },
    explanation: "Plain language explanation of why this matters.",
    recommendation: "Consider revising the clause.",
    source_citations: [
      {
        id: "common-paper-mutual-nda-v1.1",
        source: "Common Paper Mutual NDA, v1.1",
        source_url: "https://github.com/CommonPaper/Mutual-NDA",
        retrieved_at: "2026-05-11T00:00:00Z",
        license: "CC-BY-4.0",
        license_url: "https://creativecommons.org/licenses/by/4.0/",
      },
    ],
    document_position: 0,
  };
}

function makeRun(): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v0.0.1-starter",
    playbook_id: "mutual-nda",
    playbook_match_confidence: 0.92,
    playbook_match_reasoning: "Selected mutual-nda.",
    source_file: { name: "test.pdf", sha256: "a".repeat(64), size_bytes: 1024 },
    executed_at: "2026-05-12T12:00:00Z",
    findings: [finding("c1", "critical"), finding("w1", "warning"), finding("i1", "info")],
    execution_log: [
      { rule_id: "STRUCT-001", rule_version: "1.0.0", fired: true, finding_id: "c1", elapsed_ms: 0.1 },
      { rule_id: "STRUCT-002", rule_version: "1.0.0", fired: false, elapsed_ms: 0.05 },
    ],
    result_hash: "b".repeat(64),
  };
}

const ingest: IngestResult = {
  tree: { type: "document", sections: [] },
  source: "pdf",
  word_count: 1000,
  sha256: "a".repeat(64),
  warnings: [],
};

describe("buildDocxReport", () => {
  it("produces a non-empty Blob with the docx MIME type", async () => {
    const blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda());
    expect(blob.size).toBeGreaterThan(1000);
    // docx Packer.toBlob assigns the OOXML mime type
    expect(blob.type).toContain("application/vnd.openxmlformats-officedocument");
  });

  it("output bytes start with the ZIP local-file-header magic (PK\\x03\\x04)", async () => {
    const blob = await buildDocxReport(makeRun(), ingest, loadStarterDkbSync(), loadMutualNda());
    const bytes = new Uint8Array(await blob.arrayBuffer());
    expect(bytes[0]).toBe(0x50);
    expect(bytes[1]).toBe(0x4b);
    expect(bytes[2]).toBe(0x03);
    expect(bytes[3]).toBe(0x04);
  });

  it("handles a run with zero findings", async () => {
    const run = makeRun();
    run.findings = [];
    const blob = await buildDocxReport(run, ingest, loadStarterDkbSync(), loadMutualNda());
    expect(blob.size).toBeGreaterThan(0);
  });
});

describe("buildJsonReport", () => {
  it("serializes the run plus ingest summary as pretty JSON", async () => {
    const blob = buildJsonReport(makeRun(), ingest);
    expect(blob.type).toBe("application/json");
    const text = await blob.text();
    const parsed = JSON.parse(text);
    expect(parsed.run.playbook_id).toBe("mutual-nda");
    expect(parsed.ingest.sha256).toBe("a".repeat(64));
    expect(text).toContain("\n  "); // pretty-printed
  });
});
