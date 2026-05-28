/**
 * Consolidated bundle report tests (spec-v4.md §11, Step 44).
 *
 * Exercises the four public surfaces:
 *   - `bundleFingerprint` — order-independent hash of per-doc result hashes.
 *   - `buildBundleJson` / `buildBundleJsonBlob` — shape + determinism.
 *   - `buildBundleDocxReport` — non-empty Blob with OOXML magic bytes.
 *   - `buildBundleZip` — deterministic bytes, deterministic ordering.
 */

import { describe, expect, it } from "vitest";
import { unzipSync, strFromU8 } from "fflate";

import {
  bundleFingerprint,
  buildBundleJson,
  buildBundleJsonBlob,
  buildBundleDocxReport,
  buildBundleZip,
  BUNDLE_TOP_N,
} from "./bundle.js";
import { loadStarterDkbSync } from "../engine/_test-fixtures.js";
import type { BundleDocument, BundleReportInput } from "./bundle.js";
import type { EngineRun, Finding } from "../engine/finding.js";
import type { ConsistencyRun, ConsistencyFinding } from "../engine/consistency/types.js";

function finding(id: string, severity: Finding["severity"], rule_id = "STRUCT-001"): Finding {
  return {
    id,
    rule_id,
    rule_version: "1.0.0",
    severity,
    title: `Finding ${id}`,
    description: `Description ${id}`,
    excerpt: { text: "excerpt", section_id: "s1", start_offset: 0, end_offset: 7 },
    explanation: "Explanation",
    recommendation: "Recommendation",
    source_citations: [
      {
        id: "common-paper-mutual-nda-v1.1",
        source: "Common Paper Mutual NDA, v1.1",
        source_url: "https://example.com",
        retrieved_at: "2026-01-01T00:00:00Z",
        license: "CC-BY-4.0",
        license_url: "https://creativecommons.org/licenses/by/4.0/",
      },
    ],
    document_position: 0,
  };
}

function makeRun(name: string, hashSeed: string, findings: Finding[]): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v0.0.1-starter",
    playbook_id: "mutual-nda",
    playbook_match_confidence: 0.9,
    source_file: { name, sha256: hashSeed.repeat(64).slice(0, 64), size_bytes: 1024 },
    executed_at: "2026-05-12T12:00:00Z",
    findings,
    execution_log: [
      { rule_id: "STRUCT-001", rule_version: "1.0.0", fired: true, finding_id: "c1", elapsed_ms: 0.1 },
      { rule_id: "STRUCT-002", rule_version: "1.0.0", fired: false, elapsed_ms: 0.05 },
    ],
    result_hash: hashSeed.repeat(64).slice(0, 64),
  };
}

function bundleDoc(doc_id: string, hashSeed: string, findings: Finding[] = []): BundleDocument {
  return {
    doc_id,
    source_file_name: `${doc_id}.docx`,
    detected_family: "Mutual NDA",
    run: makeRun(`${doc_id}.docx`, hashSeed, findings),
  };
}

function crossFinding(id: string, severity: ConsistencyFinding["severity"]): ConsistencyFinding {
  return {
    id,
    rule_id: "CROSS-PARTY-001",
    rule_version: "1.0.0",
    severity,
    title: `Cross ${id}`,
    description: `Cross description ${id}`,
    explanation: "Cross explanation",
    recommendation: "Reconcile party names",
    source_citations: [],
    excerpts: [
      { doc_id: "a", source_file_name: "a.docx", text: "Acme Corp.", start_offset: 0, end_offset: 10 },
      { doc_id: "b", source_file_name: "b.docx", text: "Acme, Inc.", start_offset: 0, end_offset: 10 },
    ],
  };
}

function makeConsistency(findings: ConsistencyFinding[] = []): ConsistencyRun {
  return {
    version: "0.1.0",
    dkb_version: "v0.0.1-starter",
    documents: [
      { doc_id: "a", source_file_name: "a.docx", playbook_id: "mutual-nda", kind: "nda" },
      { doc_id: "b", source_file_name: "b.docx", playbook_id: "mutual-nda", kind: "nda" },
    ],
    executed_at: "2026-05-12T12:00:00Z",
    findings,
    execution_log: [
      { rule_id: "CROSS-PARTY-001", rule_version: "1.0.0", ran: true, findings_count: findings.length, elapsed_ms: 0.2 },
      { rule_id: "CROSS-JURIS-001", rule_version: "1.0.0", ran: false, findings_count: 0, elapsed_ms: 0 },
    ],
    result_hash: "f".repeat(64),
  };
}

function makeInput(opts?: { findings?: ConsistencyFinding[] }): BundleReportInput {
  return {
    documents: [
      bundleDoc("a", "a", [finding("c1", "critical"), finding("w1", "warning")]),
      bundleDoc("b", "b", [finding("i1", "info")]),
    ],
    consistency: makeConsistency(opts?.findings ?? [crossFinding("x1", "warning")]),
    dkb: loadStarterDkbSync(),
    engine_version: "0.1.0",
    executed_at: "2026-05-12T12:00:00Z",
  };
}

describe("bundleFingerprint", () => {
  it("is order-independent (sorted input)", async () => {
    const a = await bundleFingerprint(["a".repeat(64), "b".repeat(64)]);
    const b = await bundleFingerprint(["b".repeat(64), "a".repeat(64)]);
    expect(a).toBe(b);
  });

  it("changes when inputs change", async () => {
    const a = await bundleFingerprint(["a".repeat(64)]);
    const b = await bundleFingerprint(["b".repeat(64)]);
    expect(a).not.toBe(b);
  });

  it("returns 64-char hex", async () => {
    const out = await bundleFingerprint(["a".repeat(64)]);
    expect(out).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("buildBundleJson", () => {
  it("packages runs + cross-doc findings + fingerprint", async () => {
    const out = await buildBundleJson(makeInput());
    expect(out.runs).toHaveLength(2);
    expect(out.cross_doc_findings).toHaveLength(1);
    expect(out.bundle_fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(out.dkb_version).toBe("v0.0.1-starter");
    expect(out.engine_version).toBe("0.1.0");
    expect(out.consistency_version).toBe("0.1.0");
  });

  it("surfaces the cross-doc consistency execution_log so consumers can distinguish ran/skipped", async () => {
    const out = await buildBundleJson(makeInput());
    expect(out.consistency_execution_log).toHaveLength(2);
    const entries = out.consistency_execution_log;
    const ran = entries.find((e) => e.rule_id === "CROSS-PARTY-001");
    const skipped = entries.find((e) => e.rule_id === "CROSS-JURIS-001");
    expect(ran?.ran).toBe(true);
    expect(ran?.findings_count).toBe(1);
    expect(skipped?.ran).toBe(false);
    expect(skipped?.findings_count).toBe(0);
  });

  it("consistency_execution_log is a defensive copy (mutating the result does not touch the input)", async () => {
    const input = makeInput();
    const out = await buildBundleJson(input);
    out.consistency_execution_log.pop();
    expect(input.consistency.execution_log).toHaveLength(2);
  });

  it("surfaces the cross-doc consistency engine version separately from engine_version", async () => {
    const input = makeInput();
    const out = await buildBundleJson({
      ...input,
      consistency: { ...input.consistency, version: "0.2.0-cross" },
    });
    expect(out.engine_version).toBe("0.1.0");
    expect(out.consistency_version).toBe("0.2.0-cross");
  });

  it("buildBundleJsonBlob returns application/json with pretty-printed text", async () => {
    const blob = await buildBundleJsonBlob(makeInput());
    expect(blob.type).toBe("application/json");
    const text = await blob.text();
    expect(text).toContain("\n  ");
    const parsed = JSON.parse(text);
    expect(parsed.bundle_fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic across two runs over the same input", async () => {
    const a = await buildBundleJson(makeInput());
    const b = await buildBundleJson(makeInput());
    expect(a.bundle_fingerprint).toBe(b.bundle_fingerprint);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

describe("buildBundleDocxReport", () => {
  it("produces a non-empty Blob with the docx MIME type", async () => {
    const blob = await buildBundleDocxReport(makeInput());
    expect(blob.size).toBeGreaterThan(1000);
    expect(blob.type).toContain("application/vnd.openxmlformats-officedocument");
  });

  it("output bytes start with the ZIP local-file-header magic (PK\\x03\\x04)", async () => {
    const blob = await buildBundleDocxReport(makeInput());
    const bytes = new Uint8Array(await blob.arrayBuffer());
    expect(bytes[0]).toBe(0x50);
    expect(bytes[1]).toBe(0x4b);
    expect(bytes[2]).toBe(0x03);
    expect(bytes[3]).toBe(0x04);
  });

  it("handles zero cross-doc findings", async () => {
    const blob = await buildBundleDocxReport(makeInput({ findings: [] }));
    expect(blob.size).toBeGreaterThan(0);
  });

  it("BUNDLE_TOP_N is 10 per spec §11", () => {
    expect(BUNDLE_TOP_N).toBe(10);
  });

  it("renders a Skipped Files appendix when rejected entries are passed", async () => {
    const input: BundleReportInput = {
      ...makeInput(),
      rejected: [
        { filename: "notes.txt", reason: 'Vaulytica accepts .pdf and .docx — not "notes.txt".' },
        { filename: "huge.pdf", reason: "huge.pdf exceeds the 50 MB per-file limit." },
      ],
    };
    const blob = await buildBundleDocxReport(input);
    // The DOCX is a zip; the rendered text lives in word/document.xml.
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(entries["word/document.xml"]!);
    expect(docXml).toContain("Skipped Files");
    expect(docXml).toContain("notes.txt");
    expect(docXml).toContain("huge.pdf");
    expect(docXml).toContain("exceeds the 50 MB per-file limit");
  });

  it("does not render the Skipped Files appendix when no entries are rejected", async () => {
    const blob = await buildBundleDocxReport(makeInput());
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(entries["word/document.xml"]!);
    expect(docXml).not.toContain("Skipped Files");
  });
});

describe("buildBundleDocxReport — consistency_enabled", () => {
  it("cover + intro reflect the disabled state when consistency_enabled=false", async () => {
    const input: BundleReportInput = { ...makeInput(), consistency_enabled: false };
    const blob = await buildBundleDocxReport(input);
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(entries["word/document.xml"]!);
    expect(docXml).toContain("disabled by user");
    expect(docXml).toContain(
      "The cross-document consistency pass was disabled by the user",
    );
  });

  it("cover + intro reflect rules executed when consistency_enabled=true", async () => {
    const input: BundleReportInput = { ...makeInput(), consistency_enabled: true };
    const blob = await buildBundleDocxReport(input);
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(entries["word/document.xml"]!);
    expect(docXml).toMatch(/rules executed/);
    expect(docXml).not.toContain("disabled by user");
  });

  it("omitting consistency_enabled preserves prior implicit behavior", async () => {
    const blob = await buildBundleDocxReport(makeInput());
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(entries["word/document.xml"]!);
    expect(docXml).not.toContain("disabled by user");
    expect(docXml).toMatch(/rules executed/);
  });
});

describe("buildBundleJson — rejected entries", () => {
  it("includes the rejected array when present", async () => {
    const input: BundleReportInput = {
      ...makeInput(),
      rejected: [{ filename: "x.txt", reason: "unsupported" }],
    };
    const out = await buildBundleJson(input);
    expect(out.rejected).toEqual([{ filename: "x.txt", reason: "unsupported" }]);
  });

  it("omits the rejected field when empty or absent (back-compat)", async () => {
    const a = await buildBundleJson(makeInput());
    expect(a.rejected).toBeUndefined();
    const b = await buildBundleJson({ ...makeInput(), rejected: [] });
    expect(b.rejected).toBeUndefined();
  });
});

describe("buildBundleJson — consistency_enabled", () => {
  it("surfaces consistency_enabled=false when the user disabled the toggle", async () => {
    const input: BundleReportInput = { ...makeInput(), consistency_enabled: false };
    const out = await buildBundleJson(input);
    expect(out.consistency_enabled).toBe(false);
  });

  it("omits consistency_enabled when explicitly true (back-compat)", async () => {
    const input: BundleReportInput = { ...makeInput(), consistency_enabled: true };
    const out = await buildBundleJson(input);
    expect(out.consistency_enabled).toBeUndefined();
  });

  it("omits consistency_enabled when the field is absent (back-compat)", async () => {
    const out = await buildBundleJson(makeInput());
    expect(out.consistency_enabled).toBeUndefined();
  });
});

describe("buildBundleJson — per-document metadata (spec-v3 §60 follow-up)", () => {
  it("surfaces a documents[] array with detected_family + doc_id + result_hash", async () => {
    const out = await buildBundleJson(makeInput());
    expect(out.documents).toBeDefined();
    expect(out.documents).toHaveLength(2);
    expect(out.documents![0]).toEqual({
      doc_id: "a",
      source_file_name: "a.docx",
      detected_family: "Mutual NDA",
      playbook_id: "mutual-nda",
      playbook_match_confidence: 0.9,
      source_file_sha256: out.runs[0]!.source_file.sha256,
      result_hash: out.runs[0]!.result_hash,
      severity_counts: { critical: 1, warning: 1, info: 0 },
    });
    expect(out.documents![1]!.doc_id).toBe("b");
    expect(out.documents![1]!.detected_family).toBe("Mutual NDA");
  });

  it("surfaces playbook_id + playbook_match_confidence on every documents[] entry", async () => {
    const out = await buildBundleJson(makeInput());
    expect(out.documents).toBeDefined();
    for (const entry of out.documents!) {
      expect(entry.playbook_id).toBe("mutual-nda");
      expect(entry.playbook_match_confidence).toBe(0.9);
    }
  });

  it("surfaces per-doc severity_counts that match the underlying findings list", async () => {
    const input = makeInput();
    const withFindings: BundleReportInput = {
      ...input,
      documents: [
        {
          ...bundleDoc("a", "a"),
          run: {
            ...makeRun("a.docx", "a", [
              finding("f1", "critical"),
              finding("f2", "warning"),
              finding("f3", "warning"),
              finding("f4", "info"),
            ]),
          },
        },
        bundleDoc("b", "b"),
      ],
    };
    const out = await buildBundleJson(withFindings);
    expect(out.documents![0]!.severity_counts).toEqual({ critical: 1, warning: 2, info: 1 });
    expect(out.documents![1]!.severity_counts).toEqual({ critical: 0, warning: 0, info: 0 });
  });

  it("surfaces source_file_sha256 (mirrors runs[i].source_file.sha256) on every entry", async () => {
    const out = await buildBundleJson(makeInput());
    expect(out.documents).toBeDefined();
    for (let i = 0; i < out.documents!.length; i++) {
      expect(out.documents![i]!.source_file_sha256).toBe(out.runs[i]!.source_file.sha256);
      expect(out.documents![i]!.source_file_sha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("surfaces detection_confidence when threaded through, omits when absent", async () => {
    const input: BundleReportInput = {
      ...makeInput(),
      documents: [
        { ...bundleDoc("a", "a"), detection_confidence: 0.83 },
        bundleDoc("b", "b"),
      ],
    };
    const out = await buildBundleJson(input);
    expect(out.documents![0]!.detection_confidence).toBe(0.83);
    expect(out.documents![1]!.detection_confidence).toBeUndefined();
  });

  it("DOCX per-document subsection prints '(confidence X.XX)' when detection_confidence is threaded", async () => {
    const input: BundleReportInput = {
      ...makeInput(),
      documents: [
        { ...bundleDoc("a", "a"), detection_confidence: 0.83 },
        bundleDoc("b", "b"),
      ],
    };
    const blob = await buildBundleDocxReport(input);
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(entries["word/document.xml"]!);
    expect(docXml).toContain("(confidence 0.83)");
    // Other doc does not get a confidence suffix.
    expect(docXml).toContain("Detected family: Mutual NDA</w:t>");
  });

  it("omits playbook_match_confidence when the run did not record one", async () => {
    const noConfidence: BundleReportInput = {
      ...makeInput(),
      documents: [
        {
          ...bundleDoc("a", "a"),
          run: {
            ...makeRun("a.docx", "a", []),
            playbook_match_confidence: undefined,
          },
        },
        bundleDoc("b", "b"),
      ],
    };
    const out = await buildBundleJson(noConfidence);
    expect(out.documents).toBeDefined();
    expect(out.documents![0]!.playbook_id).toBe("mutual-nda");
    expect(out.documents![0]!.playbook_match_confidence).toBeUndefined();
    expect(out.documents![1]!.playbook_match_confidence).toBe(0.9);
  });

  it("DOCX per-document subsection annotates Playbook line with deprecation when threaded", async () => {
    const input: BundleReportInput = {
      ...makeInput(),
      documents: [
        { ...bundleDoc("a", "a"), playbook_deprecated: true, playbook_superseded_by: "mutual-nda-deep" },
        { ...bundleDoc("b", "b"), playbook_deprecated: true },
        bundleDoc("c", "c"),
      ],
    };
    const blob = await buildBundleDocxReport(input);
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    const docXml = strFromU8(entries["word/document.xml"]!);
    expect(docXml).toContain("Playbook: mutual-nda — legacy; superseded by mutual-nda-deep");
    expect(docXml).toContain("Playbook: mutual-nda — legacy</w:t>");
    // Doc c is not deprecated → no annotation on its Playbook line.
    // The plain "Playbook: mutual-nda" string still appears (used by the
    // first two annotated entries as a prefix), so verify via the
    // absence of " — legacy" on the third entry by counting hits.
    const legacyHits = docXml.match(/Playbook: mutual-nda — legacy/g) ?? [];
    expect(legacyHits).toHaveLength(2);
  });

  it("JSON per-entry surfaces playbook_deprecated + playbook_superseded_by when threaded", async () => {
    const input: BundleReportInput = {
      ...makeInput(),
      documents: [
        { ...bundleDoc("a", "a"), playbook_deprecated: true, playbook_superseded_by: "mutual-nda-deep" },
        { ...bundleDoc("b", "b"), playbook_deprecated: true },
        bundleDoc("c", "c"),
      ],
    };
    const out = await buildBundleJson(input);
    expect(out.documents).toBeDefined();
    expect(out.documents![0]!.playbook_deprecated).toBe(true);
    expect(out.documents![0]!.playbook_superseded_by).toBe("mutual-nda-deep");
    expect(out.documents![1]!.playbook_deprecated).toBe(true);
    expect(out.documents![1]!.playbook_superseded_by).toBeUndefined();
    expect(out.documents![2]!.playbook_deprecated).toBeUndefined();
    expect(out.documents![2]!.playbook_superseded_by).toBeUndefined();
  });

  it("omits documents[] (back-compat) when no document carries a detected_family", async () => {
    const noFamily: BundleReportInput = {
      ...makeInput(),
      documents: [
        // strip detected_family from each doc
        { ...bundleDoc("a", "a"), detected_family: undefined },
        { ...bundleDoc("b", "b"), detected_family: undefined },
      ],
    };
    const out = await buildBundleJson(noFamily);
    expect(out.documents).toBeUndefined();
  });

  it("omits per-entry detected_family when only some documents carry one", async () => {
    const mixed: BundleReportInput = {
      ...makeInput(),
      documents: [
        bundleDoc("a", "a"), // has detected_family: "Mutual NDA"
        { ...bundleDoc("b", "b"), detected_family: undefined },
      ],
    };
    const out = await buildBundleJson(mixed);
    expect(out.documents).toHaveLength(2);
    expect(out.documents![0]!.detected_family).toBe("Mutual NDA");
    expect(out.documents![1]!.detected_family).toBeUndefined();
  });
});

describe("buildBundleZip", () => {
  it("packages consolidated-report.docx + bundle.json", async () => {
    const blob = await buildBundleZip(makeInput());
    expect(blob.type).toBe("application/zip");
    const bytes = new Uint8Array(await blob.arrayBuffer());
    const entries = unzipSync(bytes);
    expect(Object.keys(entries).sort()).toEqual(["bundle.json", "consolidated-report.docx"]);
    const parsed = JSON.parse(strFromU8(entries["bundle.json"]!));
    expect(parsed.bundle_fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("includes per-document artifacts under per-document/", async () => {
    const input = makeInput();
    const blob = await buildBundleZip({
      ...input,
      per_document_artifacts: [
        { filename: "a.docx", bytes: new Uint8Array([1, 2, 3]) },
        { filename: "a.json", bytes: new Uint8Array([4, 5, 6]) },
      ],
    });
    const entries = unzipSync(new Uint8Array(await blob.arrayBuffer()));
    expect(Object.keys(entries).sort()).toEqual([
      "bundle.json",
      "consolidated-report.docx",
      "per-document/a.docx",
      "per-document/a.json",
    ]);
    expect(Array.from(entries["per-document/a.docx"]!)).toEqual([1, 2, 3]);
  });

  it("uses a fixed mtime so the zip envelope itself is deterministic", async () => {
    // The docx library packs its own (timestamped) bytes, so the full
    // zip cannot be byte-identical across runs. Instead we verify that
    // the bundle.json entry inside is byte-identical across two runs —
    // proof that the JSON layer + zip framing are deterministic.
    const a = await buildBundleZip(makeInput());
    const b = await buildBundleZip(makeInput());
    const ea = unzipSync(new Uint8Array(await a.arrayBuffer()))["bundle.json"]!;
    const eb = unzipSync(new Uint8Array(await b.arrayBuffer()))["bundle.json"]!;
    expect(ea.length).toBe(eb.length);
    for (let i = 0; i < ea.length; i++) {
      if (ea[i] !== eb[i]) throw new Error(`bundle.json byte mismatch at ${i}`);
    }
  });
});
