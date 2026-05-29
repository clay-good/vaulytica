import { describe, expect, it } from "vitest";
import {
  compareRuns,
  comparabilityOf,
  ComparisonRefusedError,
  buildComparisonJsonObject,
} from "./compare.js";
import type { EngineRun, Finding, Severity } from "../engine/finding.js";
import type { ExecutionLogEntry } from "../engine/finding.js";

// --- fixtures ---------------------------------------------------------------

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

function logEntry(rule_id: string, fired: boolean): ExecutionLogEntry {
  return { rule_id, rule_version: "1.0.0", fired, elapsed_ms: 0 };
}

function makeRun(opts: {
  name?: string;
  playbook_id?: string;
  dkb_version?: string;
  result_hash?: string;
  findings: Finding[];
  silentRules?: string[];
}): EngineRun {
  const log: ExecutionLogEntry[] = [
    ...opts.findings.map((f) => logEntry(f.rule_id, true)),
    ...(opts.silentRules ?? []).map((r) => logEntry(r, false)),
  ];
  return {
    version: "0.1.0",
    dkb_version: opts.dkb_version ?? "v1.0.0",
    playbook_id: opts.playbook_id ?? "mutual-nda",
    source_file: { name: opts.name ?? "doc.pdf", sha256: "a".repeat(64), size_bytes: 1024 },
    executed_at: "2026-05-29T00:00:00Z",
    findings: opts.findings,
    execution_log: log,
    result_hash: opts.result_hash ?? "b".repeat(64),
  };
}

// --- bucket logic -----------------------------------------------------------

describe("compareRuns — buckets", () => {
  it("buckets findings into resolved / introduced / unchanged", async () => {
    const base = makeRun({
      result_hash: "base".padEnd(64, "0"),
      findings: [finding("R-RESOLVED", "warning", 10), finding("R-UNCHANGED", "critical", 20)],
      silentRules: ["R-CLEAN-1", "R-CLEAN-2"],
    });
    const revised = makeRun({
      result_hash: "rev".padEnd(64, "0"),
      findings: [finding("R-UNCHANGED", "critical", 25), finding("R-INTRODUCED", "info", 30)],
      silentRules: ["R-CLEAN-1", "R-CLEAN-2"],
    });

    const cmp = await compareRuns(base, revised);

    expect(cmp.delta.resolved.map((f) => f.rule_id)).toEqual(["R-RESOLVED"]);
    expect(cmp.delta.introduced.map((f) => f.rule_id)).toEqual(["R-INTRODUCED"]);
    expect(cmp.delta.unchanged.map((u) => u.rule_id)).toEqual(["R-UNCHANGED"]);
    expect(cmp.delta.carried_clean_count).toBe(2);
  });

  it("uses the revised finding for the unchanged bucket", async () => {
    const base = makeRun({ findings: [finding("R", "critical", 10)] });
    const revised = makeRun({ findings: [finding("R", "warning", 99)] });
    const cmp = await compareRuns(base, revised);
    expect(cmp.delta.unchanged).toHaveLength(1);
    expect(cmp.delta.unchanged[0]!.finding.severity).toBe("warning");
    expect(cmp.delta.unchanged[0]!.finding.document_position).toBe(99);
    expect(cmp.delta.unchanged[0]!.base_finding.severity).toBe("critical");
  });

  it("flags a clause-level text change on an unchanged finding", async () => {
    const base = makeRun({ findings: [finding("R", "critical", 10, "liability capped at 1x fees")] });
    const revised = makeRun({ findings: [finding("R", "critical", 10, "liability capped at 2x fees")] });
    const cmp = await compareRuns(base, revised);
    expect(cmp.delta.unchanged[0]!.clause_changed).toBe(true);
  });

  it("does not flag a whitespace-only clause difference as a change", async () => {
    const base = makeRun({ findings: [finding("R", "critical", 10, "liability  capped\n at 1x")] });
    const revised = makeRun({ findings: [finding("R", "critical", 10, "liability capped at 1x")] });
    const cmp = await compareRuns(base, revised);
    expect(cmp.delta.unchanged[0]!.clause_changed).toBe(false);
  });

  it("computes per-bucket severity counts", async () => {
    const base = makeRun({
      findings: [finding("A", "critical", 1), finding("B", "warning", 2)],
    });
    const revised = makeRun({
      findings: [finding("C", "critical", 3), finding("D", "info", 4)],
    });
    const cmp = await compareRuns(base, revised);
    expect(cmp.delta.counts.resolved).toEqual({ critical: 1, warning: 1, info: 0, total: 2 });
    expect(cmp.delta.counts.introduced).toEqual({ critical: 1, warning: 0, info: 1, total: 2 });
    expect(cmp.delta.counts.unchanged).toEqual({ critical: 0, warning: 0, info: 0, total: 0 });
  });

  it("identical runs produce empty resolved/introduced buckets", async () => {
    const findings = [finding("A", "critical", 1), finding("B", "warning", 2)];
    const base = makeRun({ findings });
    const revised = makeRun({ findings });
    const cmp = await compareRuns(base, revised);
    expect(cmp.delta.resolved).toHaveLength(0);
    expect(cmp.delta.introduced).toHaveLength(0);
    expect(cmp.delta.unchanged).toHaveLength(2);
  });
});

// --- determinism ------------------------------------------------------------

describe("compareRuns — determinism", () => {
  it("is byte-identical across two runs (same comparison hash)", async () => {
    const base = makeRun({ result_hash: "b".repeat(64), findings: [finding("A", "critical", 1)] });
    const revised = makeRun({ result_hash: "r".repeat(64), findings: [finding("A", "critical", 1), finding("B", "info", 2)] });
    const a = await compareRuns(base, revised);
    const b = await compareRuns(base, revised);
    expect(a.result_hash).toBe(b.result_hash);
    expect(a.result_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("comparison hash changes when the delta changes", async () => {
    const base = makeRun({ result_hash: "b".repeat(64), findings: [finding("A", "critical", 1)] });
    const rev1 = makeRun({ result_hash: "r".repeat(64), findings: [finding("A", "critical", 1)] });
    const rev2 = makeRun({ result_hash: "r".repeat(64), findings: [finding("A", "critical", 1), finding("B", "info", 2)] });
    const c1 = await compareRuns(base, rev1);
    const c2 = await compareRuns(base, rev2);
    expect(c1.result_hash).not.toBe(c2.result_hash);
  });

  it("comparison hash is order-sensitive (base vs revised swap differs)", async () => {
    const x = makeRun({ result_hash: "x".repeat(64), findings: [finding("A", "critical", 1)] });
    const y = makeRun({ result_hash: "y".repeat(64), findings: [finding("B", "warning", 2)] });
    const forward = await compareRuns(x, y);
    const backward = await compareRuns(y, x);
    expect(forward.result_hash).not.toBe(backward.result_hash);
  });
});

// --- comparability / refusal ------------------------------------------------

describe("comparability and family-mismatch refusal", () => {
  it("reports same-family runs as comparable", () => {
    const base = makeRun({ playbook_id: "mutual-nda", findings: [] });
    const revised = makeRun({ playbook_id: "mutual-nda", findings: [] });
    const c = comparabilityOf(base, revised);
    expect(c.comparable).toBe(true);
    expect(c.family_mismatch).toBe(false);
  });

  it("reports cross-family runs as not comparable with a reason", () => {
    const base = makeRun({ playbook_id: "mutual-nda", findings: [] });
    const revised = makeRun({ playbook_id: "saas-subscription", findings: [] });
    const c = comparabilityOf(base, revised);
    expect(c.comparable).toBe(false);
    expect(c.family_mismatch).toBe(true);
    expect(c.reason).toContain("mutual-nda");
    expect(c.reason).toContain("saas-subscription");
  });

  it("refuses a cross-family comparison by default", async () => {
    const base = makeRun({ playbook_id: "mutual-nda", findings: [] });
    const revised = makeRun({ playbook_id: "saas-subscription", findings: [] });
    await expect(compareRuns(base, revised)).rejects.toBeInstanceOf(ComparisonRefusedError);
  });

  it("allows a cross-family comparison when the pairing is confirmed", async () => {
    const base = makeRun({ playbook_id: "mutual-nda", findings: [finding("A", "critical", 1)] });
    const revised = makeRun({ playbook_id: "saas-subscription", findings: [finding("A", "critical", 1)] });
    const cmp = await compareRuns(base, revised, { confirmPairing: true });
    expect(cmp.family_mismatch).toBe(true);
    expect(cmp.delta.unchanged).toHaveLength(1);
  });

  it("flags a DKB-version mismatch without blocking", async () => {
    const base = makeRun({ dkb_version: "v1.0.0", findings: [] });
    const revised = makeRun({ dkb_version: "v2.0.0", findings: [] });
    const cmp = await compareRuns(base, revised);
    expect(cmp.dkb_mismatch).toBe(true);
  });
});

// --- JSON projection --------------------------------------------------------

describe("buildComparisonJsonObject", () => {
  it("projects the comparison into a stable JSON shape", async () => {
    const base = makeRun({ name: "v1.pdf", findings: [finding("RES", "warning", 5)] });
    const revised = makeRun({ name: "v2.pdf", findings: [finding("INTRO", "critical", 6)] });
    const cmp = await compareRuns(base, revised);
    const json = buildComparisonJsonObject(cmp);
    expect(json.kind).toBe("vaulytica-comparison");
    expect(json.result_hash).toBe(cmp.result_hash);
    expect(json.base.name).toBe("v1.pdf");
    expect(json.revised.name).toBe("v2.pdf");
    expect(json.resolved.map((f) => f.rule_id)).toEqual(["RES"]);
    expect(json.introduced.map((f) => f.rule_id)).toEqual(["INTRO"]);
    expect(json.summary.introduced.critical).toBe(1);
  });
});
