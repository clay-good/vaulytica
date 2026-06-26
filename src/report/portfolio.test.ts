import { describe, expect, it } from "vitest";
import type { EngineRun, ExecutionLogEntry } from "../engine/finding.js";
import {
  buildPortfolioMatrix,
  portfolioFingerprint,
  PORTFOLIO_CHECKS,
  PORTFOLIO_MATRIX_MAX_ROWS,
  type PortfolioInputDocument,
} from "./portfolio.js";

/** Build an EngineRun whose execution_log records the given rule outcomes. */
function run(outcomes: Record<string, boolean>): EngineRun {
  const log: ExecutionLogEntry[] = Object.entries(outcomes).map(([rule_id, fired]) => ({
    rule_id,
    rule_version: "1.0.0",
    fired,
    elapsed_ms: 0.1,
  }));
  return {
    version: "0.1.0",
    dkb_version: "v0.0.1-starter",
    playbook_id: "msa",
    source_file: { name: "x", sha256: "a".repeat(64), size_bytes: 10 },
    executed_at: "2026-05-31T00:00:00Z",
    findings: [],
    execution_log: log,
    result_hash: "h".repeat(64),
  };
}

function doc(name: string, outcomes: Record<string, boolean>): PortfolioInputDocument {
  return { doc_id: name, source_file_name: name, run: run(outcomes) };
}

const checkIndex = (key: string) => PORTFOLIO_CHECKS.findIndex((c) => c.key === key);

describe("portfolio risk matrix (spec-v6 Part V)", () => {
  it("produces one row per document with cells parallel to the checks", () => {
    const m = buildPortfolioMatrix([
      doc("a.pdf", { "RISK-005": false }),
      doc("b.pdf", { "RISK-005": false }),
    ]);
    expect(m.rows).toHaveLength(2);
    expect(m.checks).toHaveLength(PORTFOLIO_CHECKS.length);
    for (const r of m.rows) expect(r.cells).toHaveLength(PORTFOLIO_CHECKS.length);
  });

  it("liability-cap cell: uncapped → risk, missing → risk, present → ok, not run → na", () => {
    const i = checkIndex("liability_cap");
    expect(buildPortfolioMatrix([doc("u", { "RISK-009": true })]).rows[0]!.cells[i]!.status).toBe(
      "risk",
    );
    expect(buildPortfolioMatrix([doc("m", { "RISK-005": true })]).rows[0]!.cells[i]!.status).toBe(
      "risk",
    );
    expect(buildPortfolioMatrix([doc("c", { "RISK-005": false })]).rows[0]!.cells[i]!.status).toBe(
      "ok",
    );
    expect(buildPortfolioMatrix([doc("n", {})]).rows[0]!.cells[i]!.status).toBe("na");
  });

  it("auto-renewal cell flags presence", () => {
    const i = checkIndex("auto_renew");
    expect(buildPortfolioMatrix([doc("y", { "TEMP-004": true })]).rows[0]!.cells[i]!.status).toBe(
      "flag",
    );
    expect(buildPortfolioMatrix([doc("n", { "TEMP-004": false })]).rows[0]!.cells[i]!.status).toBe(
      "ok",
    );
    expect(buildPortfolioMatrix([doc("z", {})]).rows[0]!.cells[i]!.status).toBe("na");
  });

  it("breach-notice cell reflects the DPA-024 outcome", () => {
    const i = checkIndex("breach_notice");
    expect(buildPortfolioMatrix([doc("g", { "DPA-024": true })]).rows[0]!.cells[i]!.status).toBe(
      "risk",
    );
    expect(buildPortfolioMatrix([doc("p", { "DPA-024": false })]).rows[0]!.cells[i]!.status).toBe(
      "ok",
    );
    expect(buildPortfolioMatrix([doc("na", {})]).rows[0]!.cells[i]!.status).toBe("na");
  });

  it("rollups count the documents that match and list them", () => {
    const m = buildPortfolioMatrix([
      doc("a.pdf", { "RISK-009": true }), // uncapped
      doc("b.pdf", { "RISK-005": false }), // capped
      doc("c.pdf", { "RISK-005": true }), // missing cap
    ]);
    const cap = m.rollups.find((r) => r.key === "liability_cap")!;
    expect(cap.count).toBe(2);
    expect(cap.documents).toEqual(["a.pdf", "c.pdf"]);
    expect(cap.text).toContain("2 of 3 documents");
  });

  it("rows are sorted by file name for a canonical projection", () => {
    const m = buildPortfolioMatrix([doc("z.pdf", {}), doc("a.pdf", {}), doc("m.pdf", {})]);
    expect(m.rows.map((r) => r.source_file_name)).toEqual(["a.pdf", "m.pdf", "z.pdf"]);
  });

  it("scale guard: caps rows and reports the true total without silent truncation", () => {
    const docs = Array.from({ length: PORTFOLIO_MATRIX_MAX_ROWS + 5 }, (_, k) =>
      doc(`d${String(k).padStart(3, "0")}.pdf`, {}),
    );
    const m = buildPortfolioMatrix(docs);
    expect(m.truncated).toBe(true);
    expect(m.included).toBe(PORTFOLIO_MATRIX_MAX_ROWS);
    expect(m.total).toBe(PORTFOLIO_MATRIX_MAX_ROWS + 5);
    expect(m.rows).toHaveLength(PORTFOLIO_MATRIX_MAX_ROWS);
  });

  it("portfolio fingerprint is deterministic and extends the bundle fingerprint", async () => {
    const m = buildPortfolioMatrix([doc("a.pdf", { "RISK-005": false })]);
    const f1 = await portfolioFingerprint("bundle-fp", m);
    const f2 = await portfolioFingerprint("bundle-fp", m);
    expect(f1).toBe(f2);
    expect(f1).toMatch(/^[0-9a-f]{64}$/);
    const different = await portfolioFingerprint("other-bundle-fp", m);
    expect(different).not.toBe(f1);
  });

  it("portfolio fingerprint changes when a cell status changes", async () => {
    const capped = buildPortfolioMatrix([doc("a.pdf", { "RISK-005": false })]);
    const uncapped = buildPortfolioMatrix([doc("a.pdf", { "RISK-009": true })]);
    const f1 = await portfolioFingerprint("fp", capped);
    const f2 = await portfolioFingerprint("fp", uncapped);
    expect(f1).not.toBe(f2);
  });
});

describe("portfolio executive summary (spec-v7 §17)", () => {
  function runWithFindings(sevs: Array<"critical" | "warning" | "info">): EngineRun {
    const base = run({});
    return {
      ...base,
      findings: sevs.map((severity, i) => ({
        id: `f-${i}`,
        rule_id: `R-${i}`,
        rule_version: "1.0.0",
        severity,
        title: "t",
        description: "d",
        excerpt: { text: "x", section_id: "s1", start_offset: 0, end_offset: 1 },
        explanation: "e",
        recommendation: "r",
        source_citations: [],
        document_position: i,
      })),
    };
  }

  it("rolls up severity counts across the bundle and digests each document", async () => {
    const { buildPortfolioExecutiveSummary } = await import("./portfolio.js");
    const docs: PortfolioInputDocument[] = [
      {
        doc_id: "msa",
        source_file_name: "msa.txt",
        run: runWithFindings(["critical", "warning", "info"]),
      },
      { doc_id: "dpa", source_file_name: "dpa.txt", run: runWithFindings(["info"]) },
    ];
    const summary = buildPortfolioExecutiveSummary(docs);
    expect(summary.documents).toBe(2);
    expect(summary.critical).toBe(1);
    expect(summary.warning).toBe(1);
    expect(summary.info).toBe(2);
    expect(summary.headline).toMatch(/2 documents · 1 critical · 1 warning · 2 info/);
    // Sorted by file name: dpa before msa.
    expect(summary.per_document.map((d) => d.doc_id)).toEqual(["dpa", "msa"]);
    expect(summary.per_document[1]!.digest).toMatch(/review the critical findings first/);
    expect(summary.per_document[0]!.digest).toMatch(/Clean of critical\/warning/);
  });
});
