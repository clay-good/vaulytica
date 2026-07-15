import { describe, expect, it } from "vitest";
import { buildProductionQaReport, hasProductionGap } from "./report.js";
import type { DeliveryReport } from "../delivery/types.js";

describe("buildProductionQaReport", () => {
  it("reconciles a production set with a gap and an overlapping log entry", async () => {
    const report = await buildProductionQaReport({
      filenames: ["ACME_000001.pdf", "ACME_000002.pdf", "ACME_000004.pdf", "privlog.csv"],
      logCsv:
        "BegBates,EndBates,Privilege,Description\nACME_000002,ACME_000002,Attorney-Client,Email\n",
    });
    expect(report.member_count).toBe(4);
    expect(report.log_present).toBe(true);
    const codes = report.findings.map((f) => f.code);
    expect(codes).toContain("PROD-001"); // gap at 000003
    expect(codes).toContain("PROD-010"); // 000002 claimed withheld but produced
    expect(report.production_qa_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hasProductionGap(report)).toBe(true);
  });

  it("a clean, fully-logged production has no gap findings", async () => {
    const report = await buildProductionQaReport({
      filenames: ["ACME_000001.pdf", "ACME_000002.pdf", "ACME_000003.pdf"],
    });
    expect(report.log_present).toBe(false);
    expect(hasProductionGap(report)).toBe(false);
    expect(report.findings.every((f) => f.code !== "PROD-001")).toBe(true);
  });

  it("rolls up per-member delivery scans", async () => {
    const del = (rule: string): DeliveryReport => ({
      source: "docx",
      inspectable: true,
      findings: [
        {
          rule_id: rule,
          severity: "warning",
          title: rule,
          description: "",
          count: 1,
          evidence: [],
        },
      ],
      summary: "",
      delivery_hash: "0".repeat(64),
    });
    const report = await buildProductionQaReport({
      filenames: ["ACME_000001.docx", "ACME_000002.docx"],
      deliveries: [del("HANDOFF-001"), del("HANDOFF-004")],
    });
    expect(report.delivery_rollup!.members_scanned).toBe(2);
    expect(report.delivery_rollup!.by_check["HANDOFF-001"]).toBe(1);
    expect(report.delivery_rollup!.by_check["HANDOFF-004"]).toBe(1);
  });

  it("the hash is deterministic and independent of delivery when absent", async () => {
    const args = { filenames: ["A_0001.pdf", "A_0002.pdf"] };
    const a = await buildProductionQaReport(args);
    const b = await buildProductionQaReport(args);
    expect(a.production_qa_hash).toBe(b.production_qa_hash);
    expect(a.delivery_rollup).toBeUndefined();
  });

  it("always renders the presence-only scope of review", async () => {
    const report = await buildProductionQaReport({ filenames: ["A_0001.pdf"] });
    expect(report.scope.reviewed_for.length).toBeGreaterThan(0);
    expect(report.scope.not_reviewed_for.some((s) => /redaction integrity/i.test(s))).toBe(true);
    expect(report.scope.not_reviewed_for.some((s) => /validity of any privilege/i.test(s))).toBe(
      true,
    );
  });
});
