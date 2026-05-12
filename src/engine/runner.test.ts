import { describe, expect, it } from "vitest";
import type { Rule, RuleContext, Finding } from "./finding.js";
import { runEngine, ENGINE_VERSION } from "./runner.js";
import { LAUNCH_RULES } from "./rules/index.js";
import { buildContext } from "./_test-fixtures.js";

function fakeRule(id: string, fires: boolean): Rule {
  return {
    id,
    version: "1.0.0",
    name: id,
    category: "test",
    default_severity: "info",
    description: "test",
    dkb_citations: [],
    check(_ctx: RuleContext): Finding | null {
      if (!fires) return null;
      return {
        id: `${id}-1`,
        rule_id: id,
        rule_version: "1.0.0",
        severity: "info",
        title: id,
        description: "",
        excerpt: { text: "", start_offset: 0, end_offset: 0 },
        explanation: "",
        source_citations: [],
        document_position: 0,
      };
    },
  };
}

describe("runEngine — determinism", () => {
  it("produces identical result_hash on repeated runs", async () => {
    const ctx = buildContext([
      "Agreement",
      'This Agreement is between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer"). Effective Date: 2025-01-01.',
      "Provider shall provide the Services. By: ____ Name: ____ Title: ____ Date: ____",
    ]);
    const a = await runEngine({
      rules: LAUNCH_RULES,
      ctx,
      source_file: { name: "demo.docx", sha256: "0".repeat(64), size_bytes: 100 },
    });
    const b = await runEngine({
      rules: LAUNCH_RULES,
      ctx,
      source_file: { name: "demo.docx", sha256: "0".repeat(64), size_bytes: 100 },
    });
    expect(a.result_hash).toEqual(b.result_hash);
    expect(a.result_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("excludes executed_at from the hash", async () => {
    const ctx = buildContext(["H", "Body."]);
    const a = await runEngine({
      rules: LAUNCH_RULES,
      ctx,
      source_file: { name: "x", sha256: "0".repeat(64), size_bytes: 1 },
      executed_at: "2026-01-01T00:00:00Z",
    });
    const b = await runEngine({
      rules: LAUNCH_RULES,
      ctx,
      source_file: { name: "x", sha256: "0".repeat(64), size_bytes: 1 },
      executed_at: "2099-12-31T23:59:59Z",
    });
    expect(a.result_hash).toEqual(b.result_hash);
  });

  it("sorts rules by id, regardless of input order", async () => {
    const ctx = buildContext(["H", "Body."]);
    const rules = [fakeRule("ZZZ-002", true), fakeRule("AAA-001", true)];
    const run = await runEngine({
      rules,
      ctx,
      source_file: { name: "x", sha256: "0".repeat(64), size_bytes: 1 },
    });
    const ids = run.execution_log.map((e) => e.rule_id);
    expect(ids).toEqual(["AAA-001", "ZZZ-002"]);
  });

  it("records 'fired: false' for silent rules", async () => {
    const ctx = buildContext(["H", "Body."]);
    const rules = [fakeRule("A", false), fakeRule("B", true)];
    const run = await runEngine({
      rules,
      ctx,
      source_file: { name: "x", sha256: "0".repeat(64), size_bytes: 1 },
    });
    const silent = run.execution_log.find((e) => e.rule_id === "A");
    expect(silent?.fired).toBe(false);
    expect(silent?.finding_id).toBeUndefined();
  });

  it("respects playbook overrides: skip and severity", async () => {
    const ctx = buildContext(["H", "Body."]);
    ctx.playbook = {
      id: "generic-fallback",
      version: "1.0.0",
      rule_overrides: {
        A: { skip: true },
        B: { severity: "critical" },
      },
    };
    const rules = [fakeRule("A", true), fakeRule("B", true)];
    const run = await runEngine({
      rules,
      ctx,
      source_file: { name: "x", sha256: "0".repeat(64), size_bytes: 1 },
    });
    expect(run.findings.find((f) => f.rule_id === "A")).toBeUndefined();
    expect(run.findings.find((f) => f.rule_id === "B")?.severity).toBe("critical");
  });

  it("embeds the engine and DKB versions", async () => {
    const ctx = buildContext(["H", "Body."]);
    const run = await runEngine({
      rules: [],
      ctx,
      source_file: { name: "x", sha256: "0".repeat(64), size_bytes: 1 },
    });
    expect(run.version).toBe(ENGINE_VERSION);
    expect(run.dkb_version).toBe(ctx.dkb.manifest.version);
  });
});
