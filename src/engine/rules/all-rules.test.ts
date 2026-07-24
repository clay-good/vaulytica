import { describe, expect, it } from "vitest";
import { LAUNCH_RULES } from "./index.js";
import { runEngine } from "../runner.js";
import { buildContext } from "../_test-fixtures.js";

describe("Launch rule registry", () => {
  it("ships exactly 119 rules (80 launch + 36 post-1.0 + 3 v9 Thrust-B reconciliation)", () => {
    expect(LAUNCH_RULES.length).toBe(119);
  });

  it("has unique rule ids", () => {
    const ids = LAUNCH_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every rule has a non-empty version, name, category, description", () => {
    for (const r of LAUNCH_RULES) {
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.name.length, r.id).toBeGreaterThan(0);
      expect(r.category.length, r.id).toBeGreaterThan(0);
      expect(r.description.length, r.id).toBeGreaterThan(0);
    }
  });

  it("ids belong to the documented categories", () => {
    const prefix = /^(STRUCT|FIN|TEMP|OBLI|RISK|CHOICE|TERM|IPDATA|PERS|DARK)-\d{3}$/;
    for (const r of LAUNCH_RULES) expect(r.id, r.id).toMatch(prefix);
  });

  // Pins the per-category breakdown the README publishes and the inline
  // section comments in index.ts annotate. Without this guard the comments
  // silently drift as rules are added (they had: e.g. "Personnel — 4" while
  // PERS-001..009 shipped). The counts must sum to LAUNCH_RULES.length.
  it("matches the documented per-category rule counts", () => {
    const expected: Record<string, number> = {
      STRUCT: 19,
      FIN: 9,
      TEMP: 12,
      OBLI: 9,
      RISK: 17,
      CHOICE: 12,
      TERM: 9,
      IPDATA: 10,
      PERS: 9,
      DARK: 13,
    };
    const actual: Record<string, number> = {};
    for (const r of LAUNCH_RULES) {
      const prefix = r.id.slice(0, r.id.indexOf("-"));
      actual[prefix] = (actual[prefix] ?? 0) + 1;
    }
    expect(actual).toEqual(expected);
    const sum = Object.values(expected).reduce((a, b) => a + b, 0);
    expect(sum).toBe(LAUNCH_RULES.length);
  });
});

describe("Engine + all 119 rules", () => {
  it("runs end-to-end on a minimal context and is deterministic", async () => {
    const ctx = buildContext([
      "Agreement",
      'This Agreement is between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer"). Effective Date: 2025-01-01.',
      "Provider shall provide the Services. By: ___ Name: ___ Title: ___ Date: ___",
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
    expect(a.execution_log.length).toBe(119);
  });
});
