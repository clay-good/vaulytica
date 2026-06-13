import { describe, expect, it } from "vitest";
import { LAUNCH_RULES } from "./index.js";
import { runEngine } from "../runner.js";
import { buildContext } from "../_test-fixtures.js";

describe("Launch rule registry", () => {
  it("ships exactly 115 rules (80 launch + 32 post-1.0 + 3 v9 Thrust-B reconciliation)", () => {
    expect(LAUNCH_RULES.length).toBe(115);
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
});

describe("Engine + all 115 rules", () => {
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
    expect(a.execution_log.length).toBe(115);
  });
});
