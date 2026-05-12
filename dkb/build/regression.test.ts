import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runRegression, summarizeDiffs } from "./regression.js";
import type { EngineRun } from "../../src/engine/finding.js";

function fakeRun(hash: string): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v0.0.1",
    playbook_id: "generic-fallback",
    source_file: { name: "x", sha256: "a".repeat(64), size_bytes: 1 },
    executed_at: "",
    findings: [],
    execution_log: [],
    result_hash: hash,
  };
}

describe("runRegression", () => {
  it("reports a match when hashes agree", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vaulytica-regression-"));
    const contracts = join(dir, "contracts");
    const expected = join(dir, "expected");
    mkdirSync(contracts);
    mkdirSync(expected);
    writeFileSync(join(contracts, "f1.docx"), "ignored");
    writeFileSync(join(expected, "f1.json"), JSON.stringify(fakeRun("abc")));
    const diffs = await runRegression({
      contracts_dir: contracts,
      expected_dir: expected,
      runFixture: async () => fakeRun("abc"),
    });
    expect(diffs).toHaveLength(1);
    expect(diffs[0]?.status).toBe("match");
  });

  it("reports a diff when hashes differ", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vaulytica-regression-"));
    const contracts = join(dir, "contracts");
    const expected = join(dir, "expected");
    mkdirSync(contracts);
    mkdirSync(expected);
    writeFileSync(join(contracts, "f1.docx"), "x");
    writeFileSync(join(expected, "f1.json"), JSON.stringify(fakeRun("expected-hash")));
    const diffs = await runRegression({
      contracts_dir: contracts,
      expected_dir: expected,
      runFixture: async () => fakeRun("actual-hash"),
    });
    expect(diffs[0]?.status).toBe("diff");
  });

  it("reports missing-expected when the golden file does not exist", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vaulytica-regression-"));
    const contracts = join(dir, "contracts");
    const expected = join(dir, "expected");
    mkdirSync(contracts);
    mkdirSync(expected);
    writeFileSync(join(contracts, "new.docx"), "x");
    const diffs = await runRegression({
      contracts_dir: contracts,
      expected_dir: expected,
      runFixture: async () => fakeRun("any"),
    });
    expect(diffs[0]?.status).toBe("missing-expected");
  });

  it("returns [] when the contracts dir does not exist (Step 16 fixtures not yet added)", async () => {
    const diffs = await runRegression({
      contracts_dir: "/nonexistent/path/to/contracts",
      expected_dir: "/nonexistent/path/to/expected",
      runFixture: async () => fakeRun("x"),
    });
    expect(diffs).toEqual([]);
  });
});

describe("summarizeDiffs", () => {
  it("is ok when every fixture matches", () => {
    expect(
      summarizeDiffs([{ fixture: "a", status: "match", message: "" }]).ok,
    ).toBe(true);
  });

  it("lists failing fixtures in the summary when any fail", () => {
    const r = summarizeDiffs([
      { fixture: "a", status: "match", message: "" },
      { fixture: "b", status: "diff", message: "hash drift" },
    ]);
    expect(r.ok).toBe(false);
    expect(r.summary).toContain("b: diff");
  });
});
