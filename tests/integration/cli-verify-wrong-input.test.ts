/**
 * `verify` re-derives a saved report's `result_hash` — and every OTHER `.json`
 * this tool touches is a custom playbook.
 *
 * So pointing it at one is the natural wrong guess, the mirror of the mistake
 * `cli-diff-wrong-input.test.ts` names for `diff`. Unchecked, the shape
 * mismatch surfaced as:
 *
 *     vaulytica: Cannot read properties of undefined (reading 'findings')
 *
 * — true, internal, and silent about the mistake. This command's one audience
 * is someone auditing a receipt, often not the person who produced it; a
 * TypeError tells them nothing about which file to pass instead.
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { runVerify } from "../../tools/cli/run.js";

const SPECIMEN = join(process.cwd(), "tests", "fixtures", "specimens", "msa-complete.txt");

async function stderrOf(argv: string[]): Promise<{ err: string; code: number | undefined }> {
  const chunks: string[] = [];
  const spy = vi.spyOn(process.stderr, "write").mockImplementation((c: unknown) => {
    chunks.push(String(c));
    return true;
  });
  const prev = process.exitCode;
  process.exitCode = undefined;
  try {
    await runVerify(argv).catch((e: unknown) => {
      process.stderr.write(`vaulytica: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exitCode = 1;
    });
    return { err: chunks.join(""), code: process.exitCode as number | undefined };
  } finally {
    spy.mockRestore();
    process.exitCode = prev;
  }
}

describe("verify, handed the wrong kind of JSON", () => {
  it("names a custom playbook as a playbook, and points at the command that does diff them", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vaulytica-verify-"));
    const pb = join(dir, "team.json");
    writeFileSync(
      pb,
      JSON.stringify({ id: "team", catalog_version: "1", rules: [], rule_overrides: {} }),
    );
    const { err, code } = await stderrOf([pb, SPECIMEN]);
    expect(err).toContain("looks like a custom playbook");
    expect(err, "it must point at the command that does do this").toContain("vaulytica diff");
    // 🚨 The defect, stated as an assertion: no internal error text.
    expect(err).not.toContain("Cannot read properties");
    expect(code).toBe(1);
  }, 120_000);

  it("names a posture-coherence artifact, the third shape this tool writes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vaulytica-verify-coh-"));
    const coh = join(dir, "r1.coherence.json");
    writeFileSync(
      coh,
      JSON.stringify({
        schema: "vaulytica.posture-coherence.v2",
        coherence_hash: "x",
        dimensions: [],
      }),
    );
    const { err, code } = await stderrOf([coh, SPECIMEN]);
    expect(err).toContain("looks like a posture-coherence artifact");
    expect(err).not.toContain("Cannot read properties");
    expect(code).toBe(1);
  }, 120_000);

  it("names any other JSON as not a report, and says what to pass instead", async () => {
    const { err, code } = await stderrOf(["package.json", SPECIMEN]);
    expect(err).toContain("is not a Vaulytica analysis report or verification certificate");
    expect(err, "it must say which command writes one").toContain("--format json");
    expect(err).not.toContain("Cannot read properties");
    expect(code).toBe(1);
  }, 120_000);
});
