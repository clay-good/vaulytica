/**
 * Delivery completeness (fix-cli-output-completeness): every rendered
 * artifact has a destination, or the command fails loudly. Before this
 * fix, `analyze x --format json,md` (or two inputs with one format)
 * without `--out` rendered everything, delivered nothing, printed one
 * summary line, and exited 0 — a scripted consumer had no signal that
 * output was withheld.
 */

import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { runAnalyze } from "../../tools/cli/run.js";

const TXT_FIXTURE = join(process.cwd(), "tests", "fixtures", "contracts", "pasted-mutual-nda.txt");

const tmp = mkdtempSync(join(tmpdir(), "vaul-output-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

type Captured = { stdout: string; failed: string | null };

async function capture(argv: string[]): Promise<Captured> {
  const out: string[] = [];
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);
  const realExit = process.exitCode;
  process.stdout.write = ((s: string | Uint8Array) => {
    out.push(String(s));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  let failed: string | null = null;
  try {
    await runAnalyze(argv);
  } catch (e) {
    failed = e instanceof Error ? e.message : String(e);
  } finally {
    process.stdout.write = realOut;
    process.stderr.write = realErr;
    process.exitCode = realExit;
  }
  return { stdout: out.join(""), failed };
}

describe("multi-format / multi-input without --out is a hard usage error", () => {
  it("--format json,md without --out fails naming the fix, delivers nothing silently", async () => {
    const c = await capture([TXT_FIXTURE, "--format", "json,md"]);
    expect(c.failed).toContain("--out");
    expect(c.stdout).toBe("");
  });

  it("two inputs with one format without --out fails", async () => {
    const dir = join(tmp, "two-inputs");
    mkdirSync(dir, { recursive: true });
    cpSync(TXT_FIXTURE, join(dir, "a.txt"));
    cpSync(TXT_FIXTURE, join(dir, "b.txt"));
    const c = await capture([dir, "--format", "json"]);
    expect(c.failed).toContain("--out");
  });

  it("the same combinations WITH --out write every requested artifact", async () => {
    const out = join(tmp, "delivered");
    const c = await capture([TXT_FIXTURE, "--format", "json,md", "--out", out]);
    expect(c.failed).toBeNull();
    expect(existsSync(join(out, "pasted-mutual-nda.json"))).toBe(true);
    expect(existsSync(join(out, "pasted-mutual-nda.fixlist.md"))).toBe(true);
  });

  it("single input × single format still streams to stdout", async () => {
    const c = await capture([TXT_FIXTURE, "--format", "json"]);
    expect(c.failed).toBeNull();
    expect(() => JSON.parse(c.stdout) as unknown).not.toThrow();
  });
});

describe("--format value validation", () => {
  it("an empty --format value is a usage error listing the valid set", async () => {
    const c = await capture([TXT_FIXTURE, "--format", ""]);
    expect(c.failed).toContain("json, sarif, html, md, csv");
  });

  it("an unknown format is a usage error", async () => {
    const c = await capture([TXT_FIXTURE, "--format", "pdf"]);
    expect(c.failed).toContain('unknown --format "pdf"');
  });

  it("duplicate formats are a usage error", async () => {
    const c = await capture([TXT_FIXTURE, "--format", "json,json"]);
    expect(c.failed).toContain("duplicate");
  });
});
