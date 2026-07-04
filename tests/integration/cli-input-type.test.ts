/**
 * Input-type honesty (fix-cli-input-type-honesty).
 *
 * The supported-extension allowlist used to apply only to directory and
 * glob resolution: a directly named `.rtf` (or any unknown extension —
 * including a renamed binary) fell through to a silent UTF-8 decode and
 * produced a full, confidently worded findings report on whatever the
 * bytes happened to decode to. For an attorney, wrong-but-confident is
 * the exact failure the product exists to avoid. Now: unsupported direct
 * targets are a hard error with no report; `--as-text` is the explicit
 * opt-in for unconventionally named text files.
 */

import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

import { resolveInputs, runAnalyze } from "../../tools/cli/run.js";
import { analyzeFile } from "../../tools/cli/api.js";
import { verifyReproducibilityFromFile, type SavedReport } from "../../tools/cli/verify.js";

const TXT_FIXTURE = join(process.cwd(), "tests", "fixtures", "contracts", "pasted-mutual-nda.txt");
const DOCX_FIXTURE = join(
  process.cwd(),
  "tests",
  "e2e",
  "sample-docs",
  "single",
  "vendor-saas-agreement.docx",
);

const tmp = mkdtempSync(join(tmpdir(), "vaul-input-type-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const rtf = join(tmp, "contract.rtf");
cpSync(TXT_FIXTURE, rtf);
const noExt = join(tmp, "NOTES");
cpSync(TXT_FIXTURE, noExt);

type Captured = { stdout: string; stderr: string; failed: boolean };

/** Run a CLI handler in-process, capturing streams and thrown errors. */
async function capture(fn: () => Promise<void>): Promise<Captured> {
  const out: string[] = [];
  const err: string[] = [];
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);
  const realExit = process.exitCode;
  process.stdout.write = ((s: string | Uint8Array) => {
    out.push(String(s));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((s: string | Uint8Array) => {
    err.push(String(s));
    return true;
  }) as typeof process.stderr.write;
  let failed = false;
  try {
    await fn();
  } catch (e) {
    failed = true;
    err.push(e instanceof Error ? e.message : String(e));
  } finally {
    process.stdout.write = realOut;
    process.stderr.write = realErr;
    process.exitCode = realExit;
  }
  return { stdout: out.join(""), stderr: err.join(""), failed };
}

describe("direct file targets honor the supported-input allowlist", () => {
  it("an unsupported extension is a hard error naming the file and the supported set", async () => {
    await expect(resolveInputs(rtf)).rejects.toThrow(/contract\.rtf.*\.docx.*--as-text/s);
  });

  it("analyze on an .rtf produces no report in json mode (stdout empty, error on stderr)", async () => {
    const c = await capture(() => runAnalyze([rtf, "--format", "json"]));
    expect(c.failed).toBe(true);
    expect(c.stdout).toBe("");
    expect(c.stderr).toContain("contract.rtf");
  });

  it("analyze on an .rtf produces no report in human mode either", async () => {
    const c = await capture(() => runAnalyze([rtf, "--format", "md"]));
    expect(c.failed).toBe(true);
    expect(c.stdout).toBe("");
  });

  it("the unknown-extension UTF-8 fallback is gone at the ingest layer too", async () => {
    // Even a future caller that bypasses resolveInputs cannot silently
    // decode unknown bytes as text.
    await expect(analyzeFile(rtf)).rejects.toThrow(/unsupported input type/);
  });

  it("directory resolution still silently skips unsupported files", async () => {
    const dir = join(tmp, "deals");
    mkdirSync(dir, { recursive: true });
    cpSync(TXT_FIXTURE, join(dir, "a.txt"));
    cpSync(TXT_FIXTURE, join(dir, "b.rtf"));
    const inputs = await resolveInputs(dir);
    expect(inputs.map((p) => basename(p))).toEqual(["a.txt"]);
  });
});

describe("--as-text explicit opt-in", () => {
  it("analyzes an extensionless UTF-8 file with the true byte length stamped", async () => {
    const r = await analyzeFile(noExt, { asText: true });
    expect(r.run.findings.length).toBeGreaterThan(0);
    expect(r.run.source_file.size_bytes).toBe(readFileSync(noExt).byteLength);
  });

  it("round-trips through verify --as-text", async () => {
    const r = await analyzeFile(noExt, { asText: true });
    const saved: SavedReport = {
      run: {
        version: r.run.version,
        dkb_version: r.run.dkb_version,
        playbook_id: r.run.playbook_id,
        source_file: { name: r.run.source_file.name, sha256: r.run.source_file.sha256 },
        result_hash: r.run.result_hash,
      },
      provenance: { engine_version: r.run.version, dkb_version: r.run.dkb_version },
    };
    writeFileSync(join(tmp, "notes-report.json"), JSON.stringify(saved), "utf8");
    const result = await verifyReproducibilityFromFile(saved, noExt, { asText: true });
    expect(result.reproduced).toBe(true);
    expect(result.divergences).toEqual([]);
  });

  it("never applies to a binary container", async () => {
    await expect(analyzeFile(DOCX_FIXTURE, { asText: true })).rejects.toThrow(
      /--as-text cannot apply to a binary \.docx/,
    );
  });

  it("errors without the flag for the same extensionless file", async () => {
    await expect(resolveInputs(noExt)).rejects.toThrow(/unsupported input type/);
  });
});
