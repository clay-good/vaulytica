/**
 * One unreadable file must not poison a bundle.
 *
 * `src/ingest/multi.ts`'s `ingestEntries` has promised exactly this in its own
 * docstring since it was written — *"a single corrupt file does not poison the
 * whole bundle"* — and it delivers it, per file, for the browser. The CLI walks
 * directories itself and never called it, so a deal room of five perfectly
 * readable documents plus one damaged `.docx` produced **no output at all**:
 * `analyzeFile` threw on the corrupt container and the throw escaped the loop.
 *
 * Same shape as the cross-document engine being browser-only. When a behaviour
 * is implemented for one consumer, walk the consumer list.
 *
 * The run still FAILS, and that half matters as much as the other. Reporting a
 * partial bundle as success would be worse than the crash it replaces, so the
 * rejected files are named with their reason and the exit code stays non-zero:
 * CI cannot pass on a deal room the tool could only half read.
 */
import { mkdtempSync, rmSync, writeFileSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const REPO_ROOT = process.cwd();
const SPECIMENS = join(REPO_ROOT, "tests", "fixtures", "specimens");

const tmp = mkdtempSync(join(tmpdir(), "vaul-unreadable-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

type Captured = { stdout: string; stderr: string; exitCode: number | undefined };

async function capture(argv: string[]): Promise<Captured> {
  const { runAnalyze } = await import("../../tools/cli/run.js");
  const out: string[] = [];
  const err: string[] = [];
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);
  const realExit = process.exitCode;
  process.exitCode = undefined;
  process.stdout.write = ((s: string | Uint8Array) => {
    out.push(String(s));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((s: string | Uint8Array) => {
    err.push(String(s));
    return true;
  }) as typeof process.stderr.write;
  let thrown: unknown;
  try {
    await runAnalyze(argv);
  } catch (e) {
    thrown = e;
  } finally {
    process.stdout.write = realOut;
    process.stderr.write = realErr;
  }
  const exitCode = process.exitCode as number | undefined;
  process.exitCode = realExit;
  if (thrown) throw thrown;
  return { stdout: out.join(""), stderr: err.join(""), exitCode };
}

/** A deal room of `n` real specimens plus one file that is not a valid .docx. */
function roomWithOneCorruptFile(n: number): string {
  const dir = mkdtempSync(join(tmp, "room-"));
  const picks = readdirSync(SPECIMENS)
    .filter((f) => f.endsWith("-complete.txt"))
    .sort()
    .slice(0, n);
  for (const f of picks) writeFileSync(join(dir, f), readFileSync(join(SPECIMENS, f), "utf8"));
  // A ZIP local-file-header magic with nothing behind it: the extension says
  // .docx, the bytes cannot be opened.
  writeFileSync(join(dir, "broken.docx"), Buffer.from("PKgarbage", "latin1"));
  return dir;
}

describe("a bundle survives one unreadable file", () => {
  it("analyzes the readable documents and writes the report", async () => {
    const dir = roomWithOneCorruptFile(3);
    const out = mkdtempSync(join(tmp, "out-"));
    await capture([dir, "--consistency", "--format", "bundle-json", "--out", out]);
    expect(readdirSync(out)).toContain("bundle.json");
    const bundle = JSON.parse(readFileSync(join(out, "bundle.json"), "utf8")) as {
      runs?: unknown[];
    };
    expect(bundle.runs?.length ?? 0).toBe(3);
  }, 300_000);

  it("names the file it could not read, and why", async () => {
    const dir = roomWithOneCorruptFile(2);
    const out = mkdtempSync(join(tmp, "out-"));
    const c = await capture([dir, "--consistency", "--format", "bundle-json", "--out", out]);
    expect(c.stderr).toContain("broken.docx");
    expect(c.stderr).toContain("could not be read");
    // The end-of-run roll-up, because the per-file line scrolls away behind the
    // analysis of the documents that DID work.
    expect(c.stderr).toContain("ABSENT from this report");
    expect(c.stderr).toMatch(/1 of 3 input\(s\) could not be read/);
  }, 300_000);

  it("still fails, so CI cannot pass on a half-read deal room", async () => {
    const dir = roomWithOneCorruptFile(2);
    const out = mkdtempSync(join(tmp, "out-"));
    const c = await capture([dir, "--consistency", "--format", "bundle-json", "--out", out]);
    expect(c.exitCode).toBe(1);
  }, 300_000);

  it("a SINGLE unreadable input is still a hard error", async () => {
    // Nothing to survive for: the error is the answer.
    const dir = mkdtempSync(join(tmp, "solo-"));
    writeFileSync(join(dir, "broken.docx"), Buffer.from("PKgarbage", "latin1"));
    await expect(capture([join(dir, "broken.docx"), "--format", "json"])).rejects.toThrow();
  }, 300_000);
});
