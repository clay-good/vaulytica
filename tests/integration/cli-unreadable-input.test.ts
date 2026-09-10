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

  it("records the missing file IN THE REPORT, not only on stderr", async () => {
    // `BundleReportInput.rejected` and its "Skipped Files" appendix have
    // existed since the browser's `planBundle` gained rejections (unsupported
    // extension, oversized). A corrupt container is the same kind of absence
    // and the CLI simply never filled the field, so a colleague handed
    // `bundle.json` saw a report on three documents with nothing saying the
    // deal room held four. Same shape as 9.659.0, one level up: the caveat
    // reached the terminal that ran the command and not the artifact that
    // outlives it.
    const dir = roomWithOneCorruptFile(3);
    const out = mkdtempSync(join(tmp, "out-"));
    await capture([dir, "--consistency", "--format", "bundle-json", "--out", out]);
    const raw = readFileSync(join(out, "bundle.json"), "utf8");
    expect(raw).toContain("broken.docx");
    const bundle = JSON.parse(raw) as {
      rejected?: Array<{ filename: string; reason: string }>;
    };
    expect(bundle.rejected).toHaveLength(1);
    expect(bundle.rejected![0]!.filename).toBe("broken.docx");
    expect(bundle.rejected![0]!.reason).toMatch(/zip|central directory/i);
  }, 300_000);

  it("says nothing of the kind when every file could be read", async () => {
    // The field is optional and omitting it preserves the prior renderer
    // output verbatim, so a clean run must not grow a "Skipped Files" section.
    const dir = mkdtempSync(join(tmp, "clean-"));
    const picks = readdirSync(SPECIMENS)
      .filter((f) => f.endsWith("-complete.txt"))
      .sort()
      .slice(0, 3);
    for (const f of picks) writeFileSync(join(dir, f), readFileSync(join(SPECIMENS, f), "utf8"));
    const out = mkdtempSync(join(tmp, "out-"));
    const c = await capture([dir, "--consistency", "--format", "bundle-json", "--out", out]);
    expect(c.exitCode ?? 0).toBe(0);
    const bundle = JSON.parse(readFileSync(join(out, "bundle.json"), "utf8")) as {
      rejected?: unknown[];
    };
    expect(bundle.rejected).toBeUndefined();
  }, 300_000);

  it("names the files a directory walk skipped for their extension", async () => {
    // Naming `notes.rtf` directly is a hard error that says "unsupported input
    // type"; leaving the same file in a folder used to produce a report that
    // pretended it was not there. That asymmetry is not cosmetic, because the
    // cross-document engine reasons about what the bundle CONTAINS: put
    // `dpa.doc` in a deal room and CROSS-MISSING-001 reports the DPA missing
    // from a bundle the user believes holds one.
    const dir = mkdtempSync(join(tmp, "mixed-"));
    const picks = readdirSync(SPECIMENS)
      .filter((f) => f.endsWith("-complete.txt"))
      .sort()
      .slice(0, 2);
    for (const f of picks) writeFileSync(join(dir, f), readFileSync(join(SPECIMENS, f), "utf8"));
    writeFileSync(join(dir, "logo.png"), Buffer.from("89504e470d0a1a0a", "hex"));
    writeFileSync(join(dir, "amendment.doc"), "an old-format Word file");

    const out = mkdtempSync(join(tmp, "out-"));
    const c = await capture([dir, "--consistency", "--format", "bundle-json", "--out", out]);

    expect(c.stderr).toContain("were skipped");
    expect(c.stderr).toContain("logo.png");
    expect(c.stderr).toContain("amendment.doc");
    // The reason a reader needs: a document it cannot read is one it cannot
    // see in the bundle.
    expect(c.stderr).toContain("cannot see in the bundle");

    // And in the artifact, not only the terminal.
    const bundle = JSON.parse(readFileSync(join(out, "bundle.json"), "utf8")) as {
      rejected?: Array<{ filename: string }>;
      runs?: unknown[];
    };
    expect(bundle.runs?.length ?? 0).toBe(2);
    expect((bundle.rejected ?? []).map((r) => r.filename).sort()).toEqual([
      "amendment.doc",
      "logo.png",
    ]);
  }, 300_000);

  it("skipping an unsupported file is not a failure", async () => {
    // Unlike a corrupt container, this is correct behaviour: a deal room holds
    // a logo and a README, and the run did exactly what it should. It just has
    // to say so. The exit code must not move.
    const dir = mkdtempSync(join(tmp, "mixed2-"));
    const picks = readdirSync(SPECIMENS)
      .filter((f) => f.endsWith("-complete.txt"))
      .sort()
      .slice(0, 2);
    for (const f of picks) writeFileSync(join(dir, f), readFileSync(join(SPECIMENS, f), "utf8"));
    writeFileSync(join(dir, "logo.png"), Buffer.from("89504e470d0a1a0a", "hex"));
    const out = mkdtempSync(join(tmp, "out-"));
    const c = await capture([dir, "--consistency", "--format", "bundle-json", "--out", out]);
    expect(c.exitCode ?? 0).toBe(0);
  }, 300_000);

  it("a SINGLE unreadable input is still a hard error", async () => {
    // Nothing to survive for: the error is the answer.
    const dir = mkdtempSync(join(tmp, "solo-"));
    writeFileSync(join(dir, "broken.docx"), Buffer.from("PKgarbage", "latin1"));
    await expect(capture([join(dir, "broken.docx"), "--format", "json"])).rejects.toThrow();
  }, 300_000);
});
