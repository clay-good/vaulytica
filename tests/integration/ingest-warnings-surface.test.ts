/**
 * The ingest's warnings must REACH someone.
 *
 * `IngestResult.warnings` had been carefully composed since the beginning and
 * read by nobody: not the browser UI, not the CLI, not any report. Every ingest
 * pushed honest caveats into it — pasted text lost its structure, a PDF fell
 * back to OCR, a DOCX redline was read as if every change were accepted — and
 * every one of them was thrown away at the end of the function that made it.
 *
 * That is worse than not having the warnings. A caveat that exists in the code
 * and not on the screen reads, to anyone auditing the source, like a caveat the
 * user was given.
 *
 * These tests pin the two surfaces. The browser side is pinned separately, in
 * `src/ui/states.test.ts` ("input notice").
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const dir = mkdtempSync(join(tmpdir(), "vaulytica-ingest-warn-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const TXT = join(dir, "nda.txt");
writeFileSync(
  TXT,
  [
    "MUTUAL NONDISCLOSURE AGREEMENT",
    "",
    "This Agreement is between Acme Corp. and Globex Inc.",
    "",
    "1. Each party shall keep the other party's Confidential Information confidential.",
  ].join("\n"),
);

/** Run a CLI handler in-process, capturing stderr. */
async function captureStderr(fn: () => Promise<void>): Promise<string> {
  const err: string[] = [];
  const realErr = process.stderr.write.bind(process.stderr);
  const realExit = process.exitCode;
  process.stderr.write = ((s: string | Uint8Array) => {
    err.push(String(s));
    return true;
  }) as typeof process.stderr.write;
  try {
    await fn();
  } finally {
    process.stderr.write = realErr;
    process.exitCode = realExit;
  }
  return err.join("");
}

describe("the ingest's warnings reach the CLI", () => {
  it("emits each one on stderr, prefixed and named by file", async () => {
    const { runAnalyze } = await import("../../tools/cli/run.js");
    const stderr = await captureStderr(() => runAnalyze([TXT, "--format", "json"]));
    expect(stderr).toContain("vaulytica: warning:");
    expect(stderr).toContain("nda.txt");
    // The paste path's own caveat, which had never been shown to anyone.
    expect(stderr).toContain("loses document structure");
  }, 120_000);

  it("keeps them off stdout, where the JSON lives", async () => {
    const { runAnalyze } = await import("../../tools/cli/run.js");
    const out: string[] = [];
    const realOut = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((s: string | Uint8Array) => {
      out.push(String(s));
      return true;
    }) as typeof process.stdout.write;
    try {
      await captureStderr(() => runAnalyze([TXT, "--format", "json"]));
    } finally {
      process.stdout.write = realOut;
    }
    expect(() => JSON.parse(out.join(""))).not.toThrow();
  }, 120_000);
});
