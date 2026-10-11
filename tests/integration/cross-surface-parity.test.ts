/**
 * TRUE cross-surface parity (fix-cli-browser-parity).
 *
 * The old parity test drove both of its "sides" through the same Node
 * pipeline, so it never noticed that the shipped CLI ran a different
 * knowledge base (the starter test fixture) and a different
 * `size_bytes` basis (`sections.length`) than the browser — making
 * every browser-saved report unverifiable headless.
 *
 * This test runs the REAL browser pipeline module (`src/ui/pipeline.ts`
 * — `prepareDocument` + `runReport`, with its DKB/playbook fetches
 * served from the same artifact bytes the site ships) and the REAL CLI
 * entry (`analyzeFile`) on the same fixture DOCX, and asserts the
 * resulting `EngineRun` — including `result_hash` — is identical.
 * `executed_at` is wall-clock on the browser side and blanked by the
 * CLI; it is excluded from `result_hash` by design, so it is normalized
 * before comparison.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

import { PASTED_TEXT_NAME, pastedTextFile } from "../../src/ui/dropzone.js";
import { prepareDocument, runReport } from "../../src/ui/pipeline.js";
import { analyzeFile, loadAccuracyDeps } from "../../tools/cli/api.js";
import { resolveDkbDir } from "../../tools/dkb/resolve.js";

const FIXTURE = join(
  process.cwd(),
  "tests",
  "e2e",
  "sample-docs",
  "single",
  "vendor-saas-agreement.docx",
);
const DKB_DIR = resolveDkbDir();
const PLAYBOOK_DIR = join(process.cwd(), "playbooks");

// Serve the browser pipeline's same-origin fetches (`/x-dkb/*`,
// `/x-playbooks/*`) from the exact artifact bytes on disk.
const realFetch = globalThis.fetch;
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  const serve = (dir: string, name: string): Response => {
    try {
      return new Response(readFileSync(join(dir, name)), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    } catch {
      return new Response("not found", { status: 404 });
    }
  };
  if (url.startsWith("/x-dkb/"))
    return Promise.resolve(serve(DKB_DIR, url.slice("/x-dkb/".length)));
  if (url.startsWith("/x-playbooks/")) {
    return Promise.resolve(serve(PLAYBOOK_DIR, url.slice("/x-playbooks/".length)));
  }
  return realFetch(input, init);
}) as typeof fetch;
afterAll(() => {
  globalThis.fetch = realFetch;
});

// `executed_at` (wall-clock stamp) and per-rule `elapsed_ms` (timing) are
// the two fields excluded from `result_hash` by design; normalize them so
// the remaining comparison is full-run identity.
const blank = <T extends { executed_at: string; execution_log: Array<{ elapsed_ms?: number }> }>(
  run: T,
): T => ({
  ...run,
  executed_at: "",
  execution_log: run.execution_log.map((e) => ({ ...e, elapsed_ms: 0 })),
});

describe("cross-surface parity: browser pipeline vs CLI (same DOCX, same DKB)", () => {
  it("produces an identical EngineRun, including result_hash", async () => {
    const bytes = readFileSync(FIXTURE);

    // Browser surface: the shipped pipeline module, DKB loaded through
    // the same loader + schema validation the deployed app runs.
    const file = new File([new Uint8Array(bytes)], basename(FIXTURE));
    const prepared = await prepareDocument(file, "docx", {
      dkb_base: "/x-dkb",
      playbook_base: "/x-playbooks",
    });
    const ui = await runReport(prepared);

    // CLI surface: the real headless entry, default DKB resolution.
    const cli = await analyzeFile(FIXTURE);

    expect(prepared.dkb.manifest.version).toBe(cli.run.dkb_version);
    expect(ui.run.result_hash).toBe(cli.run.result_hash);
    expect(ui.run.source_file).toEqual(cli.run.source_file);
    expect(ui.run.source_file.size_bytes).toBe(bytes.byteLength);
    // Full-run identity (executed_at normalized — excluded from result_hash).
    expect(blank(ui.run)).toEqual(blank(cli.run));
    expect(JSON.stringify(blank(ui.run))).toBe(JSON.stringify(blank(cli.run)));
  });

  it("pasted text in the tab hashes as pasted-text.txt does on the command line", async () => {
    // spec-v50 §1. The name is inside `result_hash`, so the paste box and
    // `vaulytica analyze pasted-text.txt` must agree on it, on the decoding,
    // and on the byte count.
    const sample = join(
      process.cwd(),
      "tests",
      "e2e",
      "sample-docs",
      "pasted-services-agreement.txt",
    );
    const text = readFileSync(sample, "utf8");

    const pasted = pastedTextFile(text);
    if (!pasted.ok) throw new Error(pasted.reason);
    const prepared = await prepareDocument(pasted.file, pasted.kind, {
      dkb_base: "/x-dkb",
      playbook_base: "/x-playbooks",
    });
    const ui = await runReport(prepared);

    const dir = mkdtempSync(join(tmpdir(), "vaulytica-paste-"));
    const onDisk = join(dir, PASTED_TEXT_NAME);
    writeFileSync(onDisk, text);
    const cli = await analyzeFile(onDisk);
    rmSync(dir, { recursive: true, force: true });

    expect(ui.run.source_file).toEqual(cli.run.source_file);
    expect(ui.run.result_hash).toBe(cli.run.result_hash);
    expect(JSON.stringify(blank(ui.run))).toBe(JSON.stringify(blank(cli.run)));
    // And it is read as a document: a type was matched and rules ran.
    expect(ui.run.playbook_id).not.toBe("generic-fallback");
  });

  it("a dropped .md file with a byte-order mark hashes the same on both surfaces", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vaulytica-md-"));
    const onDisk = join(dir, "terms.md");
    const bytes = Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      readFileSync(
        join(process.cwd(), "tests", "fixtures", "specimens", "mutual-nda-complete.txt"),
      ),
    ]);
    writeFileSync(onDisk, bytes);
    const prepared = await prepareDocument(new File([new Uint8Array(bytes)], "terms.md"), "text", {
      dkb_base: "/x-dkb",
      playbook_base: "/x-playbooks",
    });
    const ui = await runReport(prepared);
    const cli = await analyzeFile(onDisk);
    rmSync(dir, { recursive: true, force: true });
    expect(ui.run.source_file).toEqual(cli.run.source_file);
    expect(ui.run.result_hash).toBe(cli.run.result_hash);
  });

  it("would catch a CLI running a different DKB (the shipped defect)", async () => {
    const starterDeps = await loadAccuracyDeps({
      dkbDir: join(process.cwd(), "dkb", "dist", "v0.0.1-starter"),
    });
    const pinned = await analyzeFile(FIXTURE, { deps: starterDeps });
    const latest = await analyzeFile(FIXTURE);
    expect(pinned.run.dkb_version).not.toBe(latest.run.dkb_version);
    expect(pinned.run.result_hash).not.toBe(latest.run.result_hash);
  });
});
