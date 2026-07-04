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

import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

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
