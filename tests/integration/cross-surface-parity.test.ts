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
import {
  prepareDocument,
  runExecutedComparison,
  runRedlineComparison,
  runReport,
} from "../../src/ui/pipeline.js";
import { checkConformity } from "../../src/report/conformity.js";
import { EXECUTED, FINAL } from "../../src/report/_conformity-fixtures.js";
import { compareRuns } from "../../src/report/compare.js";
import { attributeRevisions } from "../../src/report/redline-attribution.js";
import { redlineDocx } from "../../src/delivery/_fixtures.js";
import {
  analyzeFile,
  compareExecuted,
  compareRedline,
  loadAccuracyDeps,
} from "../../tools/cli/api.js";
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

  it("a redline's two readings compare to the same hash on both surfaces", async () => {
    // add-redline-two-sided-analysis task 6: the tab's "Compare both sides of
    // this redline" is the CLI's `compare --redline` on the same bytes.
    const bytes = redlineDocx();
    const dir = mkdtempSync(join(tmpdir(), "vaulytica-redline-parity-"));
    const onDisk = join(dir, "supply-redline.docx");
    writeFileSync(onDisk, Buffer.from(bytes));
    const cli = await compareRedline(onDisk);
    rmSync(dir, { recursive: true, force: true });

    const ui = await runRedlineComparison(
      new File([bytes], "supply-redline.docx"),
      {},
      { dkb_base: "/x-dkb", playbook_base: "/x-playbooks" },
    );
    expect(ui.base.run.source_file).toEqual(cli.base.run.source_file);
    expect(ui.base.run.result_hash).toBe(cli.base.run.result_hash);
    expect(ui.revised.run.playbook_id).toBe(ui.base.run.playbook_id);
    expect(ui.revised.run.result_hash).toBe(cli.revised.run.result_hash);
    const cmp = await compareRuns(ui.base.run, ui.revised.run);
    expect(cmp.result_hash).toBe(cli.comparison.result_hash);
    expect(attributeRevisions(cmp, ui.revisions)).toEqual(cli.revision_authors);
  });

  it("a signed copy checks against its final to the same hashes on both surfaces", async () => {
    // add-executed-copy-conformity task 6: the tab's "Check a signed copy
    // against this final…" is `compare --executed` on the same bytes.
    const dir = mkdtempSync(join(tmpdir(), "vaulytica-executed-parity-"));
    const finalPath = join(dir, "consulting-final.txt");
    const signedPath = join(dir, "consulting-signed.txt");
    writeFileSync(finalPath, FINAL);
    writeFileSync(signedPath, EXECUTED.replace("$12,500", "$21,500"));
    const cli = await compareExecuted(finalPath, signedPath);
    rmSync(dir, { recursive: true, force: true });

    const config = { dkb_base: "/x-dkb", playbook_base: "/x-playbooks" };
    const final = await runReport(
      await prepareDocument(new File([FINAL], "consulting-final.txt"), "text", config),
    );
    const signed = await runExecutedComparison(
      new File([EXECUTED.replace("$12,500", "$21,500")], "consulting-signed.txt"),
      "text",
      final.run.playbook_id,
      {},
      config,
    );
    expect(final.run.result_hash).toBe(cli.base.run.result_hash);
    expect(signed.run.result_hash).toBe(cli.revised.run.result_hash);
    expect((await compareRuns(final.run, signed.run)).result_hash).toBe(cli.comparison.result_hash);
    const conformity = await checkConformity(final.ingest.tree, signed.ingest.tree);
    expect(conformity.verdict).toBe("differences");
    expect(conformity.conformity_hash).toBe(cli.conformity.conformity_hash);
  });

  it("an asserted readability standard runs the same rules to the same hash", async () => {
    // add-readability-measure: the tab's readability option is the CLI's --readability.
    const text =
      "HOMEOWNERS INSURANCE POLICY\n\nThe insurer's obligation to indemnify the insured for consequential, incidental, or derivative losses occasioned by any peril enumerated in the declarations shall be determined exclusively in accordance with the applicable valuation methodology and the limitations, conditions, and exclusions specified in this policy.\n";
    const pasted = pastedTextFile(text);
    if (!pasted.ok) throw new Error(pasted.reason);
    const prepared = await prepareDocument(pasted.file, pasted.kind, {
      dkb_base: "/x-dkb",
      playbook_base: "/x-playbooks",
    });
    const ui = await runReport(prepared, {}, { readability: "fl" });
    const dir = mkdtempSync(join(tmpdir(), "vaulytica-read-parity-"));
    const onDisk = join(dir, PASTED_TEXT_NAME);
    writeFileSync(onDisk, text);
    const cli = await analyzeFile(onDisk, { readability: "fl" });
    rmSync(dir, { recursive: true, force: true });
    expect(ui.run.asserted_readability).toBe("fl");
    expect(ui.run.findings.map((f) => f.rule_id)).toContain("READ-001");
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
