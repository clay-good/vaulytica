/**
 * The full attorney-facing DOCX report, from a script.
 *
 * This is the artifact the whole tool's output is shaped around — the cover,
 * the honesty caveats, the compliance matrix, the findings with their cited
 * bases, the audit trail. The browser tab has downloaded it since v1. The CLI
 * could not produce it **at all** until 9.570.0: `--format` accepted sixteen
 * values and none of them was the report.
 *
 * `docx-comments` is a different artifact and always was — a byte-copy of the
 * caller's own .docx with anchored Word comments. Having one is not having the
 * other, and the similar name is part of why nobody noticed.
 *
 * 🚨 `export-reach.test.ts` exists precisely to make this impossible, and it
 * could not see it: it matched `export function build*` and `buildDocxReport`
 * is `export **async** function`. The guard is widened in the same release.
 *
 * What this test asserts is CONTENT, not just "a file appeared": the CLI's
 * bytes must be the browser's builder's bytes, so the headless report cannot
 * quietly become a lesser one.
 */

import { describe, expect, it, afterAll } from "vitest";
import { mkdtemp, readFile, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { unzipSync, strFromU8 } from "fflate";

import { runAnalyze } from "../../tools/cli/run.js";

const NDA = join(process.cwd(), "tests", "fixtures", "specimens", "mutual-nda-letter.txt");
const dirs: string[] = [];
afterAll(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

async function out(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), "vaulytica-docx-"));
  dirs.push(d);
  return d;
}

function documentXml(bytes: Uint8Array): string {
  return strFromU8(unzipSync(bytes)["word/document.xml"]!);
}

/**
 * Two things in a DOCX render differ between two runs of the *same* analysis,
 * and both were found by writing this comparison rather than assumed:
 *
 *   1. The audit trail prints each rule's own elapsed **wall-clock** time
 *      ("CHOICE-001 v1.2.0 — silent (3.088 ms)"). That timing lives outside
 *      `result_hash` by design.
 *   2. The `docx` library assigns **random relationship ids** to hyperlinks
 *      (`r:id="rIdeqtdwimnu2zefnpnxgk__"`), so every citation link differs.
 *
 * Neither is content. Worth writing down, though: the DOCX container is NOT
 * byte-reproducible run-to-run, and the reproducibility this tool guarantees
 * is `result_hash` — which the report carries and which does not move.
 *
 * Normalize exactly those two and nothing else, so a headless report quietly
 * becoming a lesser one still fails.
 */
function stableXml(bytes: Uint8Array): string {
  return documentXml(bytes)
    .replace(/\(\d+\.\d+ ms\)/g, "(T ms)")
    .replace(/r:id="rId[A-Za-z0-9_-]+"/g, 'r:id="rIdN"');
}

describe("analyze --format docx", () => {
  it("writes the report and it carries the report's own sections", async () => {
    const dir = await out();
    await runAnalyze([NDA, "--format", "docx", "--out", dir]);
    const written = (await readdir(dir)).filter((f) => f.endsWith(".docx"));
    expect(written, "expected one .docx in the output directory").toEqual([
      "mutual-nda-letter.report.docx",
    ]);
    const xml = documentXml(await readFile(join(dir, written[0]!)));
    // The sections that make this the REPORT and not a fix list: the scope of
    // review, the findings, and the disclaimer that must never be dropped.
    expect(xml).toContain("Scope");
    expect(xml).toContain("Findings");
    expect(xml.toLowerCase()).toContain("not legal advice");
    // The ingest's own caveat about pasted text — an honesty caveat the
    // terminal prints and the file must carry too.
    expect(xml).toContain("Pasted text loses document structure");
  });

  it("is byte-identical to the builder the browser calls", async () => {
    // Not "a docx appeared" but "the SAME docx". A headless report that drifts
    // into a lesser one is the failure mode a reach test alone cannot see.
    const dir = await out();
    await runAnalyze([NDA, "--format", "docx", "--out", dir]);
    const fromCli = await readFile(join(dir, "mutual-nda-letter.report.docx"));

    const { analyzeFile } = await import("../../tools/cli/api.js");
    const { buildDocxReport } = await import("../../src/report/docx.js");
    const { loadAccuracyDeps } = await import("../../tools/accuracy/pipeline.js");
    const { extractAll } = await import("../../src/extract/index.js");
    const deps = await loadAccuracyDeps();
    const r = await analyzeFile(NDA, { deps, secondaryFamilies: true });
    const blob = await buildDocxReport(
      r.run,
      r.ingest,
      deps.dkb,
      r.playbook,
      undefined,
      extractAll(r.ingest.tree),
      r.secondary_families.length > 0 ? r.secondary_families : undefined,
      {
        relatedDocuments: r.related_documents.length > 0 ? r.related_documents : undefined,
        secondaryFamiliesOmitted: r.secondary_families_present - r.secondary_families.length,
      },
      undefined,
    );
    // A DOCX zip embeds no timestamp from this builder, but compare the
    // rendered document part rather than the container: that is the content,
    // and it is what a drift would change.
    const a = stableXml(new Uint8Array(await blob.arrayBuffer()));
    const b = stableXml(new Uint8Array(fromCli));
    // Guard the normalization itself: if it ate the whole document, the
    // comparison below would be trivially true.
    expect(a.length).toBeGreaterThan(100_000);
    expect(a).toBe(b);
  }, 120_000);

  it("refuses to write binary to stdout", async () => {
    await expect(runAnalyze([NDA, "--format", "docx"])).rejects.toThrow(/requires --out/);
  });
});
