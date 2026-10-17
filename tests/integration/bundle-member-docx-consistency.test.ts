/**
 * The browser's per-document DOCX inside a bundle carries the §59
 * cross-document consistency appendix.
 *
 * `renderConsistencyAppendix` renders from `V3ReportInputs.consistency`. The
 * CLI's `renderDocxReport` passed the bundle's run; the browser built each
 * member's DOCX in `prepareBundle`, before the consistency run existed, so the
 * report a user downloads from a bundle card never had the appendix. Same
 * bundle, same builder, two different artifacts.
 *
 * And with the §62 toggle OFF the appendix must be absent rather than say "No
 * cross-document conflicts were detected" — that sentence describes checks
 * that ran.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { prepareBundle, runBundleReport } from "../../src/ui/pipeline.js";
import { resolveDkbDir } from "../../tools/dkb/resolve.js";

const BUNDLE_DIR = join(
  process.cwd(),
  "tests",
  "golden",
  "v4",
  "bundles",
  "governing-law-mismatch",
);
const DKB_DIR = resolveDkbDir();
const PLAYBOOK_DIR = join(process.cwd(), "playbooks");

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
  if (url.startsWith("/x-playbooks/"))
    return Promise.resolve(serve(PLAYBOOK_DIR, url.slice("/x-playbooks/".length)));
  return realFetch(input, init);
}) as typeof fetch;
afterAll(() => {
  globalThis.fetch = realFetch;
});

const CONFIG = { dkb_base: "/x-dkb", playbook_base: "/x-playbooks" };
const NAMES = ["msa.txt", "sow.txt", "dpa.txt"];
const HEADING = "Two-Document Consistency";

function docFile(name: string): File {
  return new File([new Uint8Array(readFileSync(join(BUNDLE_DIR, name)))], name);
}

async function docxText(blob: Blob): Promise<string> {
  const { unzipSync, strFromU8 } = await import("fflate");
  const xml = strFromU8(unzipSync(new Uint8Array(await blob.arrayBuffer()))["word/document.xml"]!);
  return (xml.match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? [])
    .map((m) => m.replace(/<[^>]+>/g, ""))
    .join("");
}

describe("a bundle member's own DOCX", () => {
  it("carries the §59 appendix with the bundle's conflicts", async () => {
    const prepared = await prepareBundle(NAMES.map(docFile), {}, CONFIG, {});
    const result = await runBundleReport(prepared);

    // Anti-vacuity: the bundle is named for a conflict, so the run must have one.
    const ruleIds = result.consistency.findings.map((f) => f.rule_id);
    expect(ruleIds.length, "governing-law-mismatch produces conflicts").toBeGreaterThan(0);

    expect(result.documents).toHaveLength(NAMES.length);
    for (const d of result.documents) {
      const text = await docxText(d.docx_blob);
      expect(text, d.filename).toContain(HEADING);
      for (const id of ruleIds) expect(text, `${d.filename} names ${id}`).toContain(id);
      expect(text).toContain(`Consistency result hash: ${result.consistency.result_hash}`);
    }
  }, 120_000);

  it("omits the appendix when the consistency checks were switched off", async () => {
    const prepared = await prepareBundle(NAMES.map(docFile), {}, CONFIG, {});
    const result = await runBundleReport(prepared, { cross_doc_consistency: false });
    for (const d of result.documents) {
      const text = await docxText(d.docx_blob);
      // Anti-vacuity: this is a real report, not an empty zip.
      expect(text, d.filename).toContain("Citation Index");
      expect(text, d.filename).not.toContain(HEADING);
      expect(text).not.toContain("No cross-document conflicts were detected");
    }
  }, 120_000);
});
