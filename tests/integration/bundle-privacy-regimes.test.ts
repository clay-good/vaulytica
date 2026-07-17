/**
 * End-to-end proof that asserted privacy regimes reach the REAL browser
 * bundle pipeline (add-privacy-notice-pack, bundle integration).
 *
 * Each bundle member activates the PNOT pack independently, mirroring the
 * single-document path: a member that matched a privacy-notice playbook gets
 * the asserted regimes' presence rules and carries `asserted_regimes` in its
 * hashed run; every other member's run is byte-identical to a regime-free
 * analysis. A bundle with no notice member therefore keeps its
 * `bundle_fingerprint` byte-identical whether or not regimes were asserted.
 *
 * DKB/playbook fetches are served from the on-disk artifact bytes, mirroring
 * the cross-surface-parity harness.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { Document, HeadingLevel, Packer, Paragraph, TextRun } from "docx";

import { prepareBundle, runBundleReport } from "../../src/ui/pipeline.js";
import type { EngineRun } from "../../src/engine/finding.js";
import { resolveDkbDir } from "../../tools/dkb/resolve.js";

const BUNDLE_DIR = join(process.cwd(), "tests", "e2e", "sample-docs", "bundle");
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
  if (url.startsWith("/x-playbooks/")) {
    return Promise.resolve(serve(PLAYBOOK_DIR, url.slice("/x-playbooks/".length)));
  }
  return realFetch(input, init);
}) as typeof fetch;
afterAll(() => {
  globalThis.fetch = realFetch;
});

const CONFIG = { dkb_base: "/x-dkb", playbook_base: "/x-playbooks" };

function docFile(name: string): File {
  return new File([new Uint8Array(readFileSync(join(BUNDLE_DIR, name)))], name);
}

/**
 * Synthesize a small CCPA-shaped privacy notice as a real .docx so it rides
 * the bundle ingest path. Same body as the CLI `--regime` test fixture — it
 * classifies as `privacy-notice-us` and satisfies some (not all) CCPA items.
 */
async function noticeDocx(): Promise<File> {
  const paragraphs = [
    "Last updated: January 1, 2026.",
    "Categories of Personal Information We Collect. We collect identifiers.",
    "Your Privacy Rights. Right to know, delete, opt-out, and correct.",
    "Do Not Sell or Share My Personal Information. We do not sell.",
    "Contact Us. privacy@example.com.",
  ];
  const doc = new Document({
    sections: [
      {
        children: [
          new Paragraph({
            heading: HeadingLevel.HEADING_1,
            children: [new TextRun({ text: "PRIVACY POLICY", bold: true })],
          }),
          ...paragraphs.map((p) => new Paragraph({ children: [new TextRun({ text: p })] })),
        ],
      },
    ],
  });
  const buffer = await Packer.toBuffer(doc);
  return new File([new Uint8Array(buffer)], "privacy-notice.docx");
}

async function bundleJson(
  files: File[],
  options: { regimes?: readonly ("ccpa" | "gdpr-13" | "gdpr-14")[] } = {},
): Promise<{ runs: EngineRun[]; bundle_fingerprint: string }> {
  const prepared = await prepareBundle(files, {}, CONFIG, options);
  const result = await runBundleReport(prepared);
  return JSON.parse(await result.bundle_json_blob.text()) as {
    runs: EngineRun[];
    bundle_fingerprint: string;
  };
}

describe("browser bundle + asserted privacy regimes (add-privacy-notice-pack)", () => {
  it("activates the PNOT pack on the notice member only, dormant on the rest", async () => {
    const files = [await noticeDocx(), docFile("master-services-agreement.docx")];
    const json = await bundleJson(files, { regimes: ["ccpa"] });

    const notice = json.runs.find((r) => r.source_file.name === "privacy-notice.docx");
    expect(notice).toBeDefined();
    expect(notice!.playbook_id).toBe("privacy-notice-us");
    // The asserted regimes ride inside the notice member's hashed run…
    expect(notice!.asserted_regimes).toEqual(["ccpa"]);
    // …and its PNOT presence rules fired on the items the notice lacks.
    expect(notice!.findings.some((f) => f.rule_id.startsWith("PNOT-CCPA-"))).toBe(true);

    // The non-notice member is untouched: no stamp, no PNOT findings.
    const msa = json.runs.find((r) => r.source_file.name === "master-services-agreement.docx");
    expect(msa).toBeDefined();
    expect(msa!.asserted_regimes).toBeUndefined();
    expect(msa!.findings.some((f) => f.rule_id.startsWith("PNOT-"))).toBe(false);
  }, 30000);

  it("keeps bundle_fingerprint byte-identical when no member is a privacy notice", async () => {
    const docs = (): File[] => [
      docFile("master-services-agreement.docx"),
      docFile("statement-of-work.docx"),
    ];
    const without = await bundleJson(docs());
    const asserted = await bundleJson(docs(), { regimes: ["ccpa", "gdpr-13"] });
    // Neither member matched a notice playbook, so the pack stayed dormant on
    // every member and the fingerprint (hash chain of member result_hashes)
    // must not move.
    expect(asserted.runs.every((r) => r.asserted_regimes === undefined)).toBe(true);
    expect(asserted.bundle_fingerprint).toBe(without.bundle_fingerprint);
    // This test runs the full bundle pipeline twice; under coverage
    // instrumentation on cold CI that comfortably exceeds the 5s default.
  }, 30000);
});
