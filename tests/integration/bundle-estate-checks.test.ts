/**
 * End-to-end proof that the asserted estate checks / state reach the REAL
 * browser bundle pipeline (add-estate-planning-pack, bundle integration —
 * the same mirror bundle-privacy-regimes.test.ts is for `--regime`).
 *
 * Each bundle member activates the EST pack independently: a member that
 * matched a will/trust/codicil playbook runs the deepening rules —
 * overlay-aware under an asserted state — and carries
 * `estate_checks_asserted` / `asserted_state` in its hashed run; every other
 * member's run is byte-identical to an estate-free analysis. A bundle with
 * no estate member keeps its `bundle_fingerprint` byte-identical whether or
 * not the checks were asserted.
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
 * Synthesize a PA-style signed will as a real .docx: testator signature
 * block, NO witness blocks and no attestation clause — the exact shape
 * 20 Pa. C.S. § 2502 permits, so the PA overlay downgrades EST-105 to info.
 */
async function willDocx(): Promise<File> {
  const paragraphs = [
    "I, John Doe, being of sound mind, declare this to be my last will and testament, and I revoke all prior wills and codicils.",
    "ARTICLE I. I appoint Jane Doe as Executor of my estate, and my brother Sam Doe as successor executor if she is unable to serve.",
    "ARTICLE II. Residuary Estate. I give the rest, residue and remainder of my estate to my children in equal shares.",
    "ARTICLE III. I direct that my just debts be paid. I make the following specific bequests to my devisees.",
    "Signed at Philadelphia, Pennsylvania.",
    "By: _______________________ Testator",
  ];
  const doc = new Document({
    sections: [
      {
        children: [
          new Paragraph({
            heading: HeadingLevel.HEADING_1,
            children: [new TextRun({ text: "LAST WILL AND TESTAMENT OF JOHN DOE", bold: true })],
          }),
          ...paragraphs.map((p) => new Paragraph({ children: [new TextRun({ text: p })] })),
        ],
      },
    ],
  });
  const buffer = await Packer.toBuffer(doc);
  return new File([new Uint8Array(buffer)], "last-will.docx");
}

async function bundleJson(
  files: File[],
  options: { estate_checks?: boolean; estate_state?: string } = {},
): Promise<{ runs: EngineRun[]; bundle_fingerprint: string }> {
  const prepared = await prepareBundle(files, {}, CONFIG, options);
  const result = await runBundleReport(prepared);
  return JSON.parse(await result.bundle_json_blob.text()) as {
    runs: EngineRun[];
    bundle_fingerprint: string;
  };
}

describe("browser bundle + asserted estate checks (add-estate-planning-pack)", () => {
  it("activates the EST pack on the will member only, overlay-aware under --state pa", async () => {
    const files = [await willDocx(), docFile("master-services-agreement.docx")];
    const json = await bundleJson(files, { estate_state: "us-pa" });

    const will = json.runs.find((r) => r.source_file.name === "last-will.docx");
    expect(will).toBeDefined();
    expect(will!.playbook_id).toBe("last-will-and-testament");
    // The assertions ride inside the will member's hashed run…
    expect(will!.estate_checks_asserted).toBe(true);
    expect(will!.asserted_state).toBe("us-pa");
    // …the EST rules fired, and the PA overlay downgraded witness absence.
    const est105 = will!.findings.find((f) => f.rule_id === "EST-105");
    expect(est105?.severity).toBe("info");

    // The non-estate member is untouched: no stamp, no EST findings.
    const msa = json.runs.find((r) => r.source_file.name === "master-services-agreement.docx");
    expect(msa).toBeDefined();
    expect(msa!.estate_checks_asserted).toBeUndefined();
    expect(msa!.asserted_state).toBeUndefined();
    expect(msa!.findings.some((f) => /^EST-[123]\d\d/.test(f.rule_id))).toBe(false);
  }, 30000);

  it("keeps bundle_fingerprint byte-identical when no member is an estate instrument", async () => {
    const docs = (): File[] => [
      docFile("master-services-agreement.docx"),
      docFile("statement-of-work.docx"),
    ];
    const without = await bundleJson(docs());
    const asserted = await bundleJson(docs(), { estate_checks: true, estate_state: "us-pa" });
    expect(asserted.runs.every((r) => r.estate_checks_asserted === undefined)).toBe(true);
    expect(asserted.bundle_fingerprint).toBe(without.bundle_fingerprint);
  }, 30000);
});
