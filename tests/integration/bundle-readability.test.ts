/**
 * End-to-end proof that an asserted readability statute reaches the REAL
 * browser bundle pipeline (add-readability-measure, task 4 — the same mirror
 * bundle-privacy-regimes.test.ts and bundle-estate-checks.test.ts are for
 * `--regime` and `--estate-checks`).
 *
 * 🚨 THE GAP THIS GUARDS. `prepareBundle` layered the privacy and estate packs
 * onto each member and silently dropped `options.readability`, and both of
 * `main.ts`'s `runBundlePipeline` call sites forwarded the regimes and the
 * estate state but not the statute. So choosing a statute in the tab's panel
 * and then dropping a FOLDER produced no `READ-*` finding and no
 * `asserted_readability` stamp, with nothing on screen to say the assertion had
 * been ignored — the single-document path honored it, the bundle path did not.
 * The third test below is the regression: before the wiring, the asserted and
 * unasserted bundles hashed identically.
 *
 * Unlike the privacy and estate packs, readability is NOT playbook-gated:
 * nothing in a document says where it was filed, so the caller's assertion is
 * the whole gate and every member is held to it.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { Document, HeadingLevel, Packer, Paragraph, TextRun } from "docx";

import { prepareBundle, runBundleReport } from "../../src/ui/pipeline.js";
import type { EngineRun } from "../../src/engine/finding.js";
import { resolveDkbDir } from "../../tools/dkb/resolve.js";

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

/** The dense body of `readability-assertion.test.ts`: one 70-word sentence. */
const DENSE_BODY =
  "The insurer's obligation to indemnify the insured for consequential, incidental, or derivative losses occasioned by the occurrence of any peril enumerated in the declarations, notwithstanding any contrary provision of any endorsement, rider, or supplementary documentation incorporated by reference, shall be determined exclusively in accordance with the provisions of the applicable valuation methodology and the limitations, conditions, and exclusions specified in this policy.";

/** Short words, short sentences: comfortably above every seeded minimum. */
const PLAIN_BODY =
  "We pay for loss to your home. We do not pay for wear and tear. You must tell us of a loss soon. We will pay you within thirty days. We may ask you for proof of the loss.";

async function policyDocx(name: string, heading: string, body: string): Promise<File> {
  const doc = new Document({
    sections: [
      {
        children: [
          new Paragraph({
            heading: HeadingLevel.HEADING_1,
            children: [new TextRun({ text: heading, bold: true })],
          }),
          new Paragraph({ children: [new TextRun({ text: body })] }),
        ],
      },
    ],
  });
  return new File([new Uint8Array(await Packer.toBuffer(doc))], name);
}

/**
 * Built ONCE and reused by every case. `Packer.toBuffer` stamps a creation time
 * into the .docx, so rebuilding the pair per call gives each run different
 * bytes — a different `source_file.sha256`, a different `result_hash`, and a
 * different `bundle_fingerprint` for reasons that have nothing to do with the
 * assertion. The fingerprint case below was silently vacuous until these were
 * memoized: it passed with the bundle wiring removed. A `File` is a `Blob`, so
 * the same object reads as many times as there are cases.
 */
let cached: File[] | undefined;
const files = async (): Promise<File[]> => {
  cached ??= [
    await policyDocx("dense-policy.docx", "HOMEOWNERS INSURANCE POLICY", DENSE_BODY),
    await policyDocx("plain-policy.docx", "AUTOMOBILE INSURANCE POLICY", PLAIN_BODY),
  ];
  return cached;
};

async function bundleJson(
  input: File[],
  options: { readability?: string } = {},
): Promise<{ runs: EngineRun[]; bundle_fingerprint: string }> {
  const prepared = await prepareBundle(input, {}, CONFIG, options);
  const result = await runBundleReport(prepared);
  return JSON.parse(await result.bundle_json_blob.text()) as {
    runs: EngineRun[];
    bundle_fingerprint: string;
  };
}

/** The rendered words of a .docx, as `bundle-member-docx-consistency` reads them. */
async function docxText(blob: Blob): Promise<string> {
  const { unzipSync, strFromU8 } = await import("fflate");
  const xml = strFromU8(unzipSync(new Uint8Array(await blob.arrayBuffer()))["word/document.xml"]!);
  return xml.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
}

const runFor = (json: { runs: EngineRun[] }, name: string): EngineRun => {
  const run = json.runs.find((r) => r.source_file.name === name);
  expect(run, `no member run for ${name}`).toBeDefined();
  return run!;
};

describe("browser bundle + an asserted readability statute (add-readability-measure)", () => {
  it("holds every member to the statute, and reports only the member that fails it", async () => {
    const json = await bundleJson(await files(), { readability: "fl" });

    // The assertion rides inside EVERY member's hashed run — it is the
    // caller's, not something a member matched into.
    const dense = runFor(json, "dense-policy.docx");
    const plain = runFor(json, "plain-policy.docx");
    expect(dense.asserted_readability).toBe("fl");
    expect(plain.asserted_readability).toBe("fl");

    // Both members actually RAN the rules (the stamp alone would not prove it).
    for (const run of [dense, plain]) {
      expect(run.execution_log.some((e) => e.rule_id === "READ-001")).toBe(true);
    }

    // Only the dense one is below Florida's 45.
    const read001 = dense.findings.find((f) => f.rule_id === "READ-001");
    expect(read001?.title).toMatch(/below the 45 Fla\. Stat\. § 627\.4145 requires/);
    expect(plain.findings.some((f) => f.rule_id.startsWith("READ-"))).toBe(false);
  }, 30000);

  it("changes nothing without the assertion", async () => {
    const json = await bundleJson(await files());
    for (const name of ["dense-policy.docx", "plain-policy.docx"]) {
      const run = runFor(json, name);
      expect(run.asserted_readability).toBeUndefined();
      expect(run.execution_log.some((e) => e.rule_id.startsWith("READ-"))).toBe(false);
      expect(run.findings.some((f) => f.rule_id.startsWith("READ-"))).toBe(false);
    }
  }, 30000);

  it("moves bundle_fingerprint when asserted — the regression this guards", async () => {
    // Before the bundle wiring these two were EQUAL: the option was accepted,
    // dropped, and the run hashed as though nothing had been asserted.
    const without = await bundleJson(await files());
    // First prove the fingerprint is stable over the same bytes, or "differs"
    // below would mean nothing. This is the half that was vacuous.
    const again = await bundleJson(await files());
    expect(again.bundle_fingerprint).toBe(without.bundle_fingerprint);

    const asserted = await bundleJson(await files(), { readability: "fl" });
    expect(asserted.bundle_fingerprint).not.toBe(without.bundle_fingerprint);
  }, 30000);

  it("names the statute on each member's own Word cover inside the bundle", async () => {
    // 🥇 The artifact a reader OPENS, not the run object. `renderCover` prints
    // the reading-ease line from `run.asserted_readability`, so until the member
    // runs carried the statute every per-member cover in a bundle said
    // "informative only" even when the user had asserted one. That it follows
    // from the fix is exactly the reasoning that has shipped defects here
    // before, so this reads the .docx.
    const prepared = await prepareBundle(await files(), {}, CONFIG, { readability: "fl" });
    const result = await runBundleReport(prepared);
    const dense = result.documents.find((d) => d.filename === "dense-policy.docx");
    expect(dense, "no dense member in the bundle report").toBeDefined();
    const cover = await docxText(dense!.docx_blob);

    // The COVER FIELD, not merely the words somewhere in the file. `coverField`
    // prints "Reading ease: " with a colon; the READ-001 finding's own title
    // begins "Reading ease -60.8 is below the 45 Fla. Stat. § 627.4145
    // requires", with a space. A looser pattern here passed on the finding text
    // and proved nothing about the cover — so this anchors on the colon and
    // reads only to the end of that line's sentence.
    const line = /Reading ease: (.{0,200})/.exec(cover);
    expect(line, `no "Reading ease:" cover field in the member .docx`).not.toBeNull();
    expect(line![1]).toMatch(
      /held to Fla\. Stat\. § 627\.4145 \(minimum 45\), asserted by the user/,
    );
    expect(line![1], "an asserted cover must not still read as informative only").not.toMatch(
      /informative only/,
    );
  }, 30000);

  it("scores each member against the statute the caller named", async () => {
    // Minnesota's § 72C.10 is "more than 40" (min_exclusive) where Florida's is
    // "at least 45": the same bundle under a different assertion is a different
    // question, and the stamp names which one was asked.
    const json = await bundleJson(await files(), { readability: "mn" });
    expect(runFor(json, "dense-policy.docx").asserted_readability).toBe("mn");
    const read001 = runFor(json, "dense-policy.docx").findings.find(
      (f) => f.rule_id === "READ-001",
    );
    expect(read001?.title).toMatch(/Minn\. Stat\./);
  }, 30000);
});
