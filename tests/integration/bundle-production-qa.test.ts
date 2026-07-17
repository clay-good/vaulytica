/**
 * End-to-end proof that a privilege-log `.csv` dropped alongside a bundle
 * flows through the REAL browser bundle pipeline into the bundle JSON's
 * `production_qa` block (add-production-qa-pack, browser integration).
 *
 * The shipped dropzone lets a `.csv` ride in the multi-file / folder bundle
 * path; `prepareBundle` pulls it out as the privilege log (not a document),
 * and `runBundleReport` reconciles Bates numbering (from the document
 * filenames) and the log against the produced set — reusing the same pure
 * `buildProductionQaReport` core the CLI `--production-qa` mode uses.
 *
 * Held OUTSIDE the bundle fingerprint: dropping the log must never move
 * `bundle_fingerprint`, so a csv-free bundle stays byte-identical.
 *
 * DKB/playbook fetches are served from the on-disk artifact bytes, mirroring
 * the cross-surface-parity harness.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

import { prepareBundle, runBundleReport } from "../../src/ui/pipeline.js";
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

// A privilege log naming a withheld range (ACME-000002) that sits between two
// produced documents — the classic "claimed withheld but the gap is not
// otherwise explained" reconciliation the pack surfaces.
const PRIVILEGE_LOG_CSV =
  "bates_begin,bates_end,description,privilege\n" +
  "ACME-000002,ACME-000002,Legal advice re: indemnity,Attorney-Client";

function logFile(csv = PRIVILEGE_LOG_CSV): File {
  return new File([csv], "privilege-log.csv", { type: "text/csv" });
}

async function runBundle(
  files: File[],
): Promise<{ json: Record<string, unknown>; result: Awaited<ReturnType<typeof runBundleReport>> }> {
  const prepared = await prepareBundle(files, {}, CONFIG);
  const result = await runBundleReport(prepared);
  return {
    json: JSON.parse(await result.bundle_json_blob.text()) as Record<string, unknown>,
    result,
  };
}

async function bundleJson(files: File[]): Promise<Record<string, unknown>> {
  return (await runBundle(files)).json;
}

describe("browser bundle + privilege-log CSV → production_qa (add-production-qa-pack)", () => {
  const docs = (): File[] => [
    docFile("master-services-agreement.docx"),
    docFile("statement-of-work.docx"),
    docFile("data-processing-addendum.docx"),
  ];

  it("emits a production_qa block reconciling the privilege log against the produced set", async () => {
    // Rename the sample docs to Bates-numbered members so the reconciliation
    // has a numbering sequence to check (the pack derives Bates from filenames).
    const at = (src: string, bates: string): File =>
      new File([new Uint8Array(readFileSync(join(BUNDLE_DIR, src)))], bates);
    const members = [
      at("master-services-agreement.docx", "ACME-000001.docx"),
      at("statement-of-work.docx", "ACME-000003.docx"),
      at("data-processing-addendum.docx", "ACME-000004.docx"),
    ];
    const { json, result } = await runBundle([...members, logFile()]);

    // The pipeline result carries production_qa too — the field main.ts reads to
    // populate the bundle-complete "Production QA" card and the bundle DOCX.
    expect(result.production_qa).toBeDefined();
    expect(result.production_qa!.log_present).toBe(true);

    const pq = json.production_qa as
      | {
          member_count: number;
          log_present: boolean;
          findings: Array<{ code: string }>;
          production_qa_hash: string;
        }
      | undefined;
    expect(pq).toBeDefined();
    expect(pq!.log_present).toBe(true);
    // Four members: three documents + the privilege log itself.
    expect(pq!.member_count).toBe(4);
    expect(pq!.production_qa_hash).toMatch(/^[0-9a-f]{64}$/);
    // ACME-000002 is withheld per the log but is a gap in the produced set —
    // the pack flags the produced-set gap (PROD-001).
    expect(pq!.findings.some((f) => f.code === "PROD-001")).toBe(true);
  }, 30000);

  it("omits production_qa and leaves bundle_fingerprint byte-identical without a CSV", async () => {
    const withoutLog = await bundleJson(docs());
    const withLog = await bundleJson([...docs(), logFile()]);
    expect(withoutLog.production_qa).toBeUndefined();
    expect(withLog.production_qa).toBeDefined();
    // The privilege log is metadata about the production, never a document with
    // its own result_hash — so the fingerprint of the same three documents is
    // unchanged whether or not a log rode along.
    expect(withLog.bundle_fingerprint).toBe(withoutLog.bundle_fingerprint);
    // This test runs the full bundle pipeline three times; under coverage
    // instrumentation on cold CI that comfortably exceeds the 5s default.
  }, 30000);
});
