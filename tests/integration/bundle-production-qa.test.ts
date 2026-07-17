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
import { zipSync, strToU8 } from "fflate";

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
    // The pre-production HANDOFF sweep ran over the three document members
    // (the .csv log is not itself swept).
    expect(result.production_qa!.delivery_rollup?.members_scanned).toBe(3);

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

  it("reconciles a privilege-log CSV embedded inside a .zip bundle", async () => {
    const zipBytes = zipSync({
      "ACME-000001.docx": new Uint8Array(
        readFileSync(join(BUNDLE_DIR, "master-services-agreement.docx")),
      ),
      "ACME-000003.docx": new Uint8Array(readFileSync(join(BUNDLE_DIR, "statement-of-work.docx"))),
      "privilege-log.csv": strToU8(PRIVILEGE_LOG_CSV),
    });
    const zipFile = new File([zipBytes], "production.zip", { type: "application/zip" });
    const { result } = await runBundle([zipFile]);
    expect(result.production_qa).toBeDefined();
    expect(result.production_qa!.log_present).toBe(true);
    // Two documents + the log = three members.
    expect(result.production_qa!.member_count).toBe(3);
    expect(result.production_qa!.findings.some((f) => f.code === "PROD-001")).toBe(true);
  }, 30000);

  it("skips production_qa and surfaces both logs when more than one privilege-log CSV is present", async () => {
    // Two privilege logs are ambiguous — a production set has exactly one. The
    // bundle still reviews the documents, but production-QA is skipped and each
    // extra CSV is surfaced in the rejected/skipped-files list.
    const { json, result } = await runBundle([
      ...docs(),
      new File([PRIVILEGE_LOG_CSV], "log-a.csv", { type: "text/csv" }),
      new File([PRIVILEGE_LOG_CSV], "log-b.csv", { type: "text/csv" }),
    ]);
    expect(result.production_qa).toBeUndefined();
    expect(json.production_qa).toBeUndefined();
    const rejectedNames = result.rejected.map((r) => r.filename).sort();
    expect(rejectedNames).toEqual(["log-a.csv", "log-b.csv"]);
    expect(result.rejected.every((r) => /at most one privilege-log/.test(r.reason))).toBe(true);
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

  it("gives two members that share a basename DISTINCT doc_ids (no silent overwrite)", async () => {
    // Regression: two documents named "contract.docx" (distinct content) used to
    // collapse to a single doc_id (`doc-contract.docx`), so the "everything"
    // archive silently overwrote one document's exports and the JSON emitted a
    // duplicate id. Now the collision is disambiguated.
    const at = (src: string, name: string): File =>
      new File([new Uint8Array(readFileSync(join(BUNDLE_DIR, src)))], name);
    const members = [
      at("master-services-agreement.docx", "contract.docx"),
      at("statement-of-work.docx", "contract.docx"),
    ];
    const json = await bundleJson(members);
    const documents = json.documents as Array<{ doc_id: string; result_hash: string }>;
    expect(documents).toHaveLength(2);
    // Distinct content ⇒ distinct result_hash ⇒ the doc_ids MUST be distinct.
    expect(documents[0]!.result_hash).not.toBe(documents[1]!.result_hash);
    expect(new Set(documents.map((d) => d.doc_id)).size).toBe(2);
  }, 30000);
});
