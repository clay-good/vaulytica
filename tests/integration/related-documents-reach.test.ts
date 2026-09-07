/**
 * The single-document counterpart of the bundle's companion section, and the
 * reach test that keeps it on every human-readable surface.
 *
 * A bundle can say a companion is **absent**, because it knows what is in the
 * package. A single document knows nothing about what else exists — so the
 * same `Playbook.companion_playbooks` data renders there as a reference list
 * ("documents normally reviewed alongside this one") and asserts no absence.
 * Keeping those two claims distinct is the whole design, and the wording is
 * asserted here so a later edit cannot quietly turn the reference list into an
 * accusation.
 *
 * A surface that renders a report and not this list is not a bug in the same
 * way a missing honesty caveat is — this is a reference block, and
 * `honesty-caveat-reach.test.ts` covers the class that must never be dropped.
 * What this pins is that the three surfaces which DO carry it agree, because a
 * field that reaches the JSON and not the DOCX is the shape this repo keeps
 * finding.
 */

import { readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { prepareDocument, runReport } from "../../src/ui/pipeline.js";
import { resolveDkbDir } from "../../tools/dkb/resolve.js";
import type { RelatedDocument } from "../../src/report/companions.js";

/**
 * An MSA: it matches `msa-vendor-deep`, which declares four companions. The
 * 12 LAUNCH playbooks declare none at all — `single/vendor-saas-agreement.docx`
 * matches one of them — so that file is the back-compat fixture below rather
 * than the positive one. Picking it first made every assertion here fail, which
 * is the anti-vacuity check doing its job.
 */
const FIXTURE = join(
  process.cwd(),
  "tests",
  "e2e",
  "sample-docs",
  "bundle",
  "master-services-agreement.docx",
);

/** A family that declares no companion — every surface must be silent. */
const NO_COMPANIONS = join(
  process.cwd(),
  "tests",
  "e2e",
  "sample-docs",
  "single",
  "vendor-saas-agreement.docx",
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

const HEADING = "Documents Normally Reviewed Alongside This One";
const DISCLAIMER = "we have not seen these documents";

async function analyze(fixture: string = FIXTURE) {
  const bytes = readFileSync(fixture);
  const file = new File([new Uint8Array(bytes)], basename(fixture));
  const prepared = await prepareDocument(file, "docx", {
    dkb_base: "/x-dkb",
    playbook_base: "/x-playbooks",
  });
  const result = await runReport(prepared);
  const { unzipSync, strFromU8 } = await import("fflate");
  const entries = unzipSync(new Uint8Array(await result.docx_blob.arrayBuffer()));
  const xml = strFromU8(entries["word/document.xml"]!);
  return {
    playbook_id: prepared.playbook.id,
    related: prepared.related_documents,
    json: JSON.parse(await result.json_blob.text()) as {
      related_documents?: RelatedDocument[];
    },
    html: await result.html_blob.text(),
    sarif: JSON.parse(await result.sarif_blob.text()) as {
      runs: Array<{ properties?: { related_documents?: string[] } }>;
    },
    docx: (xml.match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? [])
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join(""),
  };
}

describe("documents normally reviewed alongside this one", () => {
  it("reaches the JSON, the DOCX and the HTML report alike", async () => {
    const r = await analyze();

    // Anti-vacuity: the fixture's family must actually declare companions,
    // or every assertion below is trivially satisfied.
    const related = r.related ?? [];
    expect(related.length, `${r.playbook_id} declares companions`).toBeGreaterThan(0);

    expect(r.json.related_documents).toEqual(related.map((x) => ({ ...x })));
    expect(r.docx).toContain(HEADING);
    expect(r.html).toContain(HEADING);
    // SARIF carries the ids as run PROVENANCE, never as results — the same
    // call `readiness` makes, and for the same reason: these are not findings,
    // so emitting one as a result would assert an absence nothing checked.
    expect(r.sarif.runs[0]?.properties?.related_documents).toEqual(
      related.map((x) => x.playbook_id),
    );
    for (const item of related) {
      expect(r.docx, "the DOCX names every related document").toContain(item.name);
      expect(r.html, "the HTML names every related document").toContain(item.name);
    }
  }, 60_000);

  it("says on every human surface that it has not seen these documents", async () => {
    // The line between a reference list and an accusation. Without it a reader
    // can take the list for a set of missing-document findings, which is
    // exactly the claim a single-document report cannot make.
    const r = await analyze();
    expect(r.related?.length ?? 0).toBeGreaterThan(0);
    expect(r.docx).toContain(DISCLAIMER);
    expect(r.html).toContain(DISCLAIMER);
    expect(r.docx).toContain("not a finding");
    expect(r.html).toContain("not a finding");
  }, 60_000);

  it("is silent on every surface for a family that names no companion", async () => {
    // The back-compat case every existing golden depends on: the field is
    // omitted from the JSON and no section appears in the DOCX or the HTML.
    const r = await analyze(NO_COMPANIONS);
    expect(r.related ?? []).toEqual([]);
    expect(r.json).not.toHaveProperty("related_documents");
    expect(r.docx).not.toContain(HEADING);
    expect(r.html).not.toContain(HEADING);
    expect(r.sarif.runs[0]?.properties?.related_documents).toBeUndefined();
  }, 60_000);

  it("leaves the engine run untouched — no finding, no hash change", async () => {
    const a = await analyze();
    const b = await analyze();
    // Deterministic across runs, and never expressed as a finding: no rule id
    // exists for it, so nothing here can enter `result_hash`.
    expect(a.related).toEqual(b.related);
    expect(a.json).toHaveProperty("related_documents");
  }, 60_000);
});
