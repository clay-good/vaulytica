/**
 * End-to-end proof that the companion field reaches a real bundle report.
 *
 * `Playbook.companion_playbooks` — "suggested two-document pairings" — was
 * declared, populated across 335 references in 205 of the 267 shipped
 * playbooks, schema-validated, and read by nothing. A bundle is the one
 * surface where the pointer can do work, because it is the only one that
 * knows whether the companion is in the room.
 *
 * The unit behaviour is `src/report/companions.test.ts`'s subject. What this
 * test proves is the wiring nobody would notice was missing: that the gaps are
 * computed against the **shipped catalog** rather than a fixture, that they
 * survive into both the bundle JSON and the bundle DOCX, and that adding a
 * document to the package retires the gap that document fills.
 *
 * 🚨 A `.docx` is a zip. Asserting on `blob.text()` "passes" a
 * `not.toContain` against any string whatsoever, so the negative case has to
 * unzip `word/document.xml` like every other DOCX assertion in this suite —
 * a green that proves nothing is the failure mode this section's back-compat
 * claim would hide behind.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { prepareBundle, runBundleReport } from "../../src/ui/pipeline.js";
import { resolveDkbDir } from "../../tools/dkb/resolve.js";
import type { CompanionGap } from "../../src/report/companions.js";

const BUNDLE_DIR = join(process.cwd(), "tests", "e2e", "sample-docs", "bundle");
const DKB_DIR = resolveDkbDir();
const PLAYBOOK_DIR = join(process.cwd(), "playbooks");

const MSA = "master-services-agreement.docx";
const SOW = "statement-of-work.docx";
const DPA = "data-processing-addendum.docx";

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

function docFile(name: string): File {
  return new File([new Uint8Array(readFileSync(join(BUNDLE_DIR, name)))], name);
}

type BundlePayload = {
  companion_gaps?: CompanionGap[];
  documents?: Array<{ playbook_id: string }>;
};

async function analyze(names: string[]): Promise<{ json: BundlePayload; docx: string }> {
  const prepared = await prepareBundle(names.map(docFile), {}, CONFIG, {});
  const result = await runBundleReport(prepared);
  const { unzipSync, strFromU8 } = await import("fflate");
  const entries = unzipSync(new Uint8Array(await result.bundle_docx_blob.arrayBuffer()));
  const xml = strFromU8(entries["word/document.xml"]!);
  return {
    json: JSON.parse(await result.bundle_json_blob.text()) as BundlePayload,
    docx: (xml.match(/<w:t[^>]*>([^<]*)<\/w:t>/g) ?? [])
      .map((m) => m.replace(/<[^>]+>/g, ""))
      .join(""),
  };
}

const SECTION = "Companion Documents Not in This Package";

describe("companion documents a package does not contain", () => {
  it("names them in the bundle JSON, resolved against the shipped catalog", async () => {
    const { json } = await analyze([MSA, SOW, DPA]);
    const gaps = json.companion_gaps ?? [];
    const present = new Set((json.documents ?? []).map((d) => d.playbook_id));

    // Anti-vacuity: the assertions below say nothing unless the package
    // actually matched families that declare companions.
    expect(gaps.length, "the sample bundle names absent companions").toBeGreaterThan(0);
    expect(present.size, "the sample bundle matched real families").toBeGreaterThan(1);

    for (const g of gaps) {
      // A name resolved from the catalog, never derived from the id.
      expect(g.missing_playbook_name.length).toBeGreaterThan(0);
      expect(g.missing_playbook_name).not.toBe(g.missing_playbook_id);
      // Somebody actually in the package asked for it…
      expect(g.expected_by.length).toBeGreaterThan(0);
      for (const who of g.expected_by) expect(present.has(who)).toBe(true);
      // …and it is genuinely absent from it.
      expect(present.has(g.missing_playbook_id)).toBe(false);
    }
  }, 60_000);

  it("renders the section, and every gap in it, into the bundle DOCX", async () => {
    const { json, docx } = await analyze([MSA, SOW, DPA]);
    const gaps = json.companion_gaps ?? [];
    expect(gaps.length).toBeGreaterThan(0);
    expect(docx).toContain(SECTION);
    // A reader must be able to see it is not a finding.
    expect(docx).toContain("not a finding about any document in it");
    for (const g of gaps) expect(docx).toContain(g.missing_playbook_name);
  }, 60_000);

  it("tells an MSA package the vendor paper it is missing", async () => {
    // The concrete value, pinned: a Master Services Agreement reviewed on its
    // own has no data-processing addendum and no vendor security addendum
    // alongside it, and the report now says so.
    const { json } = await analyze([MSA, SOW]);
    const missing = new Set((json.companion_gaps ?? []).map((g) => g.missing_playbook_id));
    expect(missing).toContain("dpa-controller-processor");
    expect(missing).toContain("vendor-security-addendum");
  }, 60_000);

  it("retires a gap as soon as the package contains the document", async () => {
    const withoutDpa = await analyze([MSA, SOW]);
    const withDpa = await analyze([MSA, SOW, DPA]);

    const before = new Set(
      (withoutDpa.json.companion_gaps ?? []).map((g) => g.missing_playbook_id),
    );
    const after = new Set((withDpa.json.companion_gaps ?? []).map((g) => g.missing_playbook_id));

    expect(before).toContain("dpa-controller-processor");
    expect(after).not.toContain("dpa-controller-processor");

    // No family present in a package is ever reported missing from it.
    for (const d of withDpa.json.documents ?? []) expect(after.has(d.playbook_id)).toBe(false);
  }, 60_000);

  it("is deterministic across two runs of the same package", async () => {
    const a = await analyze([MSA, SOW]);
    const b = await analyze([MSA, SOW]);
    expect(a.json.companion_gaps).toEqual(b.json.companion_gaps);
  }, 60_000);
});
