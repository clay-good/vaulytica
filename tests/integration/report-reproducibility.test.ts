/**
 * Render the same document twice. Which artifacts come out byte-identical?
 *
 * The README's headline claim is "same document + same engine version + same
 * DKB version → **byte-identical report on any machine, at any time**", and
 * nothing had ever checked it at the ARTIFACT level. `result_hash` equality
 * was checked from the first day; the hash deliberately blanks the volatile
 * fields, so it cannot see the very things that make two renders of one run
 * differ.
 *
 * Measured 2026-09-08, and it was not what the README said:
 *
 * | artifact | identical? |
 * |---|---|
 * | fix list (Markdown, CSV) | yes |
 * | HTML | yes |
 * | SARIF | yes |
 * | JSON | **no** — 126 differing lines, every one a per-rule `elapsed_ms` |
 * | DOCX | **no** — the same timings, plus a random hyperlink id per citation |
 *
 * The JSON half is fixed at the source (the emitted report drops the wall-clock
 * measurement — see `buildJsonReport`). The DOCX half is the `docx` library
 * assigning relationship ids with `nanoid()`, which is not reachable through
 * its public API; it is DECLARED below rather than hidden, so the exception is
 * on the record and the set can only shrink.
 *
 * The rule this file enforces: an artifact is byte-identical across two renders
 * of the same run, or its variance is named here with a reason.
 */

import { describe, expect, it } from "vitest";
import { join } from "node:path";

import { analyzeFile, loadAccuracyDeps } from "../../tools/cli/api.js";
import { extractAll } from "../../src/extract/index.js";
import { buildJsonReport } from "../../src/report/json.js";
import { buildHtmlReport } from "../../src/report/html.js";
import { buildSarif } from "../../src/report/sarif.js";
import { buildDocxReport } from "../../src/report/docx.js";
import {
  buildFixListMarkdown,
  buildFixListCsv,
  buildObligationsCsv,
  buildDeadlinesIcs,
} from "../../src/report/exports.js";

const DOC = join(process.cwd(), "tests", "fixtures", "specimens", "mutual-nda-letter.txt");

/**
 * The ONE declared exception, with its cause.
 *
 * `docx` generates each hyperlink's relationship id with `nanoid()`
 * (`uniqueId = () => nanoid().toLowerCase()` in the shipped bundle), so every
 * citation link in a fresh render carries a fresh `r:id`. Nothing in the
 * library's public API takes a seed or a counter. Normalized here, and ONLY
 * here — the rest of the document part still has to match exactly.
 */
const DOCX_RANDOM_REL_IDS = /r:id="rId[A-Za-z0-9_-]+"/g;

async function renderAll(): Promise<Record<string, string>> {
  const deps = await loadAccuracyDeps();
  const r = await analyzeFile(DOC, { deps, secondaryFamilies: true });
  const extracted = extractAll(r.ingest.tree);
  const docx = Buffer.from(
    await (await buildDocxReport(r.run, r.ingest, deps.dkb, r.playbook)).arrayBuffer(),
  ).toString("base64");
  return {
    result_hash: r.run.result_hash,
    json: await buildJsonReport(r.run, r.ingest, r.playbook).text(),
    html: buildHtmlReport(r.run, r.ingest, deps.dkb, r.playbook),
    sarif: JSON.stringify(buildSarif(r.run, undefined, undefined, r.ingest)),
    fixlist_md: buildFixListMarkdown(r.run, extracted, undefined, r.ingest),
    fixlist_csv: buildFixListCsv(r.run, undefined),
    obligations_csv: buildObligationsCsv(extracted),
    deadlines_ics: buildDeadlinesIcs(extracted),
    docx,
  };
}

/** A two-document deal room, rendered twice. */
async function renderBundleTwice(): Promise<[Record<string, string>, Record<string, string>]> {
  const deps = await loadAccuracyDeps();
  const { runConsistency } = await import("../../src/engine/consistency/runner.js");
  const { ALL_CONSISTENCY_RULES } = await import("../../src/engine/consistency/rules/index.js");
  const { buildBundleJsonBlob, buildBundleDocxReport, buildBundleZip } =
    await import("../../src/report/bundle.js");
  const files = ["mutual-nda-letter.txt", "legend-nda.txt"];
  const once = async (): Promise<Record<string, string>> => {
    const docs = [];
    const cdocs = [];
    for (const f of files) {
      const r = await analyzeFile(join(process.cwd(), "tests", "fixtures", "specimens", f), {
        deps,
      });
      const extracted = extractAll(r.ingest.tree);
      docs.push({ doc_id: f, source_file_name: f, run: r.run, extracted, ingest: r.ingest });
      cdocs.push({
        doc_id: f,
        source_file_name: f,
        playbook_id: r.playbook_id,
        tree: r.ingest.tree,
        extracted,
      });
    }
    const consistency = await runConsistency({
      rules: ALL_CONSISTENCY_RULES,
      documents: cdocs,
      dkb: deps.dkb,
    });
    const input = { documents: docs, consistency, dkb: deps.dkb, consistency_enabled: true };
    const b64 = async (b: Blob): Promise<string> =>
      Buffer.from(await b.arrayBuffer()).toString("base64");
    return {
      bundle_json: await (await buildBundleJsonBlob(input)).text(),
      bundle_docx: await b64(await buildBundleDocxReport(input)),
      bundle_zip: await b64(await buildBundleZip({ ...input, include_per_document_exports: true })),
    };
  };
  return [await once(), await once()];
}

describe("two renders of the same document produce the same artifacts", () => {
  it("every text artifact is byte-identical, including the JSON", async () => {
    const a = await renderAll();
    const b = await renderAll();
    // Guard the probe: an empty or tiny render would make this vacuous.
    expect(Object.keys(a).length).toBeGreaterThan(7);
    expect(a.json!.length).toBeGreaterThan(50_000);
    for (const key of Object.keys(a)) {
      if (key === "docx") continue;
      expect(a[key], `${key} is not byte-identical across two renders`).toBe(b[key]);
    }
  }, 300_000);

  it("the DOCX differs only in the library's random relationship ids", async () => {
    // Not "the DOCX is allowed to differ" but "it differs in exactly one known
    // way". Anything else — a wall-clock timing, a re-ordered section — fails.
    const [a, b] = [await renderAll(), await renderAll()];
    // The zip's compressed bytes are not comparable directly; compare the
    // uncompressed document part, which is where any real drift would show.
    const { unzipSync, strFromU8 } = await import("fflate");
    const part = (s: string): string =>
      strFromU8(unzipSync(new Uint8Array(Buffer.from(s, "base64")))["word/document.xml"]!).replace(
        DOCX_RANDOM_REL_IDS,
        'r:id="rIdN"',
      );
    const pa = part(a.docx!);
    // Guard the normalization: if it ate the document the compare is vacuous.
    expect(pa.length).toBeGreaterThan(100_000);
    expect(pa).toBe(part(b.docx!));
  }, 300_000);

  /**
   * `buildBundleZip`'s own comment claims it: "File order inside the zip is
   * lexicographic by basename so two runs over the same bundle produce
   * byte-identical archives (assuming the inputs were themselves
   * deterministic)." The parenthetical was doing a lot of work — the inputs
   * were NOT deterministic, because the consolidated DOCX inside the zip
   * carried the same wall-clock audit trail the single-document one did.
   */
  it("the consolidated bundle JSON is byte-identical, and the zip is too", async () => {
    const [a, b] = await renderBundleTwice();
    expect(a.bundle_json!.length).toBeGreaterThan(10_000);
    expect(a.bundle_json, "bundle JSON is not byte-identical").toBe(b.bundle_json);
    // The zip embeds the consolidated DOCX, which carries the library's random
    // hyperlink ids, so the ARCHIVE cannot be compared byte-for-byte. Its other
    // entries can, and they are what a consumer diffs.
    const { unzipSync, strFromU8 } = await import("fflate");
    const entries = (s64: string): Record<string, string> => {
      const z = unzipSync(new Uint8Array(Buffer.from(s64, "base64")));
      const out: Record<string, string> = {};
      for (const [name, bytes] of Object.entries(z)) {
        if (name.endsWith(".docx")) continue;
        out[name] = strFromU8(bytes);
      }
      return out;
    };
    const ea = entries(a.bundle_zip!);
    expect(Object.keys(ea).length).toBeGreaterThan(4);
    expect(ea).toEqual(entries(b.bundle_zip!));
  }, 300_000);
});
