/**
 * "Byte-identical report on **any machine**" — the cross-machine half.
 *
 * `report-reproducibility.test.ts` renders each artifact twice in one process
 * and asserts the bytes match. That closes *this machine, twice*. The README's
 * claim is bigger, and the thing that enforces it across Ubuntu, macOS and
 * Windows is this file plus the test matrix that runs it on all three.
 *
 * What is committed is a **SHA-256 per artifact**, not the artifact: the JSON
 * report alone is half a megabyte (1,825 execution-log entries), and a digest
 * asserts exactly the property the claim is about at a few hundred bytes. A
 * digest that moves is either a deliberate render change — regenerate — or a
 * machine-dependent byte, which is the defect this exists to catch.
 *
 * `pin-the-docx-report` tasks 1, 4 and 5.
 *
 * 🚨 The DOCX used to be absent, and the stated reason was HALF true. The
 * `docx` library does assign hyperlink relationship ids with `nanoid()`, so the
 * raw bytes differ on every render — but `report-reproducibility.test.ts` had
 * already solved that, normalizing the ids and comparing `word/document.xml`.
 * What it compares is render A against render B of the SAME code, which proves
 * DETERMINISM and pins no CONTENT: change a column header and both renders
 * change together, and it stays green.
 *
 * So nothing pinned the DOCX's content, and that is how the Jurisdictions
 * table shipped with every id cell reading "—". `docx.test.ts` asserts
 * `blob.size` and nothing about the text, and a dash is the same number of
 * bytes as an id. `docx_document_xml` below closes it, over the same
 * normalized part, shared from `_docx-part.ts` so the two guards cannot drift
 * to two spellings of one exception.
 *
 * ⚠️ What this still does NOT pin: the zip container. Per-entry metadata and
 * `docProps/core.xml`'s creation stamp are outside the document part, so a
 * change to how the archive itself is assembled would not show up here.
 *
 * Regeneration: `VAULYTICA_REGEN_GOLDEN=1 vitest run tests/golden/artifact-digests.test.ts`.
 * Regenerate on a version bump (the engine version is stamped into every
 * artifact) and whenever a renderer deliberately changes — never to make a
 * red matrix green.
 *
 * 🚨 The DKB is PINNED, not "latest". Every artifact stamps `dkb_version`, and
 * `result_hash` folds it in, so reading the newest `dkb/dist/` meant the weekly
 * bot rebuild (which commits straight to main) moved every digest here and left
 * main red for the next human push — 2026-09-20 did exactly that, with a report
 * that differed from the previous DKB's in the stamp and nothing else. This file
 * is about machine-independence, not DKB currency; move the pin deliberately,
 * together with a regeneration.
 */

import { describe, expect, it } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { analyzeFile, loadAccuracyDeps } from "../../tools/cli/api.js";
import { extractAll } from "../../src/extract/index.js";
import { sha256Hex } from "../../src/ingest/hash.js";
import { buildJsonReport } from "../../src/report/json.js";
import { buildHtmlReport } from "../../src/report/html.js";
import { buildSarif } from "../../src/report/sarif.js";
import { renderDocxReport } from "../../tools/cli/artifacts.js";
import { resolveJurisdictionId } from "../../src/dkb/jurisdiction-ids.js";
import { docxDocumentPartDigest } from "../integration/_docx-part.js";
import {
  buildFixListMarkdown,
  buildFixListCsv,
  buildObligationsCsv,
  buildDeadlinesIcs,
} from "../../src/report/exports.js";

const REGEN = process.env.VAULYTICA_REGEN_GOLDEN === "1";
const EXPECTED = join(process.cwd(), "tests", "golden", "artifact-digests.json");

/** Two specimens with different shapes: a letter-form NDA and a services agreement. */
const FIXTURES = ["mutual-nda-letter.txt", "msa-customer-side.txt"];

/** The DKB these digests were rendered against (see the 🚨 note above). */
const DKB_VERSION = "v2026-09-06-local";
const DKB_DIR = join(process.cwd(), "dkb", "dist", DKB_VERSION);

async function digests(name: string): Promise<Record<string, string>> {
  const deps = await loadAccuracyDeps({ dkbDir: DKB_DIR });
  const r = await analyzeFile(join(process.cwd(), "tests", "fixtures", "specimens", name), {
    deps,
    secondaryFamilies: true,
  });
  // The lookup, because this harness RENDERS WHAT IS PINNED. A pinned
  // artifact built from an `extracted` the product never produces enshrines
  // something no user sees — which is precisely what the dash column was.
  const extracted = extractAll(r.ingest.tree, { jurisdictionLookup: resolveJurisdictionId });
  const artifacts: Record<string, string> = {
    json: await buildJsonReport(r.run, r.ingest, r.playbook).text(),
    html: buildHtmlReport(r.run, r.ingest, deps.dkb, r.playbook),
    sarif: JSON.stringify(buildSarif(r.run, undefined, undefined, r.ingest)),
    fixlist_md: buildFixListMarkdown(r.run, extracted, undefined, r.ingest),
    fixlist_csv: buildFixListCsv(r.run, undefined),
    obligations_csv: buildObligationsCsv(extracted),
    deadlines_ics: buildDeadlinesIcs(extracted),
  };
  const out: Record<string, string> = { result_hash: r.run.result_hash };
  for (const [k, v] of Object.entries(artifacts)) out[k] = await sha256Hex(v);

  // The DOCX, via its normalized document part rather than its zip bytes.
  // `docxDocumentPartDigest` throws if the part comes back implausibly small,
  // so a broken unzip or an over-eager normalization fails loudly instead of
  // digesting an empty string identically on all three machines.
  //
  // 🚨 Rendered through the CLI's OWN `renderDocxReport`, not by calling
  // `buildDocxReport` here. The first draft of this did the latter and passed
  // six of the builder's nine arguments — which produced a report 8 KB SHORTER
  // than the one the CLI writes, missing the secondary families and the
  // related-documents block. It would have pinned a document no user ever
  // receives, which is the same mistake as building `extracted` without the
  // product's options, one layer up. Calling the real renderer is also the only
  // version that cannot drift from it.
  out.docx_document_xml = await docxDocumentPartDigest(await renderDocxReport(r, deps.dkb));
  return out;
}

describe("every text artifact is byte-identical on any machine", () => {
  it("matches the committed per-artifact digests", async () => {
    expect(
      existsSync(DKB_DIR),
      `pinned DKB ${DKB_VERSION} is missing — move the pin and regenerate`,
    ).toBe(true);
    const got: Record<string, Record<string, string>> = {};
    for (const f of FIXTURES) got[f] = await digests(f);

    if (REGEN) {
      await writeFile(EXPECTED, JSON.stringify(got, null, 2) + "\n");
      return;
    }
    expect(existsSync(EXPECTED), `missing ${EXPECTED} — regenerate it`).toBe(true);
    const expected = JSON.parse(await readFile(EXPECTED, "utf8"));
    // Guard the probe: an empty or one-key digest set would pass vacuously.
    expect(Object.keys(got)).toEqual(FIXTURES);
    for (const f of FIXTURES) {
      expect(Object.keys(got[f]!).length).toBeGreaterThan(6);
      // Named explicitly: a renamed key would otherwise pass the count.
      expect(Object.keys(got[f]!)).toContain("docx_document_xml");
    }
    expect(got).toEqual(expected);
  }, 300_000);
});
