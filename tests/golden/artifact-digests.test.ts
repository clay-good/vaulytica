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
 * 🚨 The DOCX is deliberately absent. The `docx` library assigns hyperlink
 * relationship ids with `nanoid()`, so its bytes differ on every render on one
 * machine, let alone across three; that exception is declared and normalized in
 * `report-reproducibility.test.ts`, which is where the DOCX is checked. A digest
 * here would fail everywhere and teach nobody anything.
 *
 * Regeneration: `VAULYTICA_REGEN_GOLDEN=1 vitest run tests/golden/artifact-digests.test.ts`.
 * Regenerate on a version bump (the engine version is stamped into every
 * artifact) and whenever a renderer deliberately changes — never to make a
 * red matrix green.
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

async function digests(name: string): Promise<Record<string, string>> {
  const deps = await loadAccuracyDeps();
  const r = await analyzeFile(join(process.cwd(), "tests", "fixtures", "specimens", name), {
    deps,
    secondaryFamilies: true,
  });
  const extracted = extractAll(r.ingest.tree);
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
  return out;
}

describe("every text artifact is byte-identical on any machine", () => {
  it("matches the committed per-artifact digests", async () => {
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
    }
    expect(got).toEqual(expected);
  }, 300_000);
});
