/**
 * The per-document secondary-family cap must be SAID, on every surface that
 * shows the capped list.
 *
 * `MAX_SECONDARY_FAMILIES` is 4. A document that clearly contains eight
 * families is scanned for four of them and the report lists four — which is
 * byte-for-byte what a document containing exactly four looks like. The reader
 * has no way to tell the two apart, and the difference is four whole rule sets
 * that were never run: not "no findings", but "not looked at".
 *
 * The number existed before this test (`countPresentFamilies`) and reached
 * exactly one consumer — the accuracy harness, which nobody outside this repo
 * reads. Every product surface was silent.
 *
 * Two halves, and the second is the one that matters:
 *   1. Reach — each surface says the number when the cap bites. (The bundle
 *      JSON's half of this lives in `src/report/bundle.test.ts`, beside the
 *      `makeInput` fixture that already assembles a whole bundle.)
 *   2. Anti-vacuity — each surface says NOTHING when it does not, so a
 *      truncation notice can never appear on a complete list, and the 305 of
 *      312 specimens under the cap render byte-identically to before.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { unzipSync, strFromU8 } from "fflate";

import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";
import {
  selectSecondaryFamilies,
  MAX_SECONDARY_FAMILIES,
} from "../../src/ui/playbook-candidates.js";
import { cappedFamiliesNotice } from "../../src/engine/secondary-family-notice.js";
import { matchPlaybook, titleCorpus } from "../../src/playbooks/matcher.js";
import { selectMatchCandidates } from "../../src/ui/playbook-candidates.js";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { flattenText } from "../../src/ingest/types.js";
import { buildJsonReport, type ReportSecondaryFamily } from "../../src/report/json.js";
import { buildHtmlReport } from "../../src/report/html.js";
import { buildDocxReport } from "../../src/report/docx.js";
import { buildSarif } from "../../src/report/sarif.js";
import { runFixture } from "./_pipeline-helpers.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");

/** Four families, so the rendered list length is realistic. */
const FAMILIES: ReportSecondaryFamily[] = ["dpa", "baa", "nda", "sow"].map((id) => ({
  playbook_id: id,
  playbook_name: id.toUpperCase(),
  findings: [],
  counts: { critical: 0, warning: 0, info: 0 },
}));

describe("the secondary-family cap is stated wherever the capped list is shown", () => {
  it("bites on real specimens — the caveat is not hypothetical", async () => {
    const deps = await loadAccuracyDeps();
    const files = readdirSync(SPECIMENS).filter((f) => f.endsWith(".txt"));
    expect(files.length, "the specimen corpus").toBeGreaterThan(250);

    let capped = 0;
    let worst = 0;
    for (const f of files) {
      const ingest = await ingestPaste(readFileSync(join(SPECIMENS, f), "utf8"));
      const extracted = extractAll(ingest.tree, {
        classifier: { vocab: { vocab: {} }, patterns: deps.dkb.classifier.patterns },
      });
      const signals = {
        title: titleCorpus(ingest.tree, f),
        body: flattenText(ingest.tree),
        classified: extracted.classified,
        extracted,
      };
      const candidates = selectMatchCandidates(
        deps.launchPlaybooks,
        deps.extendedPlaybooks,
        signals,
      );
      const match = matchPlaybook(extracted, extracted.classified, candidates, {
        title: signals.title,
        body_text: signals.body,
      });
      const sel = selectSecondaryFamilies(deps.extendedPlaybooks, signals, match.playbook_id);
      expect(sel.selected.length).toBeLessThanOrEqual(MAX_SECONDARY_FAMILIES);
      expect(sel.omitted).toBe(sel.present - sel.selected.length);
      if (sel.omitted > 0) capped++;
      worst = Math.max(worst, sel.present);
    }
    // Measured 2026-09-08 over 312 specimens: **7** are silently truncated,
    // all of them privacy/transfer documents (the DPA, the two SCC modules,
    // three privacy notices, and `uk-idta-addendum.txt`, which clearly
    // contains **eight** families and is scanned for four).
    //
    // The source comments said "22 of the 312" and named the DPA as the
    // eight-family document; both were true when written and neither is now —
    // the false-positive work that tightened `familyIsPresent` cut the
    // truncated set by two thirds. Asserted as a floor, not an equality, so a
    // corpus edit does not fail a test about honesty; the point is that the
    // cap bites on real documents, which is what makes the caveat owed.
    expect(capped, "specimens whose secondary list is silently truncated").toBeGreaterThan(0);
    expect(worst, "the most families any one specimen clearly contains").toBeGreaterThan(
      MAX_SECONDARY_FAMILIES,
    );
  });

  it("JSON emits the count, and omits the field when the cap did not bite", async () => {
    const { run, ingest, playbook } = await runFixture(
      join(process.cwd(), "tests", "fixtures", "specimens", "mutual-nda-letter.txt"),
    );
    const withCap = JSON.parse(
      await buildJsonReport(
        run,
        ingest,
        playbook,
        FAMILIES,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        4,
      ).text(),
    );
    expect(withCap.secondary_families_omitted).toBe(4);

    const clean = JSON.parse(await buildJsonReport(run, ingest, playbook, FAMILIES).text());
    expect(clean.secondary_families).toHaveLength(4);
    expect("secondary_families_omitted" in clean).toBe(false);
  });

  it("HTML and DOCX say the same sentence, and neither says it when uncapped", async () => {
    const { run, ingest, playbook, dkb } = await runFixture(
      join(process.cwd(), "tests", "fixtures", "specimens", "mutual-nda-letter.txt"),
    );
    const sentence = cappedFamiliesNotice(4, FAMILIES.length);

    const htmlCapped = buildHtmlReport(
      run,
      ingest,
      dkb,
      playbook,
      { secondaryFamiliesOmitted: 4 },
      undefined,
      FAMILIES,
    );
    expect(htmlCapped).toContain("4 further families");
    const htmlClean = buildHtmlReport(run, ingest, dkb, playbook, undefined, undefined, FAMILIES);
    expect(htmlClean).not.toContain("NOT scanned");

    // A DOCX is a zip: unzip it and read document.xml. Comparing byte LENGTHS
    // instead looked like it worked and did not — the capped report came out
    // ONE byte longer than the clean one, which is compression noise, not a
    // paragraph. A test that would pass on a one-byte accident is not a test
    // that the sentence is there.
    const docxText = async (omitted?: number): Promise<string> => {
      const blob = await buildDocxReport(
        run,
        ingest,
        dkb,
        playbook,
        undefined,
        undefined,
        FAMILIES,
        omitted === undefined ? undefined : { secondaryFamiliesOmitted: omitted },
      );
      const zip = unzipSync(new Uint8Array(await blob.arrayBuffer()));
      return strFromU8(zip["word/document.xml"]!);
    };
    expect(await docxText(4)).toContain("4 further families");
    expect(await docxText()).not.toContain("NOT scanned");

    // One owner, so the two surfaces cannot drift into different numbers.
    expect(sentence).toContain("4 further families");
    expect(cappedFamiliesNotice(1, 4)).toContain("1 further family that was NOT scanned");
  });

  it("SARIF carries it as a note-level result — the artifact CI actually reads", async () => {
    const { run, ingest } = await runFixture(
      join(process.cwd(), "tests", "fixtures", "specimens", "mutual-nda-letter.txt"),
    );
    const capped = buildSarif(run, { secondaryFamiliesOmitted: 4 }, undefined, ingest);
    const notes = capped.runs[0]!.results.filter(
      (r) => r.ruleId === "VAULYTICA-SECONDARY-FAMILIES-CAPPED",
    );
    expect(notes).toHaveLength(1);
    expect(notes[0]!.level).toBe("note");
    expect(notes[0]!.message.text).toContain("4 further clearly-present families were NOT scanned");
    // Every result's ruleIndex must still resolve into the descriptor array.
    const rules = capped.runs[0]!.tool.driver.rules!;
    expect(rules[notes[0]!.ruleIndex!]!.id).toBe("VAULYTICA-SECONDARY-FAMILIES-CAPPED");

    const clean = buildSarif(run, undefined, undefined, ingest);
    expect(
      clean.runs[0]!.results.some((r) => r.ruleId === "VAULYTICA-SECONDARY-FAMILIES-CAPPED"),
    ).toBe(false);
  });
});
