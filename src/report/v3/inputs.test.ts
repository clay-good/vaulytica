/**
 * The producer the v3 report layer never had.
 *
 * Six renderers shipped with spec-v3 and `buildDocxReport` has accepted them
 * as an optional fifth argument ever since. Nothing constructed it, so the
 * transfers summary, subprocessor inventory and insurance schedule were code
 * that shipped, was tested, was specified, and could not be obtained from any
 * surface.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildV3ReportInputs, hasV3Sections } from "./inputs.js";
import { ingestPaste } from "../../ingest/paste.js";
import { extractAll } from "../../extract/index.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");

async function inputsFor(file: string) {
  const ingest = await ingestPaste(readFileSync(join(SPECIMENS, file), "utf8"));
  const extracted = extractAll(ingest.tree);
  return buildV3ReportInputs(ingest.tree, { parties: extracted.parties });
}

describe("buildV3ReportInputs", () => {
  it("finds the transfer mechanisms and subprocessor terms a DPA states", async () => {
    const inputs = await inputsFor("dpa-complete.txt");
    expect(inputs.transfers?.length ?? 0).toBeGreaterThan(0);
    expect(inputs.subprocessor).toBeTruthy();
    expect(hasV3Sections(inputs)).toBe(true);
  });

  it("produces no section for a document that states none of it", async () => {
    // A mutual NDA has no cross-border transfer clause, no subprocessor list
    // and no insurance schedule. The caller passes `undefined` in that case,
    // which is what every golden in the tree was recorded against.
    const inputs = await inputsFor("mutual-nda-complete.txt");
    expect(inputs.transfers).toBeUndefined();
    expect(inputs.subprocessor).toBeUndefined();
    expect(inputs.insurance).toBeUndefined();
    expect(hasV3Sections(inputs)).toBe(false);
  });

  it("omits a field rather than passing it empty", async () => {
    // The renderers each have an "absent → []" branch; letting them decide is
    // what keeps a report byte-identical when a document carries none of this.
    const inputs = await inputsFor("mutual-nda-complete.txt");
    expect(Object.keys(inputs)).not.toContain("insurance");
    expect(Object.keys(inputs)).not.toContain("transfers");
  });

  it("reads an insurance covenant wherever it appears, not only in a COI", async () => {
    // Wiring the layer up immediately showed it doing something worth having
    // on a document nobody would have thought to check: the patent licence's
    // §10.2 requires commercial general liability at $5,000,000 per occurrence
    // with thirty days' notice of cancellation, and the §58 page now says so.
    const inputs = await inputsFor("patent-licence-complete.txt");
    expect(inputs.insurance?.amounts?.[0]?.per_occurrence_usd).toBe(5_000_000);
    expect(inputs.insurance?.notice_of_cancellation_days).toBe(30);
    expect(hasV3Sections(inputs)).toBe(true);
  });

  it("carries the DKB build date when one is supplied, and omits it otherwise", async () => {
    const ingest = await ingestPaste(readFileSync(join(SPECIMENS, "dpa-complete.txt"), "utf8"));
    const withDate = buildV3ReportInputs(ingest.tree, { dkb_build_date: "2026-09-06" });
    expect(withDate.dkb_build_date).toBe("2026-09-06");
    expect(buildV3ReportInputs(ingest.tree).dkb_build_date).toBeUndefined();
  });

  it("is deterministic — the same tree yields the same sections", async () => {
    const ingest = await ingestPaste(readFileSync(join(SPECIMENS, "dpa-complete.txt"), "utf8"));
    expect(JSON.stringify(buildV3ReportInputs(ingest.tree))).toBe(
      JSON.stringify(buildV3ReportInputs(ingest.tree)),
    );
  });

  it("never builds a compliance matrix", async () => {
    // 🚨 The load-bearing negative. A MatrixCell carries Pass / Partial / Fail
    // / N/A per column and nothing maps a column to the rules that decide it,
    // so a status derived from a column LABEL would be this tool rendering a
    // legal conclusion. See BUILD_PROGRESS step 32 (b).
    for (const file of ["dpa-complete.txt", "msa-complete.txt", "patent-licence-complete.txt"]) {
      expect((await inputsFor(file)).matrix).toBeUndefined();
    }
  });
});
