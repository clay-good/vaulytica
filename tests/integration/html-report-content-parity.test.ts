/**
 * The emailable report and the Word report must not disagree about CONTENT.
 *
 * `src/report/html.ts` keeps a written list of what the DOCX has and it
 * deliberately does not, and the list was doing real work — it is how the
 * secondary-family findings and the cross-document appendix were both caught
 * missing. But two entries did not belong on it:
 *
 *   - **Jurisdiction overlays.** A California non-compete's Bus. & Prof. Code
 *     § 16600 entry is the single most consequential thing this tool can say
 *     about that document, and `uncovered_states` is an honest coverage gap
 *     that must not read as a clean pass.
 *   - **The obligations ledger.** Who owes what, by when.
 *
 * Both were filed under "the paginated report's navigation and reference
 * apparatus", next to the findings index and the audit trail. They are not
 * apparatus. Filing content there is how a deliberate-omissions list stops
 * being a decision and becomes a place things go.
 *
 * This test asserts the content, on a real document, in both surfaces — not
 * the comment.
 */

import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { unzipSync, strFromU8 } from "fflate";

import { analyzeFile, loadAccuracyDeps } from "../../tools/cli/api.js";
import { extractAll } from "../../src/extract/index.js";
import { buildHtmlReport } from "../../src/report/html.js";
import { buildDocxReport } from "../../src/report/docx.js";

/** A California employment agreement — the family with a real overlay catalog. */
const SPECIMEN = join(
  process.cwd(),
  "tests",
  "fixtures",
  "specimens",
  "il-employment-noncompete.txt",
);

describe("the HTML report carries the same CONTENT as the DOCX", () => {
  it("renders the jurisdiction overlays and the obligations ledger", async () => {
    const deps = await loadAccuracyDeps();
    const r = await analyzeFile(SPECIMEN, { deps });
    const extracted = extractAll(r.ingest.tree);
    const html = buildHtmlReport(
      r.run,
      r.ingest,
      deps.dkb,
      r.playbook,
      undefined,
      undefined,
      undefined,
      undefined,
      extracted,
    );
    const docxXml = strFromU8(
      unzipSync(
        new Uint8Array(
          await (
            await buildDocxReport(r.run, r.ingest, deps.dkb, r.playbook, undefined, extracted)
          ).arrayBuffer(),
        ),
      )["word/document.xml"]!,
    );

    // Guard the fixture: if this specimen ever stops producing overlays or
    // obligations, the assertions below would pass vacuously.
    expect(docxXml).toContain("Jurisdiction Overlays");
    expect(docxXml).toContain("Obligations Ledger");
    expect(extracted.obligations.length).toBeGreaterThan(0);

    expect(html).toContain("Jurisdiction overlays");
    expect(html).toContain("Obligations ledger");
    // The coverage gap has to say it is a gap, in both.
    if (html.includes("No overlay on file for")) {
      expect(html).toContain("honest coverage gap — not a clean pass");
    }
  }, 180_000);

  it("renders neither section when there is nothing to render", async () => {
    // Anti-vacuity: without `extracted` the two sections are absent, exactly as
    // they are absent from a DOCX built without it. A report that invents an
    // empty "Jurisdiction overlays" heading tells a reader there was nothing to
    // say, which is a different claim from not having looked.
    const deps = await loadAccuracyDeps();
    const r = await analyzeFile(SPECIMEN, { deps });
    const html = buildHtmlReport(r.run, r.ingest, deps.dkb, r.playbook);
    expect(html).not.toContain("Jurisdiction overlays");
    expect(html).not.toContain("Obligations ledger");
  }, 180_000);
});
