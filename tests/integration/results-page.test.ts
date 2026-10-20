/**
 * The results page on a real document (add-results-page): the legend NDA,
 * analyzed the way the CLI analyzes it, projected through the same model the
 * tab renders.
 */
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { analyzeFile, loadAccuracyDeps } from "../../tools/cli/api.js";
import { abstractOf } from "../../tools/cli/artifacts.js";
import { isActionable } from "../../src/engine/finding.js";
import { buildResultsModel, signerTest } from "../../src/ui/results-page.js";
import { extractAll } from "../../src/extract/index.js";

const SPECIMEN = resolve(__dirname, "../fixtures/specimens/legend-nda.txt");

describe("the legend NDA's results page", () => {
  it("raises six things, quotes none of them, and lists the signers apart", async () => {
    const deps = await loadAccuracyDeps();
    const r = await analyzeFile(SPECIMEN, { deps });
    const abstract = await abstractOf("legend-nda.txt", r);
    const model = buildResultsModel({
      run: r.run,
      abstract,
      isSigner: signerTest(r.ingest.tree, extractAll(r.ingest.tree).parties),
      reportUrl: () => null,
    });

    expect(model.headline).toBe("6 things to raise before you sign");
    expect(model.todo_rows.length).toBe(r.run.findings.filter(isActionable).length);
    expect(model.observations.length).toBe(2);
    // Every to-do row on this NDA is an absence finding: a placeholder, never a quote.
    for (const row of model.todo_rows) {
      expect(row.quote).toBeUndefined();
      expect(row.absent).toMatch(/^\(/);
    }
    // Every quote the page shows is text the document contains. The engine
    // shortens a long excerpt with "…"; each piece between them is verbatim.
    const text = readFileSync(SPECIMEN, "utf8").replace(/\s+/g, " ");
    const quoted = model.observations.filter((o) => o.quote);
    expect(quoted.length).toBe(2);
    for (const row of quoted) {
      for (const piece of row.quote!.split("…")) {
        const p = piece.replace(/\s+/g, " ").trim();
        if (p) expect(text).toContain(p);
      }
    }
    const term = (label: string) => model.key_terms.find((t) => t.label === label);
    expect(term("Parties")!.value).toBe(
      "Northgate Instrument Company (Ohio) · Cardinal Metrology, Inc (Delaware)",
    );
    expect(term("Signed by")!.value).toBe("Priya Raghunathan · Soren Lindqvist");
    expect(term("Liability cap")!.value).toBeUndefined();
  });
});
