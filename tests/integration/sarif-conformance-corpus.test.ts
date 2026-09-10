/**
 * Every SARIF log the engine produces, over every document it has.
 *
 * `sarifConformanceViolations` pins the structural rules GitHub Code Scanning
 * actually enforces — a `level` outside the enum, a dangling `ruleIndex`, a
 * non-string `partialFingerprints` value, a missing `message.text`, a
 * non-absolute `helpUri`. It is well tested against four hand-built fixtures
 * (cited, URL-less, empty, multi-rule) and it has "has teeth" tests for each
 * rule.
 *
 * 🚨 **What it had never been asked is whether the engine's output conforms on
 * a REAL document.** The checker's own docstring says it is "exposed (not
 * test-only) so a caller writing SARIF — e.g. the CLI — can self-check its
 * output"; it had no caller anywhere, and no run over the corpus. Four
 * fixtures cannot cover 1,825 rules × 327 documents, and the failure mode is
 * the quiet one: **a malformed SARIF is not rejected loudly — an uploader
 * drops the results and reports nothing**, which reads as a clean scan.
 *
 * This is the same gap as the nine report artifacts with no headless caller
 * and the cross-document engine that ran only in the browser. A checker with
 * no caller is a checker that has never checked anything but its own fixtures.
 *
 * ~10s over the corpus. The CLI now self-checks too (9.681.0) and warns on
 * stderr, so a user's own document is covered as well as this repo's.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { buildSarif, sarifConformanceViolations } from "../../src/report/sarif.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

describe("SARIF conformance over the specimen corpus", () => {
  it("every log the engine builds satisfies the ingestion-critical rules", async () => {
    const files = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    const violations: string[] = [];
    let results = 0;

    for (const file of files) {
      const r = await analyzeText(readFileSync(join(DIR, file), "utf8"), file);
      const log = buildSarif(r.run);
      results += log.runs[0]?.results?.length ?? 0;
      for (const v of sarifConformanceViolations(log)) violations.push(`${file}: ${v}`);
    }

    // Anti-vacuity, both halves: a corpus that vanished, and a corpus whose
    // logs carry no results would each pass with an empty violation list while
    // proving nothing about a log that has something in it.
    expect(files.length).toBeGreaterThan(300);
    expect(results, "no SARIF results at all — the check proved nothing").toBeGreaterThan(500);

    expect(violations.sort()).toEqual([]);
  }, 300_000);
});
